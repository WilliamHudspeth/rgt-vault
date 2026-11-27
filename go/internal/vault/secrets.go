package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"rgt-vault-server/internal/approval"
	"rgt-vault-server/internal/crypto"
	"rgt-vault-server/internal/keychain"
	"rgt-vault-server/internal/store"
)

// SetSecretRequest are the arguments of SetSecret (python set_secret).
// There are no implicit defaults: pass DefaultNamespace / SystemAgent
// explicitly where Python relied on its argument defaults.
type SetSecretRequest struct {
	Name      string
	Namespace string
	Agent     string
	Purpose   string
	// Value is the plaintext. SetSecret neither retains nor modifies it;
	// the caller should wipe it afterwards.
	Value []byte
	// Note is short human metadata stored in the clear; it must never
	// contain the secret value.
	Note string
	// Require2FA makes the approval gate demand a TOTP code before any agent
	// can lease the secret.
	Require2FA bool
	// AllowRequire2FADowngrade lets this write drop require_2fa from a
	// secret that had it (batch H2). Without it such a write is denied and
	// audited (REQUIRE_2FA_DOWNGRADE_DENIED): a caller that can merely write
	// must not be able to strip the second factor from a secret. The server
	// sets it only for tokens with the operator scope; a successful
	// downgrade is audited (REQUIRE_2FA_DOWNGRADED).
	AllowRequire2FADowngrade bool
}

// LeaseRequest are the arguments of Lease (python lease_secret / execute).
type LeaseRequest struct {
	Name      string
	Namespace string
	Agent     string
	Purpose   string
	// Version selects a specific version (any status); 0 means the newest
	// ACTIVE version.
	Version int64
}

// ListRequest are the arguments of ListSecrets.
type ListRequest struct {
	Namespace string
	Agent     string
	Purpose   string // optional
	Limit     int    // 0 means DefaultListSize
	Offset    int
}

// isASCIISpace is bytes.strip()'s whitespace set.
func isASCIISpace(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	}
	return false
}

// SetSecret encrypts and stores a new version of a secret (python
// set_secret): validation, hook "write", ABAC "write", AES-256-GCM with
// AAD vault_id:namespace:name, then the DEK usage tally, which may rotate
// the DEK automatically (RGT-219).
func (v *Vault) SetSecret(ctx context.Context, req SetSecretRequest) error {
	if err := validateParams(
		pName(req.Name),
		pNamespace(req.Namespace),
		pAgent(req.Agent),
		param{kind: paramNote, value: req.Note, max: MaxNoteChars, allowEmpty: true},
		pPurpose(req.Purpose, true),
	); err != nil {
		return err
	}
	if len(bytes.TrimFunc(req.Value, isASCIISpace)) == 0 {
		return validationErr("'value' cannot be empty or whitespace.")
	}
	if len(req.Value) > MaxValueBytes {
		return validationErr("'value' exceeds %d bytes.", MaxValueBytes)
	}

	rotate, err := v.setSecret(ctx, req)
	if err != nil {
		return err
	}
	if rotate {
		return v.autoRotateDEK(ctx)
	}
	return nil
}

func (v *Vault) setSecret(ctx context.Context, req SetSecretRequest) (needRotate bool, err error) {
	name := req.Name
	if err := v.hookConsult(ctx, OpWrite, req.Agent, req.Namespace, req.Purpose, &name); err != nil {
		return false, err
	}
	d := v.engine.Evaluate(req.Agent, req.Namespace, req.Purpose, "write")
	if !d.Allowed {
		if err := v.withR(func() error {
			return v.logAudit(ctx, "POLICY_DENIED", store.Name(name),
				fmt.Sprintf("Action: write, Agent: %s, Namespace: %s, Reason: %s", req.Agent, req.Namespace, d.Reason))
		}); err != nil {
			return false, err
		}
		return false, deniedErr("Agent '%s' denied write access to '%s' (%s/%s)", req.Agent, name, req.Namespace, req.Purpose)
	}

	// Encrypt and store under one shared-lock hold, so the row is written
	// under the DEK that is current when it lands.
	err = v.withR(func() error {
		ct, err := crypto.Encrypt(req.Value, v.dek, v.aad(req.Namespace, name))
		if err != nil {
			return err
		}
		_, downgraded, err := v.store.SetSecretChecked(ctx, store.SetSecretParams{
			Namespace:                req.Namespace,
			Name:                     name,
			Ciphertext:               ct,
			DEKVersion:               1,
			PolicyHash:               v.policyHash,
			Note:                     req.Note,
			Require2FA:               req.Require2FA,
			AllowRequire2FADowngrade: req.AllowRequire2FADowngrade,
		})
		if errors.Is(err, store.ErrRequire2FADowngrade) {
			if aerr := v.logAudit(ctx, "REQUIRE_2FA_DOWNGRADE_DENIED", store.Name(name),
				fmt.Sprintf("Agent: %s, Namespace: %s, Reason: the secret requires 2FA; dropping it needs the operator scope", req.Agent, req.Namespace)); aerr != nil {
				return aerr
			}
			return deniedErr("Agent '%s' may not drop require_2fa from '%s' (%s): a new version must keep it (operator scope required)", req.Agent, name, req.Namespace)
		}
		if err != nil {
			return err
		}
		if downgraded {
			if err := v.logAudit(ctx, "REQUIRE_2FA_DOWNGRADED", store.Name(name),
				fmt.Sprintf("Agent: %s, Namespace: %s, Reason: operator dropped require_2fa", req.Agent, req.Namespace)); err != nil {
				return err
			}
		}
		count, nbytes, err := v.store.IncrementDEKUsage(ctx, int64(len(req.Value)))
		if err != nil {
			return err
		}
		needRotate = count >= v.dekMaxEncryptions || nbytes >= v.dekMaxBytes
		return nil
	})
	return needRotate, err
}

// Lease unseals a secret and passes the plaintext to fn (python
// lease_secret as a context manager, and execute). The buffer is wiped
// when fn returns or panics; fn must not retain it. Copies fn makes (for
// example string(buf)) are the caller's responsibility.
//
// Order, as in Python: validation, hook "read", rate limit, honeytoken,
// ABAC "read", approval gate, fetch, decrypt, LEASE_GRANTED, fn,
// LEASE_RETURNED. A denial never touches the ciphertext.
func (v *Vault) Lease(ctx context.Context, req LeaseRequest, fn func(secret []byte) error) error {
	if fn == nil {
		return validationErr("The provided callback must be a callable object.")
	}
	if err := validateParams(
		pName(req.Name),
		pAgent(req.Agent),
		pNamespace(req.Namespace),
		pPurpose(req.Purpose, false),
	); err != nil {
		return err
	}
	if req.Version < 0 {
		return validationErr("'version' must be >= 1.")
	}

	buf, err := v.unseal(ctx, req)
	if err != nil {
		return err
	}
	defer func() {
		keychain.Wipe(buf)
		// Close the lease in the chain even if a failed rotation marked the
		// vault inconsistent meanwhile; only Close stops it.
		v.mu.RLock()
		defer v.mu.RUnlock()
		if !v.closed {
			_ = v.logAudit(ctx, "LEASE_RETURNED", store.Name(req.Name), "Agent: "+req.Agent)
		}
	}()
	return fn(buf)
}

// require2FA reports whether the leased row needs a second factor: the
// ACTIVE version's flag (Python requires_2fa) OR, for a by-version lease,
// that version's own flag, so an older 2FA-flagged version cannot be read
// without it after a revoke or a non-2FA successor.
func (v *Vault) require2FA(ctx context.Context, ns, name string, version int64) (bool, error) {
	req, err := v.store.Requires2FA(ctx, ns, name)
	if err != nil || req || version == 0 {
		return req, err
	}
	var flag sql.NullInt64
	err = v.aux.QueryRowContext(ctx,
		"SELECT require_2fa FROM secrets WHERE namespace = ? AND name = ? AND version = ? LIMIT 1",
		ns, name, version).Scan(&flag)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("vault: read require_2fa: %w", err)
	}
	return flag.Int64 != 0, nil
}

// unseal runs every check and decrypts; it writes LEASE_GRANTED on success.
// The hook and the approval gate run without the vault lock.
func (v *Vault) unseal(ctx context.Context, req LeaseRequest) ([]byte, error) {
	name, ns, agent := req.Name, req.Namespace, req.Agent
	if err := v.hookConsult(ctx, OpRead, agent, ns, req.Purpose, &name); err != nil {
		return nil, err
	}
	if !v.rateLimiter.Allow(agent) {
		if err := v.withR(func() error {
			return v.logAudit(ctx, "RATE_LIMITED", store.Name(name), "Agent: "+agent)
		}); err != nil {
			return nil, err
		}
		return nil, rateLimitedErr(agent)
	}
	var require2FA bool
	if err := v.withR(func() error {
		if err := v.checkHoneytoken(ctx, ns, name, agent, req.Purpose); err != nil {
			return err
		}
		d := v.engine.Evaluate(agent, ns, req.Purpose, "read")
		if !d.Allowed {
			if err := v.logAudit(ctx, "POLICY_DENIED", store.Name(name),
				fmt.Sprintf("Action: read, Agent: %s, Namespace: %s, Reason: %s", agent, ns, d.Reason)); err != nil {
				return err
			}
			return deniedErr("Agent '%s' denied read access to '%s' (%s/%s)", agent, name, ns, req.Purpose)
		}
		var err error
		require2FA, err = v.require2FA(ctx, ns, name, req.Version)
		return err
	}); err != nil {
		return nil, err
	}

	// Live approval gate: after static policy, before any ciphertext is read.
	gd := v.approval.Consult(ctx, approval.NewRequest(agent, ns, name, req.Purpose,
		approval.WithAction("read"), approval.With2FA(require2FA)))
	if !gd.Allowed {
		if err := v.withR(func() error {
			return v.logAudit(ctx, "APPROVAL_DENIED", store.Name(name),
				fmt.Sprintf("Agent: %s, Namespace: %s, Reason: %s", agent, ns, gd.Reason))
		}); err != nil {
			return nil, err
		}
		return nil, deniedErr("Agent '%s' approval denied for '%s' (%s/%s): %s", agent, name, ns, req.Purpose, gd.Reason)
	}

	var pt []byte
	err := v.withR(func() error {
		// The approval ran unlocked: re-check what may have changed
		// meanwhile (a write flagging 2FA, an import adding a honeytoken).
		if err := v.checkHoneytoken(ctx, ns, name, agent, req.Purpose); err != nil {
			return err
		}
		ct, dekVersion, err := v.fetch(ctx, ns, name, req.Version)
		if err != nil {
			return err
		}
		// Checked AFTER the fetch: a write that flagged 2FA and landed
		// before it is seen here (fail closed), one after it did not
		// produce the row we hold.
		if !require2FA {
			now, rerr := v.require2FA(ctx, ns, name, req.Version)
			if rerr != nil {
				return rerr
			}
			if now {
				reason := "second factor required (flag changed during approval)"
				if err := v.logAudit(ctx, "APPROVAL_DENIED", store.Name(name),
					fmt.Sprintf("Agent: %s, Namespace: %s, Reason: %s", agent, ns, reason)); err != nil {
					return err
				}
				return deniedErr("Agent '%s' approval denied for '%s' (%s/%s): %s", agent, name, ns, req.Purpose, reason)
			}
		}
		if dekVersion != 1 {
			return unsupportedDEKErr(dekVersion)
		}
		if pt, err = crypto.Decrypt(ct, v.dek, v.aad(ns, name)); err != nil {
			return err
		}
		if err := v.logAudit(ctx, "LEASE_GRANTED", store.Name(name), "Agent: "+agent); err != nil {
			keychain.Wipe(pt)
			pt = nil
			return err
		}
		return nil
	})
	return pt, err
}

// fetch reads the newest ACTIVE version (version 0) or a given version.
func (v *Vault) fetch(ctx context.Context, ns, name string, version int64) ([]byte, int64, error) {
	var (
		ct  []byte
		dv  int64
		err error
	)
	if version == 0 {
		ct, dv, err = v.store.GetSecret(ctx, ns, name, v.policyHash)
	} else {
		ct, dv, err = v.store.GetSecretVersion(ctx, ns, name, version, v.policyHash)
	}
	if errors.Is(err, store.ErrNotFound) {
		return nil, 0, notFoundErr(ns, name, err)
	}
	return ct, dv, err
}

// checkHoneytoken writes HONEYTOKEN_TRIGGERED and refuses a decoy name.
// The caller holds v.mu shared.
func (v *Vault) checkHoneytoken(ctx context.Context, ns, name, agent, purpose string) error {
	hit, err := v.store.IsHoneytoken(ctx, ns, name)
	if err != nil {
		return err
	}
	if !hit {
		return nil
	}
	details := pyDumps(pyObject{{"severity", "critical"}, {"agent", agent}, {"namespace", ns}, {"purpose", purpose}})
	if err := v.logAudit(ctx, "HONEYTOKEN_TRIGGERED", store.Name(name), details); err != nil {
		return err
	}
	return honeytokenErr(ns, name)
}

// Fingerprint returns the first 8 hex digits of sha256(ciphertext) (python
// get_fingerprint). It is deliberately not policy-gated, hooked or rate
// limited (it leaks no plaintext), but honeytokens still trigger. version 0
// means the newest ACTIVE version.
func (v *Vault) Fingerprint(ctx context.Context, namespace, name string, version int64) (string, error) {
	if err := validateParams(pName(name), pNamespace(namespace)); err != nil {
		return "", err
	}
	if version < 0 {
		return "", validationErr("'version' must be >= 1.")
	}
	var fp string
	err := v.withR(func() error {
		if err := v.checkHoneytoken(ctx, namespace, name, SystemAgent, "fingerprint"); err != nil {
			return err
		}
		ct, _, err := v.fetch(ctx, namespace, name, version)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(ct)
		fp = hex.EncodeToString(sum[:])[:8]
		return nil
	})
	return fp, err
}

// ListSecrets lists the ACTIVE secrets of a namespace, never their values
// (python list_secrets): hook "list", then ABAC "read".
func (v *Vault) ListSecrets(ctx context.Context, req ListRequest) ([]store.SecretInfo, error) {
	if err := validateParams(pNamespace(req.Namespace), pAgent(req.Agent), pPurpose(req.Purpose, true)); err != nil {
		return nil, err
	}
	if req.Offset < 0 {
		return nil, validationErr("'offset' must be >= 0.")
	}
	limit := req.Limit
	if limit <= 0 {
		limit = DefaultListSize
	}
	if err := v.hookConsult(ctx, OpList, req.Agent, req.Namespace, req.Purpose, nil); err != nil {
		return nil, err
	}
	var out []store.SecretInfo
	err := v.withR(func() error {
		d := v.engine.Evaluate(req.Agent, req.Namespace, req.Purpose, "read")
		if !d.Allowed {
			if err := v.logAudit(ctx, "POLICY_DENIED", sql.NullString{},
				fmt.Sprintf("Action: list, Agent: %s, Namespace: %s, Reason: %s", req.Agent, req.Namespace, d.Reason)); err != nil {
				return err
			}
			return deniedErr("Unauthorized to access namespace '%s'", req.Namespace)
		}
		var err error
		out, err = v.store.ListSecrets(ctx, req.Namespace, v.policyHash, limit, req.Offset)
		return err
	})
	return out, err
}

// RevokeSecret marks the ACTIVE version REVOKED (python revoke_secret):
// hook "revoke", then ABAC "revoke" with purpose "*".
func (v *Vault) RevokeSecret(ctx context.Context, namespace, name, agent string) error {
	if err := validateParams(pNamespace(namespace), pName(name), pAgent(agent)); err != nil {
		return err
	}
	if err := v.hookConsult(ctx, OpRevoke, agent, namespace, "", &name); err != nil {
		return err
	}
	return v.withR(func() error {
		d := v.engine.Evaluate(agent, namespace, "*", "revoke")
		if !d.Allowed {
			if err := v.logAudit(ctx, "POLICY_DENIED", store.Name(name),
				fmt.Sprintf("Action: revoke, Agent: %s, Namespace: %s, Reason: %s", agent, namespace, d.Reason)); err != nil {
				return err
			}
			return deniedErr("Unauthorized to revoke secret.")
		}
		return v.store.RevokeSecret(ctx, namespace, name, v.policyHash)
	})
}
