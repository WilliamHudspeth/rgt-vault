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
	if err := v.rlock(); err != nil {
		return false, err
	}
	defer v.mu.RUnlock()

	name := req.Name
	if err := v.hookConsult(ctx, OpWrite, req.Agent, req.Namespace, req.Purpose, &name); err != nil {
		return false, err
	}
	d := v.engine.Evaluate(req.Agent, req.Namespace, req.Purpose, "write")
	if !d.Allowed {
		if err := v.logAudit(ctx, "POLICY_DENIED", store.Name(name),
			fmt.Sprintf("Action: write, Agent: %s, Namespace: %s, Reason: %s", req.Agent, req.Namespace, d.Reason)); err != nil {
			return false, err
		}
		return false, deniedErr("Agent '%s' denied write access to '%s' (%s/%s)", req.Agent, name, req.Namespace, req.Purpose)
	}

	ct, err := crypto.Encrypt(req.Value, v.dek, v.aad(req.Namespace, name))
	if err != nil {
		return false, err
	}
	if _, err := v.store.SetSecret(ctx, store.SetSecretParams{
		Namespace:  req.Namespace,
		Name:       name,
		Ciphertext: ct,
		DEKVersion: 1,
		PolicyHash: v.policyHash,
		Note:       req.Note,
		Require2FA: req.Require2FA,
	}); err != nil {
		return false, err
	}
	count, nbytes, err := v.store.IncrementDEKUsage(ctx, int64(len(req.Value)))
	if err != nil {
		return false, err
	}
	return count >= v.dekMaxEncryptions || nbytes >= v.dekMaxBytes, nil
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

	buf, err := v.unseal(ctx, req)
	if err != nil {
		return err
	}
	defer func() {
		keychain.Wipe(buf)
		if err := v.rlock(); err == nil {
			_ = v.logAudit(ctx, "LEASE_RETURNED", store.Name(req.Name), "Agent: "+req.Agent)
			v.mu.RUnlock()
		}
	}()
	return fn(buf)
}

// unseal runs every check and decrypts; it writes LEASE_GRANTED on success.
func (v *Vault) unseal(ctx context.Context, req LeaseRequest) ([]byte, error) {
	if err := v.rlock(); err != nil {
		return nil, err
	}
	defer v.mu.RUnlock()

	name, ns, agent := req.Name, req.Namespace, req.Agent
	if err := v.hookConsult(ctx, OpRead, agent, ns, req.Purpose, &name); err != nil {
		return nil, err
	}
	if !v.rateLimiter.Allow(agent) {
		if err := v.logAudit(ctx, "RATE_LIMITED", store.Name(name), "Agent: "+agent); err != nil {
			return nil, err
		}
		return nil, rateLimitedErr(agent)
	}
	if err := v.checkHoneytoken(ctx, ns, name, agent, req.Purpose); err != nil {
		return nil, err
	}
	d := v.engine.Evaluate(agent, ns, req.Purpose, "read")
	if !d.Allowed {
		if err := v.logAudit(ctx, "POLICY_DENIED", store.Name(name),
			fmt.Sprintf("Action: read, Agent: %s, Namespace: %s, Reason: %s", agent, ns, d.Reason)); err != nil {
			return nil, err
		}
		return nil, deniedErr("Agent '%s' denied read access to '%s' (%s/%s)", agent, name, ns, req.Purpose)
	}

	// Live approval gate: after static policy, before any ciphertext is read.
	require2FA, err := v.store.Requires2FA(ctx, ns, name)
	if err != nil {
		return nil, err
	}
	gd := v.approval.Consult(ctx, approval.NewRequest(agent, ns, name, req.Purpose,
		approval.WithAction("read"), approval.With2FA(require2FA)))
	if !gd.Allowed {
		if err := v.logAudit(ctx, "APPROVAL_DENIED", store.Name(name),
			fmt.Sprintf("Agent: %s, Namespace: %s, Reason: %s", agent, ns, gd.Reason)); err != nil {
			return nil, err
		}
		return nil, deniedErr("Agent '%s' approval denied for '%s' (%s/%s): %s", agent, name, ns, req.Purpose, gd.Reason)
	}

	ct, dekVersion, err := v.fetch(ctx, ns, name, req.Version)
	if err != nil {
		return nil, err
	}
	if dekVersion != 1 {
		return nil, unsupportedDEKErr(dekVersion)
	}
	pt, err := crypto.Decrypt(ct, v.dek, v.aad(ns, name))
	if err != nil {
		return nil, err
	}
	if err := v.logAudit(ctx, "LEASE_GRANTED", store.Name(name), "Agent: "+agent); err != nil {
		keychain.Wipe(pt)
		return nil, err
	}
	return pt, nil
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
	if err := v.rlock(); err != nil {
		return "", err
	}
	defer v.mu.RUnlock()
	if err := v.checkHoneytoken(ctx, namespace, name, SystemAgent, "fingerprint"); err != nil {
		return "", err
	}
	ct, _, err := v.fetch(ctx, namespace, name, version)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(ct)
	return hex.EncodeToString(sum[:])[:8], nil
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
	if err := v.rlock(); err != nil {
		return nil, err
	}
	defer v.mu.RUnlock()
	if err := v.hookConsult(ctx, OpList, req.Agent, req.Namespace, req.Purpose, nil); err != nil {
		return nil, err
	}
	d := v.engine.Evaluate(req.Agent, req.Namespace, req.Purpose, "read")
	if !d.Allowed {
		if err := v.logAudit(ctx, "POLICY_DENIED", sql.NullString{},
			fmt.Sprintf("Action: list, Agent: %s, Namespace: %s, Reason: %s", req.Agent, req.Namespace, d.Reason)); err != nil {
			return nil, err
		}
		return nil, deniedErr("Unauthorized to access namespace '%s'", req.Namespace)
	}
	return v.store.ListSecrets(ctx, req.Namespace, v.policyHash, limit, req.Offset)
}

// RevokeSecret marks the ACTIVE version REVOKED (python revoke_secret):
// hook "revoke", then ABAC "revoke" with purpose "*".
func (v *Vault) RevokeSecret(ctx context.Context, namespace, name, agent string) error {
	if err := validateParams(pNamespace(namespace), pName(name), pAgent(agent)); err != nil {
		return err
	}
	if err := v.rlock(); err != nil {
		return err
	}
	defer v.mu.RUnlock()
	if err := v.hookConsult(ctx, OpRevoke, agent, namespace, "", &name); err != nil {
		return err
	}
	d := v.engine.Evaluate(agent, namespace, "*", "revoke")
	if !d.Allowed {
		if err := v.logAudit(ctx, "POLICY_DENIED", store.Name(name),
			fmt.Sprintf("Action: revoke, Agent: %s, Namespace: %s, Reason: %s", agent, namespace, d.Reason)); err != nil {
			return err
		}
		return deniedErr("Unauthorized to revoke secret.")
	}
	return v.store.RevokeSecret(ctx, namespace, name, v.policyHash)
}
