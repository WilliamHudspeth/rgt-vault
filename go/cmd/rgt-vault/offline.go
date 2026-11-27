package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"rgt-vault-server/internal/servecmd"
	"rgt-vault-server/internal/vault"
)

// resolveDB resolves --db / RGT_VAULT_DB / the default for the offline
// subcommands that only read the database file.
func resolveDB(vf *servecmd.VaultFlags) (string, error) {
	res, err := vf.Resolve(os.Getenv)
	if err != nil {
		return "", err
	}
	return res.DB, nil
}

// errTampered is the exit-2 error of a broken audit chain.
func errTampered(r auditChain) error {
	msg := "audit chain verification failed"
	if r.FirstBad > 0 {
		msg += fmt.Sprintf(" (first invalid entry: audit_logs id %d)", r.FirstBad)
	}
	return &exitError{code: 2, msg: msg}
}

// runVerifyAuditOffline verifies the hash chain of the database file with no
// server and no master secret. It prints OK, or TAMPERED and exits 2, like
// the HTTP form.
func runVerifyAuditOffline(ctx context.Context, vf *servecmd.VaultFlags, out io.Writer) error {
	db, err := resolveDB(vf)
	if err != nil {
		return err
	}
	r, err := openReadOnly(db)
	if err != nil {
		return err
	}
	defer r.Close()
	tables, err := r.tables(ctx)
	if err != nil {
		return err
	}
	chain, err := r.verifyAudit(ctx, tables)
	if err != nil {
		return err
	}
	if chain.OK {
		fmt.Fprintln(out, "OK")
		return nil
	}
	fmt.Fprintln(out, "TAMPERED")
	return errTampered(chain)
}

// runStatusOffline prints Python's `status` summary from the database file
// (read-only; no master secret).
func runStatusOffline(ctx context.Context, vf *servecmd.VaultFlags, out io.Writer) error {
	db, err := resolveDB(vf)
	if err != nil {
		return err
	}
	r, err := openReadOnly(db)
	if err != nil {
		return err
	}
	defer r.Close()
	tables, err := r.tables(ctx)
	if err != nil {
		return err
	}
	meta, err := r.metadata(ctx, tables)
	if err != nil {
		return err
	}
	stats, err := r.secretStats(ctx, tables)
	if err != nil {
		return err
	}
	chain, err := r.verifyAudit(ctx, tables)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "vault_id:     %s\n", orUnset(meta["vault_id"]))
	fmt.Fprintf(out, "key_epoch:    %s\n", orUnset(meta["key_epoch"]))
	active := int64(0)
	for _, n := range stats.ActiveByNamespace {
		active += n
	}
	fmt.Fprintf(out, "active secrets: %d\n", active)
	for _, ns := range sortedKeys(stats.ActiveByNamespace) {
		fmt.Fprintf(out, "  %s: %d\n", ns, stats.ActiveByNamespace[ns])
	}
	fmt.Fprintf(out, "audit rows:   %d\n", chain.Rows)
	if action, ts, name, ok, err := r.lastAudit(ctx, tables); err != nil {
		return err
	} else if ok {
		if name == "" {
			name = "-"
		}
		fmt.Fprintf(out, "last action:  %s  %s  %s\n", ts, action, name)
	}
	if chain.OK {
		fmt.Fprintln(out, "audit chain:  OK")
		return nil
	}
	fmt.Fprintln(out, "audit chain:  TAMPERED")
	return errTampered(chain)
}

func orUnset(s string) string {
	if s == "" {
		return "(not set)"
	}
	return s
}

// runGetOffline leases a secret by opening the vault files locally: the
// operator-only form of `get` (decision D5). It runs the same ABAC policy
// (--policy; none = deny everything) and writes the same audit rows as the
// server's lease, as the given agent.
func runGetOffline(ctx context.Context, vf *servecmd.VaultFlags, name, namespace, agent, purpose string, out io.Writer) error {
	if name == "" {
		return errors.New("secret name must not be empty")
	}
	if strings.TrimSpace(purpose) == "" {
		return errors.New("--purpose is required with --offline (the policy decides on it)")
	}
	stack, _, err := openStackFor(ctx, vf, false, false)
	if err != nil {
		return err
	}
	defer stack.Close()
	var value string
	err = stack.Vault.Lease(ctx, vault.LeaseRequest{Name: name, Namespace: namespace, Agent: agent, Purpose: purpose},
		func(secret []byte) error {
			value = string(secret)
			return nil
		})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, value)
	return err
}
