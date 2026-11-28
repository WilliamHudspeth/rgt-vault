package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/keychain"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/servecmd"
)

// supportedMigrations is the number of schema migrations this build knows
// (go/internal/store/migrations, byte-identical to python/storage/migrations).
const supportedMigrations = 5

// legacyVaultMessage is decision D3: the Go line does not read Fernet rows.
const legacyVaultMessage = "contains legacy Fernet-encrypted secrets (dek_version=0), which the Go line does not migrate: " +
	"open it once with the last Python release of rgt-vault (it upgrades them to AES-256-GCM automatically), " +
	"then run `rgt-vault migrate check` again"

func newMigrateCmd(vf *servecmd.VaultFlags, stdout io.Writer) *cobra.Command {
	migrate := &cobra.Command{
		Use:   "migrate",
		Short: "Python-to-Go migration helpers",
	}
	check := &cobra.Command{
		Use:   "check",
		Short: "Check that a Python-created vault can be opened by this build (read-only)",
		Long: "Open the database at --db read-only (nothing is written, no master secret is needed) and\n" +
			"report the vault id, key epoch, applied schema migrations, keychain.json, the DEK versions of\n" +
			"the secrets and the audit chain verdict.\n\n" +
			"Exit status: 0 the vault is ready to be opened with rgt-vault; 1 it is not (a vault with\n" +
			"legacy dek_version=0 rows must be opened once with the last Python release first); 2 the\n" +
			"audit chain does not verify.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMigrateCheck(cmd.Context(), vf, stdout)
		},
	}
	migrate.AddCommand(check)
	return migrate
}

// keychainInfo is what migrate check reads from keychain.json (never the
// wrapped DEK or salt).
type keychainInfo struct {
	Present  bool
	Version  int64
	KDF      string
	Epoch    int64
	HasEpoch bool
	Pending  bool // keychain.json.new exists: an interrupted rotation
	Err      error
}

func readKeychainInfo(dbPath string) keychainInfo {
	p := filepath.Join(filepath.Dir(dbPath), keychain.FileName)
	var ki keychainInfo
	if _, err := os.Stat(p + ".new"); err == nil {
		ki.Pending = true
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return ki
	}
	ki.Present = true
	if err != nil {
		ki.Err = err
		return ki
	}
	var f struct {
		Version  *json.Number `json:"version"`
		KDF      string       `json:"kdf"`
		KeyEpoch *json.Number `json:"key_epoch"`
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	if err := dec.Decode(&f); err != nil {
		ki.Err = errors.New("keychain.json is not valid JSON")
		return ki
	}
	ki.KDF = f.KDF
	if f.Version != nil {
		ki.Version, _ = f.Version.Int64()
	}
	if f.KeyEpoch != nil {
		if n, err := f.KeyEpoch.Int64(); err == nil {
			ki.Epoch, ki.HasEpoch = n, true
		}
	}
	return ki
}

func runMigrateCheck(ctx context.Context, vf *servecmd.VaultFlags, out io.Writer) error {
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
	applied, err := r.migrations(ctx, tables)
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
	ki := readKeychainInfo(db)

	var problems []string
	fmt.Fprintf(out, "database:     %s\n", db)
	fmt.Fprintf(out, "vault_id:     %s\n", orUnset(meta["vault_id"]))
	fmt.Fprintf(out, "key_epoch:    %s\n", orUnset(meta["key_epoch"]))

	// Schema.
	var vs []string
	newer := false
	for _, v := range applied {
		vs = append(vs, strconv.FormatInt(v, 10))
		if v > supportedMigrations {
			newer = true
		}
	}
	switch {
	case len(applied) == 0:
		fmt.Fprintln(out, "migrations:   none applied (they are applied on first open)")
	default:
		pending := supportedMigrations - len(applied)
		note := ""
		if pending > 0 && !newer {
			note = fmt.Sprintf(" (%d pending, applied on first open)", pending)
		}
		fmt.Fprintf(out, "migrations:   %s%s\n", strings.Join(vs, ","), note)
	}
	if newer {
		problems = append(problems, fmt.Sprintf("the database has schema migrations newer than this build knows (it supports 1-%d)", supportedMigrations))
	}

	// Secrets / DEK versions.
	deks := make([]int64, 0, len(stats.ByDEK))
	for k := range stats.ByDEK {
		deks = append(deks, k)
	}
	sort.Slice(deks, func(i, j int) bool { return deks[i] < deks[j] })
	var parts []string
	for _, k := range deks {
		parts = append(parts, fmt.Sprintf("dek_version %d: %d", k, stats.ByDEK[k]))
	}
	if len(parts) == 0 {
		parts = append(parts, "none")
	}
	fmt.Fprintf(out, "secrets:      %d rows (%s)\n", stats.Total, strings.Join(parts, ", "))
	if stats.LegacyActive > 0 {
		problems = append(problems, fmt.Sprintf("%s %s (%d active legacy rows)", db, legacyVaultMessage, stats.LegacyActive))
	}
	for _, k := range deks {
		if k != 0 && k != 1 {
			problems = append(problems, fmt.Sprintf("unsupported dek_version %d on %d rows", k, stats.ByDEK[k]))
		}
	}

	// keychain.json.
	switch {
	case ki.Err != nil:
		fmt.Fprintf(out, "keychain:     unreadable: %v\n", ki.Err)
		problems = append(problems, "keychain.json is unreadable: "+ki.Err.Error())
	case !ki.Present:
		fmt.Fprintln(out, "keychain:     keychain.json not found next to the database")
		if stats.Total > 0 && !ki.Pending {
			problems = append(problems, "keychain.json is missing but the vault holds secrets: restore it from a backup (a new key would make them unreadable)")
		}
	default:
		fmt.Fprintf(out, "keychain:     keychain.json version %d, kdf %s, key_epoch %s\n", ki.Version, ki.KDF, epochText(ki))
		if ki.Version != keychain.SchemaVersion || ki.KDF != keychain.KDFName {
			problems = append(problems, "keychain.json is not a version-1 argon2id keychain")
		}
		if ki.HasEpoch && meta["key_epoch"] != "" && strconv.FormatInt(ki.Epoch, 10) != strings.TrimSpace(meta["key_epoch"]) && !ki.Pending {
			problems = append(problems, fmt.Sprintf("keychain.json key_epoch %d does not match the database epoch %s (a rolled-back keychain or backup mix-up)", ki.Epoch, meta["key_epoch"]))
		}
	}
	if ki.Pending {
		fmt.Fprintln(out, "              keychain.json.new present: an interrupted rotation is completed on first open")
	}

	// Audit chain.
	fmt.Fprintf(out, "audit rows:   %d\n", chain.Rows)
	if chain.OK {
		fmt.Fprintln(out, "audit chain:  OK")
	} else {
		fmt.Fprintln(out, "audit chain:  TAMPERED")
	}

	switch {
	case len(problems) > 0:
		fmt.Fprintln(out, "verdict:      NOT READY")
		for _, p := range problems {
			fmt.Fprintln(out, "  - "+p)
		}
		return &exitError{code: 1, msg: "vault cannot be opened by this build: " + problems[0]}
	case !chain.OK:
		fmt.Fprintln(out, "verdict:      NOT READY (audit chain)")
		return errTampered(chain)
	}
	fmt.Fprintln(out, "verdict:      READY (the master secret was not checked: it is only needed to open the vault)")
	return nil
}

func epochText(ki keychainInfo) string {
	if !ki.HasEpoch {
		return "(not set)"
	}
	return strconv.FormatInt(ki.Epoch, 10)
}
