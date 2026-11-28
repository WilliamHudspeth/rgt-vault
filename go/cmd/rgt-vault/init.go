package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/auth"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/servecmd"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/server"
)

// initOptions are the flags of `rgt-vault init`.
type initOptions struct {
	tokenStore        string
	operatorAgent     string
	legacy            bool
	tokenFile         string
	operatorTokenFile string
	harnessKeyFile    string
	tokensOnly        bool
	force             bool
	forceImport       bool
}

func newInitCmd(vf *servecmd.VaultFlags, stdout io.Writer) *cobra.Command {
	var o initOptions
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create the vault, the token store and an operator token (idempotent, non-destructive)",
		Long: "Create everything `rgt-vault serve` needs:\n\n" +
			"  - the vault: vault.db and keychain.json at --db, and the master secret in the --provider\n" +
			"    backend (the keyring by default). An existing vault is only opened, never reset.\n" +
			"  - the per-agent token store (--token-store, hashes only) with one OPERATOR token for\n" +
			"    --operator-agent (scopes agent, lease, audit, operator), whose plaintext goes to\n" +
			"    --operator-token-file (0600, written atomically) for the CLI and the TUI. An existing\n" +
			"    operator token file that is not in the store yet is imported (migration). Tokens are\n" +
			"    never printed. Mint one token per agent afterwards: rgt-vault token mint --agent NAME.\n" +
			"  - with --harness-key-file, an HMAC key for v2 capability tokens.\n\n" +
			"With --legacy-shared-token init instead creates the pre-H1 shared agent token file\n" +
			"(--token-file) and a separate operator token file, for `serve --legacy-shared-token`.\n\n" +
			"Running init again changes nothing: existing files are kept (a token that is too weak is\n" +
			"an error). --force replaces the operator token (revoking the old one in the store), the\n" +
			"token files and the harness key; it never touches vault.db or keychain.json.\n" +
			"--tokens-only skips the vault.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInit(cmd, vf, o, stdout)
		},
	}
	cmd.Flags().StringVar(&o.tokenStore, "token-store", "", "per-agent token store (env RGT_VAULT_TOKEN_STORE, default ~/.config/rgt-vault/tokens.json)")
	cmd.Flags().StringVar(&o.operatorAgent, "operator-agent", "operator", "agent id of the operator token")
	cmd.Flags().BoolVar(&o.legacy, "legacy-shared-token", false, "DEPRECATED: create the pre-H1 shared token files instead of the token store")
	cmd.Flags().StringVar(&o.tokenFile, "token-file", servecmd.DefaultTokenPath(), "legacy only: shared agent bearer token file (0600)")
	cmd.Flags().StringVar(&o.operatorTokenFile, "operator-token-file", servecmd.DefaultOperatorTokenPath(), "operator token file (0600); \"-\" skips it")
	cmd.Flags().StringVar(&o.harnessKeyFile, "harness-key-file", "", "also create an HMAC key for v2 capability tokens at this path (0600)")
	cmd.Flags().BoolVar(&o.tokensOnly, "tokens-only", false, "create only the token files, not the vault")
	cmd.Flags().BoolVar(&o.force, "force", false, "replace existing token files / harness key with new ones (never touches the vault)")
	cmd.Flags().BoolVar(&o.forceImport, "force-import", false, "import an existing operator token file even though other users could read it (Unix group/other bits); prefer --force, which mints a new one")
	return cmd
}

// newRandomToken returns a fresh token (urlsafe base64 of 32 random bytes).
func newRandomToken() ([]byte, error) {
	t, err := auth.GenerateToken()
	if err != nil {
		return nil, err
	}
	return []byte(t + "\n"), nil
}

// newHarnessKey returns 32 random bytes as hex.
func newHarnessKey() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}
	return []byte(hex.EncodeToString(b) + "\n"), nil
}

// ensureSecretFile creates path with mint() unless it already exists (and
// force is false). It returns "created", "replaced" or "kept". An existing
// file is tightened to 0600 and, for a token, checked for strength.
func ensureSecretFile(path, what string, force, isToken bool, mint func() ([]byte, error)) (string, error) {
	if path == "" {
		return "", fmt.Errorf("no path for the %s: home directory unknown, pass its --*-file flag", what)
	}
	p, err := server.ExpandHome(path)
	if err != nil {
		return "", err
	}
	_, statErr := os.Stat(p)
	exists := statErr == nil
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return "", fmt.Errorf("%s %s: %w", what, p, statErr)
	}
	if exists && !force {
		if err := servecmd.TightenFile(p); err != nil {
			return "", fmt.Errorf("restricting %s %s: %w", what, p, err)
		}
		if isToken {
			b, err := os.ReadFile(p)
			if err != nil {
				return "", fmt.Errorf("reading %s %s: %w", what, p, err)
			}
			if err := servecmd.ValidateToken(string(b)); err != nil {
				return "", fmt.Errorf("existing %s %s: %w; pass --force to replace it", what, p, err)
			}
		}
		return "kept", nil
	}
	data, err := mint()
	if err != nil {
		return "", err
	}
	created, err := writeSecretFile(p, data, force)
	if err != nil {
		return "", err
	}
	switch {
	case !created: // lost a race with another init: the other file wins
		return "kept", nil
	case exists:
		return "replaced", nil
	}
	return "created", nil
}

func runInit(cmd *cobra.Command, vf *servecmd.VaultFlags, o initOptions, out io.Writer) error {
	ctx := cmd.Context()
	var lines []string
	if !o.legacy && cmd.Flags().Changed("token-file") {
		return errors.New("--token-file is the pre-H1 shared token: it needs --legacy-shared-token " +
			"(the default is the per-agent token store)")
	}

	// The vault first: if the master-secret provider is unusable nothing
	// else has been written yet.
	if !o.tokensOnly {
		res, err := vf.Resolve(os.Getenv)
		if err != nil {
			return err
		}
		existed := vaultFileExists(res.DB)
		stack, err := openStackAt(ctx, res, server.StackOptions{})
		if err != nil {
			return err
		}
		id, epoch := stack.Vault.VaultID(), stack.Vault.KeyEpoch()
		if err := stack.Close(); err != nil {
			return fmt.Errorf("closing vault: %w", err)
		}
		state := "created"
		if existed {
			state = "kept (opened and verified)"
		}
		lines = append(lines, fmt.Sprintf("vault:           %s  %s  id %s  epoch %d", res.DB, state, id, epoch))
	}

	type target struct {
		path, what string
		token      bool
		mint       func() ([]byte, error)
	}
	var targets []target
	if o.legacy {
		targets = append(targets, target{o.tokenFile, "agent token file", true, newRandomToken})
		if o.operatorTokenFile != "-" {
			targets = append(targets, target{o.operatorTokenFile, "operator token file", true, newRandomToken})
		}
	} else {
		storeLines, err := initTokenStore(o)
		if err != nil {
			return err
		}
		lines = append(lines, storeLines...)
	}
	if o.harnessKeyFile != "" {
		targets = append(targets, target{o.harnessKeyFile, "harness key file", false, newHarnessKey})
	}
	for _, t := range targets {
		state, err := ensureSecretFile(t.path, t.what, o.force, t.token, t.mint)
		if err != nil {
			return err
		}
		lines = append(lines, fmt.Sprintf("%-16s %s  %s (0600)", t.what+":", t.path, state))
	}

	fmt.Fprintln(out, "rgt-vault initialised.")
	for _, l := range lines {
		fmt.Fprintln(out, "  "+l)
	}
	fmt.Fprintln(out, "Tokens are never printed. Next: write a policy, then")
	if o.legacy {
		fmt.Fprintln(out, "  rgt-vault serve --legacy-shared-token --policy policy.yaml --token-file <agent token> [--operator-token-file <operator token>]")
		return nil
	}
	fmt.Fprintln(out, "  rgt-vault token mint --agent <name> [--scope agent,lease] --out <file>   (one per agent)")
	fmt.Fprintln(out, "  rgt-vault serve --policy policy.yaml")
	return nil
}

// operatorScopes are the scopes of the operator token init MINTS: the
// operator's own CLI/TUI identity (approve, rotate, audit, and set/list/use
// as agent "operator"). No lease scope: the operator reads plaintext with
// `get --offline`, and an agent that picks up this token cannot lease.
var operatorScopes = []auth.Scope{auth.ScopeAgent, auth.ScopeOperator, auth.ScopeAudit}

// importedOperatorScopes are the scopes an existing (pre-H1) operator token
// file is imported with: exactly its old privilege, the approval endpoints
// (review of PR #53, MEDIUM-2). Anything more needs a freshly minted token.
var importedOperatorScopes = []auth.Scope{auth.ScopeOperator}

// looseMode reports whether a file is readable or writable by group/other
// (Unix). Windows has no such bits: there the profile directory's ACL is
// the protection.
func looseMode(path string) (bool, error) {
	if runtime.GOOS == "windows" {
		return false, nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return fi.Mode().Perm()&0o077 != 0, nil
}

// initTokenStore makes sure the store holds an operator token whose
// plaintext is in the operator token file. It returns summary lines.
func initTokenStore(o initOptions) ([]string, error) {
	storePath, err := tokenStorePath(o.tokenStore)
	if err != nil {
		return nil, err
	}
	st := auth.OpenStore(storePath)
	if _, err := st.List(); err != nil { // a corrupt store is an error, never overwritten
		return nil, fmt.Errorf("token store %s: %w", storePath, err)
	}
	if o.operatorTokenFile == "-" {
		if err := ensureStoreFile(st); err != nil {
			return nil, err
		}
		return []string{fmt.Sprintf("%-16s %s  (no operator token: --operator-token-file -)", "token store:", storePath)}, nil
	}
	if o.operatorTokenFile == "" {
		return nil, errors.New("no path for the operator token file: home directory unknown, pass --operator-token-file")
	}
	opPath, err := server.ExpandHome(o.operatorTokenFile)
	if err != nil {
		return nil, err
	}
	var old string
	b, rerr := os.ReadFile(opPath)
	switch {
	case rerr == nil:
		old = string(b)
	case !errors.Is(rerr, os.ErrNotExist):
		return nil, fmt.Errorf("operator token file %s: %w", opPath, rerr)
	}
	mintOpts := auth.MintOptions{Agent: o.operatorAgent, Scopes: operatorScopes}
	storeLine := fmt.Sprintf("%-16s %s (0600, hashes only)", "token store:", storePath)

	if old != "" && !o.force {
		if err := servecmd.ValidateToken(old); err != nil {
			return nil, fmt.Errorf("existing operator token file %s: %w; pass --force to replace it", opPath, err)
		}
		loose, err := looseMode(opPath)
		if err != nil {
			return nil, fmt.Errorf("operator token file %s: %w", opPath, err)
		}
		info, found, err := st.Contains(old)
		if err != nil {
			return nil, err
		}
		var warn []string
		if loose {
			if !found && !o.forceImport {
				return nil, fmt.Errorf("operator token file %s is readable by other users, so the token may be exposed: "+
					"not importing it. Run `rgt-vault init --force` to mint a new operator token (recommended), or pass "+
					"--force-import to import it anyway", opPath)
			}
			warn = append(warn, fmt.Sprintf("WARNING: %s was readable by other users (now 0600); the token may be exposed: "+
				"rotate it with `rgt-vault init --force`", opPath))
		}
		if err := servecmd.TightenFile(opPath); err != nil {
			return nil, fmt.Errorf("restricting operator token file %s: %w", opPath, err)
		}
		state := "kept (in the store as " + info.ID + ")"
		if !found {
			if info, err = st.Import(old, auth.MintOptions{Agent: o.operatorAgent, Scopes: importedOperatorScopes}); err != nil {
				return nil, err
			}
			state = "imported into the store as " + info.ID + " with the operator scope only (its pre-H1 privilege)"
		}
		return append([]string{storeLine, fmt.Sprintf("%-16s %s  %s", "operator token:", opPath, state)}, warn...), nil
	}

	tok, info, err := st.Mint(mintOpts)
	if err != nil {
		return nil, err
	}
	if _, err := writeSecretFile(opPath, []byte(tok+"\n"), true); err != nil {
		_, _ = st.Revoke(info.ID) // never leave a token whose plaintext nobody has
		return nil, err
	}
	state := "created as " + info.ID
	if old != "" { // --force: retire the replaced token
		state = "replaced, now " + info.ID
		if prev, found, err := st.Contains(old); err == nil && found {
			if _, err := st.Revoke(prev.ID); err != nil {
				return nil, fmt.Errorf("revoking the replaced operator token %s: %w", prev.ID, err)
			}
			state += " (" + prev.ID + " revoked)"
		}
	}
	return []string{storeLine, fmt.Sprintf("%-16s %s  %s (0600)", "operator token:", opPath, state)}, nil
}

// ensureStoreFile creates an empty store file if there is none.
func ensureStoreFile(st *auth.Store) error {
	if st.Exists() {
		return nil
	}
	_, err := writeSecretFile(st.Path(), []byte("{\n  \"version\": 1,\n  \"tokens\": []\n}\n"), false)
	return err
}
