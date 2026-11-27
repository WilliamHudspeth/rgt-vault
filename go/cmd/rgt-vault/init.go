package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/servecmd"
	"rgt-vault-server/internal/server"
)

// initOptions are the flags of `rgt-vault init`.
type initOptions struct {
	tokenFile         string
	operatorTokenFile string
	harnessKeyFile    string
	tokensOnly        bool
	force             bool
}

func newInitCmd(vf *servecmd.VaultFlags, stdout io.Writer) *cobra.Command {
	var o initOptions
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create the vault and the bearer/operator token files (idempotent, non-destructive)",
		Long: "Create everything `rgt-vault serve` needs:\n\n" +
			"  - the vault: vault.db and keychain.json at --db, and the master secret in the --provider\n" +
			"    backend (the keyring by default). An existing vault is only opened, never reset.\n" +
			"  - the agent bearer token file (--token-file) and the operator token file\n" +
			"    (--operator-token-file, the approve/deny scope), 32 random bytes each, mode 0600,\n" +
			"    written atomically. Tokens are never printed.\n" +
			"  - with --harness-key-file, an HMAC key for v2 capability tokens.\n\n" +
			"Running init again changes nothing: existing files are kept (a token that is too weak is\n" +
			"an error). --force replaces the token files and the harness key with new ones; it never\n" +
			"touches vault.db or keychain.json. --tokens-only skips the vault.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInit(cmd, vf, o, stdout)
		},
	}
	cmd.Flags().StringVar(&o.tokenFile, "token-file", servecmd.DefaultTokenPath(), "agent bearer token file (0600)")
	cmd.Flags().StringVar(&o.operatorTokenFile, "operator-token-file", servecmd.DefaultOperatorTokenPath(), "operator token file (0600); \"-\" skips it")
	cmd.Flags().StringVar(&o.harnessKeyFile, "harness-key-file", "", "also create an HMAC key for v2 capability tokens at this path (0600)")
	cmd.Flags().BoolVar(&o.tokensOnly, "tokens-only", false, "create only the token files, not the vault")
	cmd.Flags().BoolVar(&o.force, "force", false, "replace existing token files / harness key with new ones (never touches the vault)")
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
	targets := []target{{o.tokenFile, "agent token file", true, newRandomToken}}
	if o.operatorTokenFile != "-" {
		targets = append(targets, target{o.operatorTokenFile, "operator token file", true, newRandomToken})
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
	fmt.Fprintln(out, "  rgt-vault serve --policy policy.yaml --token-file <agent token> [--operator-token-file <operator token>]")
	return nil
}
