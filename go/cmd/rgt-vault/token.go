package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/servecmd"
	"rgt-vault-server/internal/server"
)

// `rgt-vault token ...`: manage the per-agent token store (batch H1).
//
// The store (default ~/.config/rgt-vault/tokens.json, env
// RGT_VAULT_TOKEN_STORE, flag --store) holds only sha256 hashes. A token's
// plaintext exists once: printed by mint/rotate, or written to --out (0600).
// list never shows hashes or tokens. A running server re-reads the store on
// the next request, so revoke and rotate take effect immediately.

// tokenStorePath resolves --store > $RGT_VAULT_TOKEN_STORE > default.
func tokenStorePath(flagVal string) (string, error) {
	p := flagVal
	if p == "" {
		p = os.Getenv("RGT_VAULT_TOKEN_STORE")
	}
	if p == "" {
		p = servecmd.DefaultTokenStorePath()
	}
	if p == "" {
		return "", errors.New("no token store path: home directory unknown, pass --store")
	}
	return server.ExpandHome(p)
}

// tokenOut writes a new token to an --out file BEFORE the store commits it
// (review of PR #53, L3): the destination is checked up front, written with
// no-clobber semantics inside the store's commit hook, and removed again if
// the store write then fails. Without --out the token is printed once,
// after the commit.
type tokenOut struct {
	path    string // expanded --out, or ""
	created bool
}

func newTokenOut(outFile string) (*tokenOut, error) {
	if outFile == "" {
		return &tokenOut{}, nil
	}
	p, err := server.ExpandHome(outFile)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(p); err == nil {
		return nil, fmt.Errorf("%s already exists; not overwriting it (nothing was changed)", p)
	}
	return &tokenOut{path: p}, nil
}

// hook is the store's BeforeCommit (nil without --out).
func (o *tokenOut) hook() func(string) error {
	if o.path == "" {
		return nil
	}
	return func(token string) error {
		created, err := writeSecretFile(o.path, []byte(token+"\n"), false)
		if err != nil {
			return err
		}
		if !created {
			return fmt.Errorf("%s already exists; not overwriting it (nothing was changed)", o.path)
		}
		o.created = true
		return nil
	}
}

// finish reports the outcome: on a failed commit it removes the file the
// hook wrote; on success it prints the token once (no --out) or says where
// it went. It is written with Write, not a formatted print, and nowhere else.
func (o *tokenOut) finish(out io.Writer, token string, commitErr error) error {
	if commitErr != nil {
		if o.created {
			_ = os.Remove(o.path)
		}
		return commitErr
	}
	if o.path != "" {
		fmt.Fprintf(out, "token written to %s (0600)\n", o.path)
		return nil
	}
	fmt.Fprintln(out, "token (shown once; store it now, it cannot be recovered):")
	_, err := out.Write([]byte(token + "\n"))
	return err
}

func describe(info auth.TokenInfo) string {
	exp := "never"
	if info.ExpiresAt != nil {
		exp = info.ExpiresAt.Format(time.RFC3339)
	}
	return fmt.Sprintf("id %s  agent %s  scopes %s  expires %s", info.ID, info.Agent, joinScopes(info.Scopes), exp)
}

func joinScopes(sc []auth.Scope) string {
	parts := make([]string, len(sc))
	for i, s := range sc {
		parts[i] = string(s)
	}
	return strings.Join(parts, ",")
}

func newTokenCmd(stdin io.Reader, stdout io.Writer) *cobra.Command {
	var storeFlag string
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Manage per-agent bearer tokens (mint, list, revoke, rotate, import)",
		Long: "Each token belongs to one agent and carries scopes:\n\n" +
			"  agent     act as that agent on the secrets routes (ABAC applies)\n" +
			"  lease     also read plaintext values (POST .../lease; with agent)\n" +
			"  audit     read and verify the audit log\n" +
			"  operator  approve/deny, rotate keys, read the audit log\n\n" +
			"The store keeps only sha256 hashes; a token is shown once when minted.",
	}
	cmd.PersistentFlags().StringVar(&storeFlag, "store", "", "token store file (env RGT_VAULT_TOKEN_STORE, default ~/.config/rgt-vault/tokens.json)")
	open := func() (*auth.Store, error) {
		p, err := tokenStorePath(storeFlag)
		if err != nil {
			return nil, err
		}
		return auth.OpenStore(p), nil
	}

	// mint
	var mintAgent, mintScopes, mintOut string
	var mintTTL time.Duration
	mint := &cobra.Command{
		Use:   "mint",
		Short: "Create a token for an agent (printed once, or written to --out)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			scopes, err := auth.ParseScopes(mintScopes)
			if err != nil {
				return err
			}
			st, err := open()
			if err != nil {
				return err
			}
			to, err := newTokenOut(mintOut)
			if err != nil {
				return err
			}
			tok, info, err := st.Mint(auth.MintOptions{Agent: mintAgent, Scopes: scopes, TTL: mintTTL, BeforeCommit: to.hook()})
			if err == nil {
				fmt.Fprintln(stdout, "minted "+describe(info))
			}
			return to.finish(stdout, tok, err)
		},
	}
	mint.Flags().StringVar(&mintAgent, "agent", "", "agent id the token acts as (required)")
	mint.Flags().StringVar(&mintScopes, "scope", "agent", "comma-separated scopes: agent, lease, audit, operator")
	mint.Flags().DurationVar(&mintTTL, "expires", 0, "lifetime, e.g. 24h (default: no expiry)")
	mint.Flags().StringVar(&mintOut, "out", "", "write the token to this new file (0600) instead of printing it")
	_ = mint.MarkFlagRequired("agent")

	// list
	var listJSON bool
	list := &cobra.Command{
		Use:   "list",
		Short: "List tokens: id, agent, scopes, created, expiry (never hashes or tokens)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := open()
			if err != nil {
				return err
			}
			infos, err := st.List()
			if err != nil {
				return err
			}
			if listJSON {
				enc := json.NewEncoder(stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{"tokens": infos})
			}
			tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tAGENT\tSCOPES\tCREATED\tEXPIRES")
			now := time.Now()
			for _, in := range infos {
				exp := "never"
				if in.ExpiresAt != nil {
					exp = in.ExpiresAt.Format(time.RFC3339)
					if in.Expired(now) {
						exp += " (expired)"
					}
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", in.ID, in.Agent, joinScopes(in.Scopes), in.CreatedAt.Format(time.RFC3339), exp)
			}
			return tw.Flush()
		},
	}
	list.Flags().BoolVar(&listJSON, "json", false, "JSON output")

	// revoke
	revoke := &cobra.Command{
		Use:   "revoke ID",
		Short: "Revoke a token (a running server rejects it at the next request)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := open()
			if err != nil {
				return err
			}
			info, err := st.Revoke(args[0])
			if err != nil {
				return err
			}
			fmt.Fprintln(stdout, "revoked "+describe(info))
			return nil
		},
	}

	// rotate
	var rotTTL time.Duration
	var rotOut string
	rotate := &cobra.Command{
		Use:   "rotate ID",
		Short: "Replace a token by a new one for the same agent and scopes (the old one stops working)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := open()
			if err != nil {
				return err
			}
			to, err := newTokenOut(rotOut)
			if err != nil {
				return err
			}
			tok, info, err := st.RotateWith(args[0], rotTTL, to.hook())
			if err == nil {
				fmt.Fprintln(stdout, "rotated "+args[0]+" -> "+describe(info))
			}
			return to.finish(stdout, tok, err)
		},
	}
	rotate.Flags().DurationVar(&rotTTL, "expires", 0, "new lifetime (default: the old token's lifetime, or none)")
	rotate.Flags().StringVar(&rotOut, "out", "", "write the new token to this new file (0600) instead of printing it")

	// import
	var impFile, impAgent, impScopes string
	var impTTL time.Duration
	imp := &cobra.Command{
		Use:   "import",
		Short: "Add an existing token file (e.g. a pre-H1 token) to the store under an agent",
		Long: "Hash the token in --file into the store as --agent with --scope, so a client that\n" +
			"already holds that file keeps working with the per-agent server. The file is not\n" +
			"changed and the token is never printed. A shared token imported for one agent\n" +
			"gives that agent's identity to EVERY holder: mint one token per agent instead.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			scopes, err := auth.ParseScopes(impScopes)
			if err != nil {
				return err
			}
			p, err := server.ExpandHome(impFile)
			if err != nil {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return fmt.Errorf("reading token file: %w", err)
			}
			if err := servecmd.ValidateToken(string(b)); err != nil {
				return fmt.Errorf("token file %s: %w", p, err)
			}
			st, err := open()
			if err != nil {
				return err
			}
			info, err := st.Import(string(b), auth.MintOptions{Agent: impAgent, Scopes: scopes, TTL: impTTL})
			if err != nil {
				return err
			}
			fmt.Fprintln(stdout, "imported "+describe(info))
			return nil
		},
	}
	imp.Flags().StringVar(&impFile, "file", "", "existing token file (required)")
	imp.Flags().StringVar(&impAgent, "agent", "", "agent id the token acts as (required)")
	imp.Flags().StringVar(&impScopes, "scope", "agent", "comma-separated scopes")
	imp.Flags().DurationVar(&impTTL, "expires", 0, "lifetime from now (default: no expiry)")
	_ = imp.MarkFlagRequired("file")
	_ = imp.MarkFlagRequired("agent")

	_ = stdin
	cmd.AddCommand(mint, list, revoke, rotate, imp)
	return cmd
}
