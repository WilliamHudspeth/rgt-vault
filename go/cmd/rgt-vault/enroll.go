package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"rgt-vault-server/internal/servecmd"
	"rgt-vault-server/internal/server"
	"rgt-vault-server/internal/store"
	"rgt-vault-server/internal/totp"
)

// Audit event written when --force replaces an existing TOTP secret.
const auditTOTPReplaced = "TOTP_SECRET_REPLACED"

func newEnroll2FACmd(vf *servecmd.VaultFlags, stdout io.Writer) *cobra.Command {
	var out, account string
	var force, showSecret bool
	cmd := &cobra.Command{
		Use:   "enroll-2fa",
		Short: "Generate a TOTP secret for approval 2FA",
		Long: "Generate a TOTP secret, write it to --out (mode 0600 from the moment the file is created) and\n" +
			"print the provisioning URI for an authenticator app.\n\n" +
			"The provisioning URI and the secret are shown once, on the terminal, so you can add them to an\n" +
			"authenticator app; when stdout is redirected or piped they are NOT printed unless you pass\n" +
			"--show-secret (so they do not end up in logs). The file is always written.\n\n" +
			"An existing secret file is never overwritten without --force. A forced replacement locks\n" +
			"out the old authenticator, so it is recorded in the vault's audit log (" + auditTOTPReplaced + ");\n" +
			"if a vault exists at --db but cannot be opened to record it, the secret is left untouched.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runEnroll2FA(cmd.Context(), vf, out, account, force, showSecret, stdout, cmd.ErrOrStderr())
		},
	}
	cmd.Flags().StringVar(&out, "out", servecmd.DefaultTOTPPath(), "where to write the base32 secret")
	cmd.Flags().StringVar(&account, "account", "operator", "account label for the authenticator app")
	cmd.Flags().BoolVar(&force, "force", false, "replace an existing secret file (audited)")
	cmd.Flags().BoolVar(&showSecret, "show-secret", false, "print the provisioning URI and secret even when stdout is not a terminal")
	return cmd
}

func runEnroll2FA(ctx context.Context, vf *servecmd.VaultFlags, out, account string, force, showSecret bool, stdout, stderr io.Writer) error {
	if out == "" {
		return errors.New("no output path: home directory unknown, pass --out")
	}
	path, err := server.ExpandHome(out)
	if err != nil {
		return err
	}
	fi, statErr := os.Stat(path)
	exists := statErr == nil
	if exists && fi.IsDir() {
		return fmt.Errorf("%s is a directory: pass --out with a file path", path)
	}
	if exists && !force {
		return fmt.Errorf("%s already exists: use --force to replace it (the old authenticator will stop working)", path)
	}
	secret, err := totp.GenerateSecret(totp.DefaultSecretLength)
	if err != nil {
		return err
	}
	uri, err := totp.ProvisioningURI(secret, account, totp.WithIssuer("rgt-vault"))
	if err != nil {
		return err
	}

	// Record a forced replacement BEFORE destroying the old secret.
	if exists {
		if err := auditTOTPReplace(ctx, vf, path, stderr); err != nil {
			return err
		}
	}
	if _, err := writeSecretFile(path, []byte(secret+"\n"), force); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "TOTP secret written to: %s (mode 0600)\n", path)
	if showSecret || isTerminal(stdout) {
		fmt.Fprintln(stdout, "Add it to your authenticator app via this URI (or type the secret). It is shown only now:")
		fmt.Fprintln(stdout, "  "+uri)
		fmt.Fprintf(stdout, "  secret: %s\n", secret)
	} else {
		fmt.Fprintln(stdout, "The provisioning URI and secret were not printed because stdout is not a terminal;")
		fmt.Fprintln(stdout, "re-run with --show-secret (and --force to replace this one), or read the file yourself.")
	}
	fmt.Fprintf(stdout, "\nStart the daemon with:  rgt-vault serve --require-approval --operator-token-file <operator token> --totp-secret-file %s\n", path)
	return nil
}

// isTerminal reports whether w is a character device (an interactive
// terminal): buffers, pipes, files and the null device are not.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	// The null device is a character device too, and is not a person.
	if null, err := os.Stat(os.DevNull); err == nil && os.SameFile(fi, null) {
		return false
	}
	return true
}

// auditTOTPReplace appends the audit row for a forced replacement. When no
// vault exists at --db there is no log to write to and a notice is printed;
// when one exists but cannot be opened the replacement is refused.
func auditTOTPReplace(ctx context.Context, vf *servecmd.VaultFlags, path string, stderr io.Writer) error {
	res, err := vf.Resolve(os.Getenv)
	if err != nil {
		return err
	}
	if !vaultFileExists(res.DB) {
		fmt.Fprintf(stderr, "notice: no vault at %s, so replacing %s is not audited\n", res.DB, path)
		return nil
	}
	stack, err := openStackAt(ctx, res, server.StackOptions{})
	if err != nil {
		return fmt.Errorf("refusing to replace %s: cannot record it in the audit log: %w", path, err)
	}
	defer stack.Close()
	if err := stack.Vault.Audit(ctx, auditTOTPReplaced, store.Name("TOTP"), "TOTP secret file replaced with --force", store.Name("cli")); err != nil {
		return fmt.Errorf("refusing to replace %s: cannot record it in the audit log: %w", path, err)
	}
	return nil
}
