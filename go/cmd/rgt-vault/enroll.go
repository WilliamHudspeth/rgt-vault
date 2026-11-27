package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"rgt-vault-server/internal/approval"
	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/servecmd"
	"rgt-vault-server/internal/server"
	"rgt-vault-server/internal/store"
	"rgt-vault-server/internal/totp"
)

// Audit event written when --force replaces an existing TOTP secret.
const auditTOTPReplaced = "TOTP_SECRET_REPLACED"

func newEnroll2FACmd(vf *servecmd.VaultFlags, stdout io.Writer) *cobra.Command {
	var out, account, storeFlag string
	var force, showSecret, offlineAck bool
	cmd := &cobra.Command{
		Use:   "enroll-2fa",
		Short: "Generate a TOTP secret for approval 2FA",
		Long: "Generate a TOTP secret, write it to --out (mode 0600 from the moment the file is created) and\n" +
			"print the provisioning URI for an authenticator app.\n\n" +
			"The provisioning URI and the secret are shown once, on the terminal, so you can add them to an\n" +
			"authenticator app; when stdout is redirected or piped they are NOT printed unless you pass\n" +
			"--show-secret (so they do not end up in logs). The file is always written.\n\n" +
			"An existing secret file is never overwritten without --force. A forced replacement locks\n" +
			"out the old authenticator, so it needs an operator token (or, when there is no operator token to\n" +
			"check, --i-am-offline-operator; a named --token-store that does not exist is an error)\n" +
			"(--token, RGT_VAULT_TOKEN, RGT_VAULT_TOKEN_FILE or ~/.config/rgt-vault/operator.token), prints a\n" +
			"warning, and is recorded in the vault's audit log (" + auditTOTPReplaced + ") with the operator token id\n" +
			"and a short fingerprint of the OLD secret (never the secret itself); if a vault exists at --db but\n" +
			"cannot be opened to record it, the secret is left untouched.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tok := ""
			if f := cmd.Flag("token"); f != nil {
				tok = f.Value.String()
			}
			return runEnroll2FA(cmd.Context(), vf, out, account, force, showSecret, stdout, cmd.ErrOrStderr(), replaceAuth{tokenFlag: tok, storeFlag: storeFlag, offlineAck: offlineAck})
		},
	}
	cmd.Flags().StringVar(&out, "out", servecmd.DefaultTOTPPath(), "where to write the base32 secret")
	cmd.Flags().StringVar(&account, "account", "operator", "account label for the authenticator app")
	cmd.Flags().BoolVar(&force, "force", false, "replace an existing secret file (needs an operator token when the token store has one; audited; the old authenticator stops working)")
	cmd.Flags().BoolVar(&offlineAck, "i-am-offline-operator", false, "with --force: replace the secret although there is no operator token to check (no token store, or none with the operator scope); recorded in the audit row")
	cmd.Flags().StringVar(&storeFlag, "token-store", "", "token store that holds the operator token checked by --force (env RGT_VAULT_TOKEN_STORE, default ~/.config/rgt-vault/tokens.json)")
	cmd.Flags().BoolVar(&showSecret, "show-secret", false, "print the provisioning URI and secret even when stdout is not a terminal")
	return cmd
}

// replaceAuth is where --force finds its proof of operator scope.
type replaceAuth struct {
	tokenFlag  string // root --token
	storeFlag  string // --token-store
	offlineAck bool   // --i-am-offline-operator
}

// authorizeReplace decides whether this caller may replace the TOTP secret
// and returns the operator token id (or "offline-ack") for the audit row.
//
// Replacing the secret locks out the operator's authenticator, so it is an
// operator action:
//   - the token store holds an unexpired operator token: the caller MUST
//     present one (--token, RGT_VAULT_TOKEN, RGT_VAULT_TOKEN_FILE or
//     operator.token) that authenticates with the operator scope;
//   - an explicitly named store (--token-store or RGT_VAULT_TOKEN_STORE) that
//     is missing or unreadable is an error (fail closed: a mistyped or
//     attacker-chosen path must not switch the check off);
//   - the default store missing, or holding no operator token (a fresh or
//     legacy setup): refused unless --i-am-offline-operator says "I own this
//     machine and there is no operator token to ask for". The row then
//     records operator "offline-ack".
//
// This is a safeguard against a mistake or a casual misuse, not a security
// boundary: whoever can write the 0600 secret file as this user can replace
// it with any tool.
func authorizeReplace(ra replaceAuth, stderr io.Writer) (string, error) {
	path, err := tokenStorePath(ra.storeFlag)
	if err != nil {
		return "", err
	}
	explicit := ra.storeFlag != "" || os.Getenv("RGT_VAULT_TOKEN_STORE") != ""
	needAck := func(reason string) (string, error) {
		if !ra.offlineAck {
			return "", fmt.Errorf("replacing the TOTP secret needs an operator token, but %s; "+
				"if this machine has no operator token and you are its operator, pass --i-am-offline-operator", reason)
		}
		fmt.Fprintf(stderr, "WARNING: %s: replacing the TOTP secret on your own say-so (--i-am-offline-operator)\n", reason)
		return "offline-ack", nil
	}
	st := auth.OpenStore(path)
	if !st.Exists() {
		if explicit {
			return "", fmt.Errorf("refusing to replace the TOTP secret: the token store %s does not exist (fix --token-store / RGT_VAULT_TOKEN_STORE)", path)
		}
		return needAck("there is no token store at " + path)
	}
	infos, err := st.List()
	if err != nil {
		return "", fmt.Errorf("refusing to replace the TOTP secret: cannot read the token store: %w", err)
	}
	now := time.Now()
	hasOperator := false
	for _, in := range infos {
		if in.Expired(now) {
			continue
		}
		for _, sc := range in.Scopes {
			if sc == auth.ScopeOperator {
				hasOperator = true
			}
		}
	}
	if !hasOperator {
		return needAck("the token store " + path + " has no operator token")
	}
	tok := resolveToken(ra.tokenFlag, operatorCmd)
	if tok == "" {
		return "", errors.New("replacing the TOTP secret needs an operator token: pass --token, or set RGT_VAULT_TOKEN / RGT_VAULT_TOKEN_FILE (or keep it in ~/.config/rgt-vault/operator.token)")
	}
	p, err := st.Authenticate("Bearer " + tok)
	if err != nil || !p.Has(auth.ScopeOperator) {
		return "", errors.New("replacing the TOTP secret needs a valid token with the operator scope")
	}
	return p.TokenID, nil
}

// secretFingerprint is the first 8 hex digits of sha256 of the secret text
// (whitespace trimmed): enough to tell two secrets apart in the audit log,
// useless for recovering one. The unreadable / empty cases get a label.
func secretFingerprint(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "unreadable"
	}
	t := strings.TrimSpace(string(b))
	if t == "" {
		return "empty"
	}
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])[:8]
}

func runEnroll2FA(ctx context.Context, vf *servecmd.VaultFlags, out, account string, force, showSecret bool, stdout, stderr io.Writer, ra replaceAuth) error {
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

	// A forced replacement: check the operator, warn, and record it BEFORE
	// destroying the old secret.
	if exists {
		operatorID, err := authorizeReplace(ra, stderr)
		if err != nil {
			return err
		}
		fp := secretFingerprint(path)
		fmt.Fprintf(stderr, "WARNING: replacing the TOTP secret %s (old secret fingerprint %s, operator token %s): the old authenticator stops working\n", path, fp, operatorID)
		if err := auditTOTPReplace(ctx, vf, path, fp, operatorID, stderr); err != nil {
			return err
		}
		notifyWebhook(ctx, stderr, approval.EventTOTPReplaced, "",
			"TOTP secret replaced with --force old_secret_fingerprint="+fp+" operator_token="+operatorID+" by="+cliUser())
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
func auditTOTPReplace(ctx context.Context, vf *servecmd.VaultFlags, path, oldFingerprint, operatorID string, stderr io.Writer) error {
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
	details := "TOTP secret file replaced with --force old_secret_fingerprint=" + oldFingerprint +
		" operator_token=" + operatorID + " by=" + cliUser()
	if err := stack.Vault.Audit(ctx, auditTOTPReplaced, store.Name("TOTP"), details, store.Name("cli")); err != nil {
		return fmt.Errorf("refusing to replace %s: cannot record it in the audit log: %w", path, err)
	}
	return nil
}
