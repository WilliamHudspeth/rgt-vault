// Package servecmd is the one implementation of `rgt-vault serve`: it opens
// the real vault (server.OpenStack), builds the HTTP handler (server.New)
// and serves it on a loopback address until the context is cancelled.
//
// Both binaries use it: go/cmd/rgt-vault (`rgt-vault serve`) and the
// deprecated alias go/cmd/server (`rgt-vault-server`).
//
// Flags (decision D6: Python's default port 8765):
//
//	--db / RGT_VAULT_DB                   default ~/.secure-vault/vault.db
//	--policy / RGT_VAULT_POLICY           ABAC policy YAML; unset = deny everything
//	--provider / RGT_VAULT_PROVIDER       keyring (default), file or platform
//	--master-key-file / RGT_VAULT_MASTER_KEY_FILE
//	                                      key file of the file provider; unset = the
//	                                      systemd credential $CREDENTIALS_DIRECTORY/
//	                                      rgt-vault-master, else ~/.config/rgt-vault/
//	                                      keys/<vault-id>.key (docs/guides/providers.md)
//	--host / RGT_VAULT_HOST               listen address, default 127.0.0.1
//	--port / RGT_VAULT_PORT               listen port, default 8765
//	--tls-cert / RGT_VAULT_TLS_CERT       PEM certificate (chain) to serve HTTPS with
//	--tls-key / RGT_VAULT_TLS_KEY         its PEM private key; refused if group/other can
//	                                      read it (Unix). Both or neither
//	--tls-client-ca / RGT_VAULT_TLS_CLIENT_CA
//	                                      PEM CA bundle: turns on mutual TLS
//	--tls-client-auth / RGT_VAULT_TLS_CLIENT_AUTH
//	                                      require (default with a client CA) or
//	                                      verify-if-given
//	--tls-reload-interval                 poll the TLS files for changes (default 1m,
//	                                      0 = off); SIGHUP always reloads
//	--allow-insecure-non-loopback         permit a non-loopback --host WITHOUT TLS
//	                                      (loud warning + audit row). Without TLS a
//	                                      non-loopback bind is refused. The old name
//	                                      --allow-non-loopback is a deprecated alias.
//	--token-store / RGT_VAULT_TOKEN_STORE per-agent token store (hashes only), default
//	                                      ~/.config/rgt-vault/tokens.json (batch H1;
//	                                      manage it with `rgt-vault token`)
//	--legacy-shared-token                 DEPRECATED: authenticate with the single shared
//	                                      token file instead (self-asserted agent field)
//	--token-file / RGT_VAULT_TOKEN_FILE   legacy only: shared agent token, default
//	                                      ~/.config/rgt-vault/server.token
//	--operator-token-file / RGT_VAULT_OPERATOR_TOKEN_FILE
//	                                      legacy only: token for /v1/requests*
//	--require-approval                    live approval of every unseal
//	--totp-secret-file / RGT_VAULT_TOTP_SECRET_FILE   base32 secret (2FA approvals)
//	--approval-timeout                    default 120s
//	--harness-key-file / RGT_VAULT_HARNESS_KEY_FILE   HMAC key for v2 capability
//	                                      tokens; unset = capability execution
//	                                      fails closed
//	--allow-private-network               built-in HTTP actions may reach private
//	                                      addresses (SSRF risk)
//	CORS_ALLOWED_ORIGINS                  comma-separated exact origins; unset = no CORS
//	RGT_VAULT_MAX_BODY_BYTES              request body limit, default 1 MiB
//
// TLS policy (internal/transport): TLS 1.2 minimum with ECDHE + AES-GCM /
// ChaCha20-Poly1305 only (TLS 1.3 preferred), HTTP/2 allowed, session tickets
// off, no renegotiation, HSTS on every response. See docs/guides/tls.md.
//
// The bearer tokens are NEVER printed or logged. Only the token file paths
// and short token ids (a hash prefix) appear in output.
package servecmd

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/actions"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/approval"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/auth"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/hooks"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/kdf"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/providers"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/server"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/server/handlers"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/transport"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/vault"
)

// Defaults of Python's `rgt-vault serve` (decision D6).
const (
	DefaultHost = "127.0.0.1"
	DefaultPort = "8765"
	// DefaultApprovalTimeout is how long an approval request waits.
	DefaultApprovalTimeout = 120 * time.Second
)

// DefaultTokenPath is ~/.config/rgt-vault/server.token ("" if there is no
// home directory).
func DefaultTokenPath() string { return configPath("server.token") }

// DefaultTokenStorePath is ~/.config/rgt-vault/tokens.json, the per-agent
// token store (hashes only).
func DefaultTokenStorePath() string { return configPath("tokens.json") }

// DefaultOperatorTokenPath is ~/.config/rgt-vault/operator.token.
func DefaultOperatorTokenPath() string { return configPath("operator.token") }

// DefaultTOTPPath is ~/.config/rgt-vault/totp.secret.
func DefaultTOTPPath() string { return configPath("totp.secret") }

func configPath(name string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "rgt-vault", name)
}

// Env carries the process-level dependencies of the command, so tests can
// replace them. The zero value is usable: it reads the real environment and
// uses the real master-secret providers.
type Env struct {
	// Getenv reads environment variables (default os.Getenv).
	Getenv func(string) string
	// Stdout receives the startup banner (default os.Stdout).
	Stdout io.Writer
	// Logger receives warnings and progress (default log.Default()).
	Logger *log.Logger
	// NewProvider builds the named master-secret provider (default
	// server.NewProviderWith with the resolved --master-key-file).
	NewProvider func(name string) (vault.MasterProvider, error)
	// KDFParams are the Argon2 parameters for a NEW keychain (tests only;
	// zero means Python's defaults).
	KDFParams kdf.Params
	// Ready, if set, is called with the bound address once the listener is
	// up (tests).
	Ready func(addr string)
}

func (e Env) getenv(k string) string {
	if e.Getenv != nil {
		return e.Getenv(k)
	}
	return os.Getenv(k)
}

func (e Env) stdout() io.Writer {
	if e.Stdout != nil {
		return e.Stdout
	}
	return os.Stdout
}

func (e Env) logger() *log.Logger {
	if e.Logger != nil {
		return e.Logger
	}
	return log.Default()
}

func (e Env) newProvider(r Resolved) (vault.MasterProvider, error) {
	if e.NewProvider != nil {
		return e.NewProvider(r.Provider)
	}
	return server.NewProviderWith(r.Provider, r.ProviderOptions())
}

// VaultFlags are the flags that select a vault: --db, --policy, --provider.
// `rgt-vault` registers them once as persistent root flags (like Python's
// global options); `rgt-vault-server` registers them on its own command.
type VaultFlags struct {
	DB            string
	Policy        string
	Provider      string
	MasterKeyFile string
}

// Register adds the flags to cmd.
func (v *VaultFlags) Register(cmd *cobra.Command, persistent bool) {
	fs := cmd.Flags()
	if persistent {
		fs = cmd.PersistentFlags()
	}
	fs.StringVar(&v.DB, "db", "", "vault database (env RGT_VAULT_DB, default "+server.DefaultDBPath+")")
	fs.StringVar(&v.Policy, "policy", "", "ABAC policy YAML (env RGT_VAULT_POLICY; default: deny everything)")
	fs.StringVar(&v.Provider, "provider", "", "master-secret provider: keyring, file or platform (env RGT_VAULT_PROVIDER, default keyring; see docs/guides/providers.md)")
	fs.StringVar(&v.MasterKeyFile, "master-key-file", "", "key file of --provider file (env "+providers.EnvMasterKeyFile+"; default: the systemd credential rgt-vault-master, else ~/.config/rgt-vault/keys/<vault-id>.key)")
}

// Resolved are the vault-selection settings after flag > environment >
// default resolution.
type Resolved struct {
	DB       string
	Policy   string
	Provider string
	// MasterKeyFile is the explicit key file of the file provider (expanded;
	// empty when the provider is not "file" or no path was given).
	MasterKeyFile string
}

// ProviderOptions are the provider settings of r.
func (r Resolved) ProviderOptions() server.ProviderOptions {
	return server.ProviderOptions{MasterKeyFile: r.MasterKeyFile}
}

// Resolve applies flag > environment > default.
func (v *VaultFlags) Resolve(getenv func(string) string) (Resolved, error) {
	r := Resolved{
		DB:       firstNonEmpty(v.DB, getenv("RGT_VAULT_DB"), server.DefaultDBPath),
		Policy:   firstNonEmpty(v.Policy, getenv("RGT_VAULT_POLICY")),
		Provider: firstNonEmpty(v.Provider, getenv("RGT_VAULT_PROVIDER"), server.ProviderKeyring),
	}
	switch r.Provider {
	case server.ProviderKeyring, server.ProviderPlatform, server.ProviderFile:
	default:
		return Resolved{}, fmt.Errorf("unknown provider %q: use 'keyring', 'file' or 'platform'", r.Provider)
	}
	if r.Provider == server.ProviderFile {
		r.MasterKeyFile = firstNonEmpty(v.MasterKeyFile, getenv(providers.EnvMasterKeyFile))
		if r.MasterKeyFile != "" {
			p, err := server.ExpandHome(r.MasterKeyFile)
			if err != nil {
				return Resolved{}, err
			}
			r.MasterKeyFile = p
		}
	} else if v.MasterKeyFile != "" {
		return Resolved{}, fmt.Errorf("--master-key-file needs --provider file (the provider is %q)", r.Provider)
	}
	db, err := server.ExpandHome(r.DB)
	if err != nil {
		return Resolved{}, err
	}
	r.DB = db
	return r, nil
}

// Flags holds the raw `serve` flag values.
type Flags struct {
	Host                     string
	Port                     string
	AllowInsecureNonLoopback bool
	// AllowNonLoopback is the deprecated spelling of AllowInsecureNonLoopback.
	AllowNonLoopback    bool
	TLSCert             string
	TLSKey              string
	TLSClientCA         string
	TLSClientAuth       string
	TLSReloadInterval   time.Duration
	TokenStore          string
	LegacySharedToken   bool
	LegacyPrivileged    bool
	TokenFile           string
	OperatorTokenFile   string
	RequireApproval     bool
	TOTPSecretFile      string
	ApprovalTimeout     time.Duration
	HarnessKeyFile      string
	AllowPrivateNetwork bool
	// Destinations is the destination allow-list mode (RGT-523): enforce
	// (default) or warn (temporary migration switch).
	Destinations string

	// RequireApprovalFor lists mutating operations (set, rotate, revoke,
	// all) that also wait for operator approval (batch H2; default none).
	RequireApprovalFor string
	// SecurityWebhookURL receives approval security events as JSON (bad or
	// replayed TOTP codes, lockouts, self-approval attempts), in addition to
	// the audit row and the log line every event always gets.
	SecurityWebhookURL         string
	SecurityWebhookAllowRemote bool
}

// config is the resolved server configuration.
type config struct {
	host string
	port string
	// allowInsecure permits a non-loopback bind without TLS.
	allowInsecure bool
	tls           server.TLSSettings
	tokenFile     string
	// tokenStore is the per-agent store; legacy selects the shared token
	// files (tokenFile / operatorTokenFile) instead.
	tokenStore string
	legacy     bool
	// legacyPrivileged lets the shared token reach lease/rotate/audit.
	legacyPrivileged bool
	origins          []string
	rejected         []string
	maxBody          int64

	vault               Resolved
	operatorTokenFile   string
	requireApproval     bool
	totpSecretFile      string
	approvalTimeout     time.Duration
	harnessKeyFile      string
	allowPrivateNetwork bool
	destinations        actions.DestinationMode

	gatedOps           []approval.GatedOp
	securityWebhook    string
	securityWebhookRem bool
}

// approvalActive reports whether an approval broker will run: reads
// (--require-approval) or any gated mutating operation.
func (c config) approvalActive() bool { return c.requireApproval || len(c.gatedOps) > 0 }

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// parseConfig resolves flags, then environment, then defaults.
func parseConfig(f Flags, vf *VaultFlags, getenv func(string) string) (config, error) {
	if f.ApprovalTimeout <= 0 || f.ApprovalTimeout > MaxApprovalTimeout {
		return config{}, fmt.Errorf("invalid --approval-timeout %s (must be above 0 and at most %s)", f.ApprovalTimeout, MaxApprovalTimeout)
	}
	res, err := vf.Resolve(getenv)
	if err != nil {
		return config{}, err
	}
	cfg := config{
		host:          firstNonEmpty(f.Host, getenv("RGT_VAULT_HOST"), DefaultHost),
		port:          firstNonEmpty(f.Port, getenv("RGT_VAULT_PORT"), DefaultPort),
		allowInsecure: f.AllowInsecureNonLoopback || f.AllowNonLoopback,
		tls: server.TLSSettings{
			CertFile:       firstNonEmpty(f.TLSCert, getenv("RGT_VAULT_TLS_CERT")),
			KeyFile:        firstNonEmpty(f.TLSKey, getenv("RGT_VAULT_TLS_KEY")),
			ClientCAFile:   firstNonEmpty(f.TLSClientCA, getenv("RGT_VAULT_TLS_CLIENT_CA")),
			ClientAuth:     firstNonEmpty(f.TLSClientAuth, getenv("RGT_VAULT_TLS_CLIENT_AUTH")),
			ReloadInterval: f.TLSReloadInterval,
		},
		maxBody: server.DefaultMaxBodyBytes,
		legacy:  f.LegacySharedToken,

		legacyPrivileged: f.LegacyPrivileged,

		vault:               res,
		requireApproval:     f.RequireApproval,
		totpSecretFile:      firstNonEmpty(f.TOTPSecretFile, getenv("RGT_VAULT_TOTP_SECRET_FILE")),
		approvalTimeout:     f.ApprovalTimeout,
		harnessKeyFile:      firstNonEmpty(f.HarnessKeyFile, getenv("RGT_VAULT_HARNESS_KEY_FILE")),
		allowPrivateNetwork: f.AllowPrivateNetwork,
	}
	gated, err := approval.ParseGatedOps(firstNonEmpty(f.RequireApprovalFor, getenv("RGT_VAULT_REQUIRE_APPROVAL_FOR")))
	if err != nil {
		return config{}, err
	}
	cfg.gatedOps = gated
	if cfg.destinations, err = actions.ParseDestinationMode(firstNonEmpty(f.Destinations, getenv("RGT_VAULT_DESTINATIONS"))); err != nil {
		return config{}, err
	}
	cfg.securityWebhook = firstNonEmpty(f.SecurityWebhookURL, getenv("RGT_VAULT_SECURITY_WEBHOOK_URL"))
	cfg.securityWebhookRem = f.SecurityWebhookAllowRemote
	if cfg.securityWebhookRem && cfg.securityWebhook == "" {
		return config{}, errors.New("--security-webhook-allow-remote needs --security-webhook-url")
	}
	if err := cfg.tls.Validate(); err != nil {
		return config{}, err
	}
	if f.TLSReloadInterval < 0 {
		return config{}, fmt.Errorf("invalid --tls-reload-interval %s", f.TLSReloadInterval)
	}
	if cfg.legacyPrivileged && !cfg.legacy {
		return config{}, errors.New("--legacy-allow-privileged-routes needs --legacy-shared-token")
	}
	if cfg.legacy {
		cfg.tokenFile = firstNonEmpty(f.TokenFile, getenv("RGT_VAULT_TOKEN_FILE"), DefaultTokenPath())
		cfg.operatorTokenFile = firstNonEmpty(f.OperatorTokenFile, getenv("RGT_VAULT_OPERATOR_TOKEN_FILE"))
		if f.TokenStore != "" {
			return config{}, errors.New("--token-store does not apply with --legacy-shared-token")
		}
		if cfg.tokenFile == "" {
			return cfg, errors.New("no token path: home directory unknown, pass --token-file")
		}
	} else {
		if f.TokenFile != "" || f.OperatorTokenFile != "" {
			return config{}, errors.New("--token-file and --operator-token-file are the pre-H1 shared tokens: they need " +
				"--legacy-shared-token. The default is the per-agent token store (--token-store); move an existing " +
				"token file into it with `rgt-vault token import --file FILE --agent NAME --scope ...`")
		}
		cfg.tokenStore = firstNonEmpty(f.TokenStore, getenv("RGT_VAULT_TOKEN_STORE"), DefaultTokenStorePath())
		if cfg.tokenStore == "" {
			return cfg, errors.New("no token store path: home directory unknown, pass --token-store")
		}
	}
	if cfg.legacy && cfg.approvalActive() && cfg.operatorTokenFile == "" {
		// Without a separate operator token the approve/deny endpoints would
		// accept the AGENT token, so any agent could approve its own request.
		return config{}, errors.New("--require-approval / --require-approval-for need --operator-token-file (or RGT_VAULT_OPERATOR_TOKEN_FILE): " +
			"without a separate operator token an agent could approve its own request. " +
			"`rgt-vault init` creates one at " + DefaultOperatorTokenPath())
	}
	if cfg.totpSecretFile != "" && !cfg.approvalActive() {
		return config{}, errors.New("--totp-secret-file needs --require-approval or --require-approval-for")
	}
	if p, err := strconv.Atoi(cfg.port); err != nil || p < 0 || p > 65535 {
		return config{}, fmt.Errorf("invalid port %q", cfg.port)
	}
	if v := getenv("RGT_VAULT_MAX_BODY_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return config{}, fmt.Errorf("invalid RGT_VAULT_MAX_BODY_BYTES %q", v)
		}
		cfg.maxBody = n
	}
	cfg.origins, cfg.rejected = server.ParseAllowedOrigins(getenv("CORS_ALLOWED_ORIGINS"))
	return cfg, nil
}

// writeTimeout bounds writing a response. A request waiting for operator
// approval holds its response until the broker decides (up to the approval
// timeout), so the limit must outlast it or an approved lease could not be
// answered.
func writeTimeout(cfg config) time.Duration {
	const base = 60 * time.Second
	if cfg.approvalActive() {
		return cfg.approvalTimeout + base
	}
	return base
}

// MaxApprovalTimeout caps --approval-timeout: a request waiting for an
// operator holds a connection (and the response write deadline) that long.
const MaxApprovalTimeout = 24 * time.Hour

// tokensEqual compares two tokens in constant time: both sides are hashed
// first, so neither the content nor the length leaks through timing.
func tokensEqual(a, b string) bool {
	ha, hb := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

// IsLoopbackHost reports whether host is "localhost" or a loopback address.
func IsLoopbackHost(host string) bool { return transport.IsLoopbackHost(host) }

// NewCommand returns the `serve` command. vf are the shared vault flags
// (already registered by the caller on a parent); nil registers --db,
// --policy and --provider on the command itself.
func NewCommand(env Env, vf *VaultFlags) *cobra.Command {
	var f Flags
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the HTTP(S) server on the real vault (loopback, plain HTTP by default)",
		Long: "Open the vault at --db (creating it on first use), serve the HTTP API on --host:--port and\n" +
			"keep every secret on disk, so data persists across restarts.\n\n" +
			"Without --policy every request is denied (default deny). Without --harness-key-file\n" +
			"/v1/capabilities/execute fails closed.\n\n" +
			"Without --tls-cert/--tls-key the server speaks plain HTTP and only a loopback --host is\n" +
			"accepted. With them it serves TLS 1.2+ (AEAD suites only); --tls-client-ca adds mutual TLS.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := parseConfig(f, vf, env.getenv)
			if err != nil {
				return err
			}
			return Run(cmd.Context(), cfg, env)
		},
	}
	if vf == nil {
		vf = &VaultFlags{}
		vf.Register(cmd, false)
	}
	fs := cmd.Flags()
	fs.StringVar(&f.Host, "host", "", "listen address (env RGT_VAULT_HOST, default "+DefaultHost+")")
	fs.StringVar(&f.Port, "port", "", "listen port (env RGT_VAULT_PORT, default "+DefaultPort+")")
	fs.StringVar(&f.TLSCert, "tls-cert", "", "PEM certificate (chain) to serve HTTPS with (env RGT_VAULT_TLS_CERT); needs --tls-key")
	fs.StringVar(&f.TLSKey, "tls-key", "", "PEM private key for --tls-cert (env RGT_VAULT_TLS_KEY); refused if group/other can read it")
	fs.StringVar(&f.TLSClientCA, "tls-client-ca", "", "PEM CA bundle that signs client certificates: enables mutual TLS (env RGT_VAULT_TLS_CLIENT_CA); the bearer token is still required")
	fs.StringVar(&f.TLSClientAuth, "tls-client-auth", "", "mutual TLS mode: require (default with --tls-client-ca) or verify-if-given (env RGT_VAULT_TLS_CLIENT_AUTH)")
	fs.DurationVar(&f.TLSReloadInterval, "tls-reload-interval", server.DefaultTLSReloadInterval, "how often the TLS files are checked for a change and reloaded without dropping connections (0 = only on SIGHUP)")
	fs.BoolVar(&f.AllowInsecureNonLoopback, "allow-insecure-non-loopback", false, "permit a non-loopback --host WITHOUT TLS (plain HTTP: tokens and secrets cross the network unencrypted; logged and audited)")
	fs.BoolVar(&f.AllowNonLoopback, "allow-non-loopback", false, "")
	_ = fs.MarkDeprecated("allow-non-loopback", "use --tls-cert/--tls-key, or --allow-insecure-non-loopback for plain HTTP")
	fs.StringVar(&f.TokenStore, "token-store", "", "per-agent token store (env RGT_VAULT_TOKEN_STORE, default ~/.config/rgt-vault/tokens.json; see `rgt-vault token`)")
	fs.BoolVar(&f.LegacySharedToken, "legacy-shared-token", false, "DEPRECATED: authenticate with one shared token file and the self-asserted agent field (pre-H1 behaviour); the lease route, /v1/rotate and the audit log are then refused")
	fs.BoolVar(&f.LegacyPrivileged, "legacy-allow-privileged-routes", false, "with --legacy-shared-token: let the shared token also reach the plaintext lease route, /v1/rotate and the audit log (full pre-H1 exposure)")
	fs.StringVar(&f.TokenFile, "token-file", "", "legacy only: shared agent token file (env RGT_VAULT_TOKEN_FILE, default ~/.config/rgt-vault/server.token; created 0600 if missing)")
	fs.StringVar(&f.OperatorTokenFile, "operator-token-file", "", "legacy only: operator token for approve/deny (env RGT_VAULT_OPERATOR_TOKEN_FILE)")
	fs.BoolVar(&f.RequireApproval, "require-approval", false, "require live operator approval for every unseal")
	fs.StringVar(&f.TOTPSecretFile, "totp-secret-file", "", "base32 TOTP secret for 2FA approvals (env RGT_VAULT_TOTP_SECRET_FILE; see enroll-2fa)")
	fs.DurationVar(&f.ApprovalTimeout, "approval-timeout", DefaultApprovalTimeout, "how long an approval request waits before it is denied")
	fs.StringVar(&f.RequireApprovalFor, "require-approval-for", "", "also require live operator approval for these operations: comma list of set, rotate, revoke or all (env RGT_VAULT_REQUIRE_APPROVAL_FOR; default none; the approver must be another token than the requester)")
	fs.StringVar(&f.SecurityWebhookURL, "security-webhook-url", "", "DEPRECATED, use env RGT_VAULT_SECURITY_WEBHOOK_URL: POST approval security events (bad/replayed TOTP codes, lockouts, self-approval) to this http(s) URL ( loopback only unless --security-webhook-allow-remote)")
	fs.BoolVar(&f.SecurityWebhookAllowRemote, "security-webhook-allow-remote", false, "let the security webhook reach a non-loopback host")
	// The URL may carry a credential and a command-line flag is visible in
	// `ps`: the environment variable is the supported way.
	_ = fs.MarkDeprecated("security-webhook-url", "put the URL in the environment variable RGT_VAULT_SECURITY_WEBHOOK_URL: a command line is visible to other users in `ps`")
	fs.StringVar(&f.HarnessKeyFile, "harness-key-file", "", "HMAC key for v2 capability tokens (env RGT_VAULT_HARNESS_KEY_FILE)")
	fs.BoolVar(&f.AllowPrivateNetwork, "allow-private-network", false, "let built-in HTTP actions reach loopback/private addresses (SSRF risk)")
	fs.StringVar(&f.Destinations, "destinations", "enforce", "destination allow-list mode: enforce, or warn (TEMPORARY, removed in the next release: secrets with no destinations: entry are sent to any host, logged and audited; secrets with an entry stay enforced) (env RGT_VAULT_DESTINATIONS)")
	return cmd
}

// Main runs cmd as a process main: it cancels the context on SIGINT/SIGTERM
// and returns the process exit code.
func Main(cmd *cobra.Command, args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cmd.SetArgs(args)
	if err := cmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(cmd.ErrOrStderr(), "Error:", handlers.LogSafe(err.Error()))
		return 1
	}
	return 0
}

// loadToken reads (creating it 0600 if missing) a bearer token file and
// rejects a weak token. The token itself is never echoed.
func loadToken(path, what string) (string, string, error) {
	p, err := server.ExpandHome(path)
	if err != nil {
		return "", "", err
	}
	p, token, err := auth.LoadOrCreateToken(p)
	if err != nil {
		return "", "", fmt.Errorf("failed to load/create %s: %w", what, err)
	}
	if err := ValidateToken(token); err != nil {
		return "", "", fmt.Errorf("%s %s: %w", what, p, err)
	}
	// An existing file is reused as-is; make sure no other user can read it.
	if err := TightenFile(p); err != nil {
		return "", "", fmt.Errorf("restricting %s: %w", what, err)
	}
	return p, token, nil
}

// authSetup is what loadAuth resolved: the per-agent store, or the legacy
// shared token files.
type authSetup struct {
	store           *auth.Store
	agent, operator *auth.TokenStore
}

// LegacyWarning is logged at startup with --legacy-shared-token.
const LegacyWarning = "WARNING: --legacy-shared-token is DEPRECATED and insecure for more than one agent: every " +
	"client holds the same token and the ABAC subject is the self-asserted \"agent\" field, so any agent can " +
	"act as any other. Mint per-agent tokens (`rgt-vault token mint --agent NAME`) and drop the flag; see " +
	"docs/guides/agent-identity-migration.md"

// LegacyPrivilegedWarning is logged with --legacy-allow-privileged-routes.
const LegacyPrivilegedWarning = "WARNING: --legacy-allow-privileged-routes: EVERY holder of the shared token can read " +
	"plaintext secrets (as any agent it names), rotate keys and read the audit log; there is no scope enforcement"

// loadAuth prepares authentication. The tokens themselves are never printed.
func loadAuth(cfg config, logger *log.Logger) (authSetup, string, error) {
	if !cfg.legacy {
		p, err := server.ExpandHome(cfg.tokenStore)
		if err != nil {
			return authSetup{}, "", err
		}
		st := auth.OpenStore(p)
		infos, err := st.List()
		if err != nil {
			return authSetup{}, "", fmt.Errorf("token store %s: %w", p, err)
		}
		if len(infos) == 0 {
			return authSetup{}, "", fmt.Errorf("token store %s has no tokens: run `rgt-vault init` (creates an operator "+
				"token) and `rgt-vault token mint --agent NAME` for each agent", p)
		}
		if err := TightenFile(p); err != nil {
			return authSetup{}, "", fmt.Errorf("restricting token store: %w", err)
		}
		ops := 0
		for _, in := range infos {
			if !in.Expired(time.Now()) && (auth.Principal{Scopes: in.Scopes}).Has(auth.ScopeOperator) {
				ops++
			}
		}
		if cfg.requireApproval && ops == 0 {
			logger.Printf("WARNING: --require-approval but the token store has no live operator-scoped token: " +
				"nobody can approve until one is minted (rgt-vault token mint --agent NAME --scope operator)")
		}
		logger.Printf("Token store: %s (%d tokens, %d with operator scope)", handlers.LogSafe(p), len(infos), ops)
		return authSetup{store: st}, fmt.Sprintf("per-agent tokens from %s (%d)", p, len(infos)), nil
	}

	logger.Print(LegacyWarning)
	if cfg.legacyPrivileged {
		logger.Print(LegacyPrivilegedWarning)
	} else {
		logger.Print("Legacy mode: the lease route, /v1/rotate and the audit log are refused for the shared token " +
			"(use get/verify-audit --offline, or --legacy-allow-privileged-routes)")
	}
	path, token, err := loadToken(cfg.tokenFile, "agent token")
	if err != nil {
		return authSetup{}, "", err
	}
	tokenID := auth.TokenID(token)
	logger.Printf("Token file: %s", handlers.LogSafe(path))
	logger.Printf("Token ID: %s", tokenID)
	setup := authSetup{agent: auth.NewTokenStore(path)}
	if cfg.operatorTokenFile != "" {
		opPath, opToken, err := loadToken(cfg.operatorTokenFile, "operator token")
		if err != nil {
			return authSetup{}, "", err
		}
		if tokensEqual(opToken, token) {
			return authSetup{}, "", errors.New("the operator token must differ from the agent token")
		}
		setup.operator = auth.NewTokenStore(opPath)
		logger.Printf("Operator token file: %s (id %s)", handlers.LogSafe(opPath), auth.TokenID(opToken))
	}
	return setup, fmt.Sprintf("LEGACY shared bearer token from %s (id %s)", path, tokenID), nil
}

// checkLoopbackListener refuses a plain-HTTP listener that is not bound to a
// loopback address.
func checkLoopbackListener(a net.Addr) error {
	ta, ok := a.(*net.TCPAddr)
	if !ok || !ta.IP.IsLoopback() {
		return fmt.Errorf("refusing to serve plain HTTP: the listener is bound to %s, which is not a loopback address "+
			"(use --tls-cert/--tls-key, or --allow-insecure-non-loopback)", a)
	}
	return nil
}

func clientAuthText(m transport.ClientAuthMode) string {
	switch m {
	case transport.ClientAuthRequire:
		return "required (mTLS)"
	case transport.ClientAuthVerifyIfGiven:
		return "verified if presented (mTLS)"
	}
	return "not requested"
}

// watchSIGHUP reloads the TLS material on SIGHUP and (interval > 0) when the
// files change. The returned function stops it.
func watchSIGHUP(ctx context.Context, t *transport.ServerTLS, interval time.Duration) func() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)
	trigger := make(chan struct{}, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sig:
				select {
				case trigger <- struct{}{}:
				default:
				}
			}
		}
	}()
	go t.Watch(ctx, trigger, interval)
	return func() { signal.Stop(sig) }
}

// ignoreSIGHUP swallows SIGHUP (logging it) while the server has no TLS
// material to reload.
func ignoreSIGHUP(ctx context.Context, logger *log.Logger) func() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sig:
				logger.Printf("SIGHUP ignored: TLS is not enabled, nothing to reload")
			}
		}
	}()
	return func() { signal.Stop(sig) }
}

// Run opens the vault described by cfg and serves until ctx is cancelled.
func Run(ctx context.Context, cfg config, env Env) error {
	if ctx == nil {
		ctx = context.Background()
	}
	logger := env.logger()
	stdout := env.stdout()

	tlsOn := cfg.tls.Enabled()
	insecureWarning, err := server.CheckBind(cfg.host, tlsOn, cfg.allowInsecure)
	if err != nil {
		return err
	}
	// The certificate is loaded (and refused if it is expired, mismatched or
	// its key is world-readable) before anything else is touched.
	var tlsSrv *transport.ServerTLS
	if tlsOn {
		if tlsSrv, err = server.NewTLS(cfg.tls, logger.Printf); err != nil {
			return fmt.Errorf("TLS: %w", err)
		}
		if herr := tlsSrv.CoversHost(cfg.host); herr != nil {
			logger.Printf("WARNING: the TLS certificate does not cover --host %s (%v): clients that connect "+
				"by that name will reject it; reissue it with that name in the SAN", handlers.LogSafe(cfg.host), handlers.LogSafe(herr.Error()))
		}
		if cfg.allowInsecure && !IsLoopbackHost(cfg.host) {
			logger.Printf("NOTE: --allow-insecure-non-loopback has no effect: TLS is enabled")
		}
	}

	for _, bad := range cfg.rejected {
		logger.Printf("WARNING: ignoring CORS origin %q (wildcards and \"null\" are not accepted)", handlers.LogSafe(bad))
	}
	authn, authLine, err := loadAuth(cfg, logger)
	if err != nil {
		return err
	}
	if insecureWarning != "" {
		logger.Print("WARNING: " + insecureWarning)
	}
	if cfg.allowPrivateNetwork {
		logger.Printf("WARNING: --allow-private-network enables the built-in HTTP actions to call " +
			"loopback / RFC1918 addresses. Any caller with a valid bearer token can use this to " +
			"probe internal services (SSRF). Only enable on trusted networks.")
	}

	prov, err := env.newProvider(cfg.vault)
	if err != nil {
		return err
	}
	// Approval security events always reach the log; a webhook is optional.
	var notifier approval.Notifier = approval.LogNotifier{Logf: logger.Printf}
	if cfg.securityWebhook != "" {
		wh, err := hooks.NewEventWebhook(cfg.securityWebhook, cfg.securityWebhookRem)
		if err != nil {
			return err
		}
		notifier = approval.Multi{notifier, wh}
	}
	stack, err := server.OpenStack(ctx, server.StackOptions{
		DBPath:              cfg.vault.DB,
		PolicyFile:          cfg.vault.Policy,
		MasterProvider:      prov,
		RequireApproval:     cfg.requireApproval,
		RequireApprovalFor:  cfg.gatedOps,
		Notifier:            notifier,
		TOTPSecretFile:      cfg.totpSecretFile,
		ApprovalTimeout:     cfg.approvalTimeout,
		HarnessKeyFile:      cfg.harnessKeyFile,
		AllowPrivateNetwork: cfg.allowPrivateNetwork,
		Destinations:        cfg.destinations,
		KDFParams:           env.KDFParams,
	})
	if err != nil {
		return fmt.Errorf("failed to open vault: %w", WithKeyringRemedy(err))
	}
	defer func() {
		if cerr := stack.Close(); cerr != nil {
			logger.Printf("closing vault: %v", handlers.LogSafe(cerr.Error()))
		}
	}()
	if insecureWarning != "" {
		// Leave a trace in the tamper-evident log, not only in the journal.
		details := fmt.Sprintf("plain HTTP on non-loopback host %s port %s (--allow-insecure-non-loopback)", cfg.host, cfg.port)
		if aerr := stack.Vault.Audit(ctx, "server_insecure_bind", sql.NullString{}, details, sql.NullString{}); aerr != nil {
			logger.Printf("WARNING: could not audit the insecure bind: %v", handlers.LogSafe(aerr.Error()))
		}
	}
	if cfg.vault.Policy == "" {
		logger.Printf("WARNING: no --policy given: every secret request is denied (default deny)")
	}
	logger.Printf("Destinations: mode=%s (HTTP actions may send a secret only to the hosts under \"destinations:\" in the policy file)", stack.DestinationMode)
	for _, w := range stack.DestinationWarnings {
		logger.Printf("WARNING: %s", handlers.LogSafe(w))
	}
	if cfg.harnessKeyFile == "" {
		logger.Printf("No --harness-key-file: /v1/capabilities/execute fails closed")
	}

	router, err := server.New(server.Config{
		Vault:                  stack.Vault,
		Tokens:                 authn.store,
		LegacyPrivilegedRoutes: cfg.legacyPrivileged,
		AgentTokens:            authn.agent,
		OperatorTokens:         authn.operator,
		Broker:                 stack.Broker,
		GatedOps:               stack.GatedOps,
		Notifier:               stack.Notifier,
		Actions:                stack.Actions,
		Capabilities:           stack.Capabilities,
		AllowedOrigins:         cfg.origins,
		MaxBodyBytes:           cfg.maxBody,
	})
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(cfg.host, cfg.port))
	if err != nil {
		return fmt.Errorf("listen on %s: %w", net.JoinHostPort(cfg.host, cfg.port), err)
	}
	addr := ln.Addr().String()
	if !tlsOn && !cfg.allowInsecure {
		// CheckBind judged the NAME; judge the address actually bound (a
		// host name such as "localhost" can resolve elsewhere).
		if lerr := checkLoopbackListener(ln.Addr()); lerr != nil {
			_ = ln.Close()
			return lerr
		}
	}

	fmt.Fprintln(stdout, "==============================================")
	fmt.Fprintln(stdout, "  rgt-vault server")
	fmt.Fprintf(stdout, "  Listening on %s\n", addr)
	fmt.Fprintf(stdout, "  Vault: %s (id %s, epoch %d)\n", stack.DBPath, stack.Vault.VaultID(), stack.Vault.KeyEpoch())
	scheme := "http"
	if tlsOn {
		scheme = "https"
		info := tlsSrv.Info()
		fmt.Fprintf(stdout, "  TLS: %s+ (AEAD only), certificate %s valid until %s, client certificates: %s\n",
			"1.2", handlers.LogSafe(info.Subject), info.NotAfter.UTC().Format("2006-01-02"), clientAuthText(tlsSrv.ClientAuth()))
	}
	fmt.Fprintf(stdout, "  Health check: %s://%s/healthz\n", scheme, addr)
	fmt.Fprintf(stdout, "  Auth: %s\n", authLine)
	fmt.Fprintln(stdout, "==============================================")

	var handler http.Handler = router
	if tlsOn {
		handler = server.HSTSHandler(router)
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      writeTimeout(cfg),
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	errCh := make(chan error, 1)
	if tlsOn {
		watchCtx, stopWatch := context.WithCancel(ctx)
		defer stopWatch()
		stopSig := watchSIGHUP(watchCtx, tlsSrv, cfg.tls.ReloadInterval)
		defer stopSig()
		go func() { errCh <- server.Serve(srv, ln, tlsSrv) }()
		logger.Printf("Starting HTTPS server on %s", addr)
	} else {
		// `systemctl reload` sends SIGHUP: with nothing to reload it must
		// not take the default action (terminate the process).
		stopIgnore := ignoreSIGHUP(ctx, logger)
		defer stopIgnore()
		go func() { errCh <- srv.Serve(ln) }()
		logger.Printf("Starting HTTP server on %s", addr)
	}
	if env.Ready != nil {
		env.Ready(addr)
	}

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			// Graceful drain timed out: force-close remaining connections.
			logger.Printf("graceful shutdown incomplete (%v); closing connections", err)
			_ = srv.Close()
		}
		return nil
	}
}
