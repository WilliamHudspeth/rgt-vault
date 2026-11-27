package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"rgt-vault-server/internal/actions"
	"rgt-vault-server/internal/approval"
	"rgt-vault-server/internal/capabilities"
	"rgt-vault-server/internal/captoken"
	"rgt-vault-server/internal/kdf"
	"rgt-vault-server/internal/providers"
	"rgt-vault-server/internal/server/handlers"
	"rgt-vault-server/internal/totp"
	"rgt-vault-server/internal/vault"
)

// DefaultDBPath is Python's --db default (expanded at use).
const DefaultDBPath = "~/.secure-vault/vault.db"

// Provider names accepted by StackOptions.Provider (python --provider).
const (
	ProviderKeyring  = "keyring"
	ProviderPlatform = "platform"
)

// StackOptions describe the vault the server runs on: the Go equivalent of
// `rgt-vault --db --policy --provider serve [--require-approval
// --totp-secret-file --approval-timeout --allow-private-network]`, plus
// HarnessKeyFile, which Python never wired (so its capability endpoint
// always failed closed, old-plan N2).
type StackOptions struct {
	// DBPath is the vault database; keychain.json lives next to it.
	// Empty means DefaultDBPath. A leading "~/" is expanded.
	DBPath string
	// PolicyFile is the ABAC policy YAML. Empty means no policy: every
	// request is denied (Python's default).
	PolicyFile string
	// Provider is "keyring" (default, as in Python) or "platform"
	// (DPAPI / macOS Keychain / TPM, from the environment). Ignored when
	// MasterProvider is set.
	Provider string
	// MasterProvider overrides Provider (tests, embedding).
	MasterProvider vault.MasterProvider

	// RequireApproval puts a live approval broker in front of every unseal.
	RequireApproval bool
	// RequireApprovalFor additionally makes set, rotate and/or revoke wait
	// for operator approval (--require-approval-for; default none). It
	// creates the broker even without RequireApproval, which then still
	// gates only these operations, not reads.
	RequireApprovalFor []approval.GatedOp
	// Notifier receives approval security events. Nil logs a warning line.
	Notifier approval.Notifier
	// ApprovalCodeAttempts / ApprovalOperatorFails / ApprovalLockout tune the
	// bad-TOTP-code caps (zero = approval.DefaultMaxCodeAttempts / ...Fails /
	// ...Lockout).
	ApprovalCodeAttempts  int
	ApprovalOperatorFails int
	ApprovalLockout       time.Duration
	// TOTPSecretFile is the base32 TOTP secret (rgt-vault enroll-2fa) that
	// approving a require_2fa secret needs. Optional.
	TOTPSecretFile string
	// ApprovalTimeout is how long a request waits before it is denied
	// (0 = approval.DefaultTimeout, 120 s).
	ApprovalTimeout time.Duration

	// HarnessKeyFile is the shared HMAC key the harness signs v2 capability
	// tokens with (file contents, surrounding whitespace trimmed). Empty
	// means /v1/capabilities/execute fails closed.
	HarnessKeyFile string

	// AllowPrivateNetwork lets the built-in HTTP actions reach loopback and
	// private addresses (python --allow-private-network; SSRF risk).
	AllowPrivateNetwork bool

	// RateLimit / RateWindow configure the vault's per-agent lease limiter
	// (zero = vault.DefaultRateLimit per vault.DefaultRateWindow).
	RateLimit  int
	RateWindow time.Duration

	// KDFParams for a NEW keychain (tests only; zero = Python's defaults).
	KDFParams kdf.Params
}

// Stack is an open vault and everything the server needs around it.
type Stack struct {
	Vault  *vault.Vault
	Broker *approval.Broker // nil unless RequireApproval / RequireApprovalFor
	// GatedOps and Notifier are passed on to server.Config.
	GatedOps     []approval.GatedOp
	Notifier     approval.Notifier
	Actions      *actions.Registry
	Capabilities *capabilities.Registry
	// DBPath is the resolved database path.
	DBPath string
}

// Close closes the vault.
func (s *Stack) Close() error { return s.Vault.Close() }

// ExpandHome expands a leading "~/" (or a bare "~") to the home directory.
func ExpandHome(p string) (string, error) {
	if p != "~" && !strings.HasPrefix(p, "~/") && !strings.HasPrefix(p, `~\`) {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("expand %q: %w", p, err)
	}
	return filepath.Join(home, p[1:]), nil
}

// NewProvider returns the named master-secret provider (python
// _build_provider).
func NewProvider(name string) (vault.MasterProvider, error) {
	switch name {
	case "", ProviderKeyring:
		return providers.NewKeyringProvider("", ""), nil
	case ProviderPlatform:
		return providers.NewPlatformProvider()
	default:
		return nil, fmt.Errorf("unknown provider %q: use 'keyring' or 'platform'", name)
	}
}

func readTrimmed(path, what string) ([]byte, error) {
	p, err := ExpandHome(path)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", what, err)
	}
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, fmt.Errorf("%s %s is empty", what, p)
	}
	return b, nil
}

// OpenStack opens the vault described by o, with the built-in actions and
// capabilities registered.
func OpenStack(ctx context.Context, o StackOptions) (*Stack, error) {
	dbPath, err := ExpandHome(firstNonEmpty(o.DBPath, DefaultDBPath))
	if err != nil {
		return nil, err
	}

	policyYAML := ""
	if o.PolicyFile != "" {
		p, err := ExpandHome(o.PolicyFile)
		if err != nil {
			return nil, err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read policy: %w", err)
		}
		policyYAML = string(b)
	}

	prov := o.MasterProvider
	if prov == nil {
		if prov, err = NewProvider(o.Provider); err != nil {
			return nil, err
		}
	}

	var broker *approval.Broker
	if o.RequireApproval || len(o.RequireApprovalFor) > 0 {
		opts := []approval.BrokerOption{approval.WithAttemptLimits(o.ApprovalCodeAttempts, o.ApprovalOperatorFails, o.ApprovalLockout)}
		if o.ApprovalTimeout > 0 {
			opts = append(opts, approval.WithTimeout(o.ApprovalTimeout))
		}
		if o.TOTPSecretFile != "" {
			secret, err := readTOTPSecret(o.TOTPSecretFile)
			if err != nil {
				return nil, err
			}
			// Always the replay-guarded verifier: a code is accepted once,
			// and a reuse is reported (audited and notified) as a replay.
			v, err := totp.NewReplayGuardedVerifier(string(secret))
			if err != nil {
				return nil, fmt.Errorf("TOTP secret: %w", err)
			}
			opts = append(opts, approval.WithTOTPChecker(func(code string) approval.CodeResult {
				switch v.VerifyResult(code) {
				case totp.ResultOK:
					return approval.CodeOK
				case totp.ResultReplay:
					return approval.CodeReplay
				}
				return approval.CodeInvalid
			}))
		}
		broker = approval.NewBroker(opts...)
	} else if o.TOTPSecretFile != "" {
		return nil, errors.New("a TOTP secret file only applies with RequireApproval")
	}

	var verifier captoken.TokenVerifier
	if o.HarnessKeyFile != "" {
		key, err := readTrimmed(o.HarnessKeyFile, "harness key file")
		if err != nil {
			return nil, err
		}
		hv, err := captoken.NewHMACTokenVerifier(key)
		if err != nil {
			return nil, fmt.Errorf("harness key: %w", err)
		}
		// Capability tokens are single-use by default: the guard remembers
		// each token id until the token expires (batch H2, RGT-338).
		verifier = captoken.NewReplayGuard(hv)
	}

	acts, err := actions.NewBuiltinRegistry(actions.Config{AllowPrivateNetwork: o.AllowPrivateNetwork})
	if err != nil {
		return nil, err
	}
	caps := capabilities.NewDefault(handlers.ActionBridge{Registry: acts})

	cfg := vault.Config{
		DBPath:        dbPath,
		Provider:      prov,
		PolicyYAML:    policyYAML,
		Capabilities:  caps,
		TokenVerifier: verifier,
		KDFParams:     o.KDFParams,
		RateLimit:     o.RateLimit,
		RateWindow:    o.RateWindow,
	}
	if broker != nil && o.RequireApproval {
		cfg.Approval = broker // reads; --require-approval-for alone gates only the listed operations
	}
	v, err := vault.Open(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &Stack{Vault: v, Broker: broker, GatedOps: o.RequireApprovalFor, Notifier: o.Notifier,
		Actions: acts, Capabilities: caps, DBPath: dbPath}, nil
}

// readTOTPSecret reads the TOTP secret file. On POSIX systems it refuses a
// file that group or others can read: the secret is the second factor, and a
// loose mode usually means it was copied or created carelessly. (Windows has
// no POSIX mode bits to check; protect the file with its ACL.)
func readTOTPSecret(path string) ([]byte, error) {
	p, err := ExpandHome(path)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("read TOTP secret file: %w", err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("TOTP secret file %s has mode %04o: it must not be accessible by group or others (chmod 600)", p, fi.Mode().Perm())
		}
	}
	return readTrimmed(path, "TOTP secret file")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
