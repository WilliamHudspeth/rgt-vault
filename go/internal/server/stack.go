package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	Vault        *vault.Vault
	Broker       *approval.Broker // nil unless RequireApproval
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
	if o.RequireApproval {
		opts := []approval.BrokerOption{}
		if o.ApprovalTimeout > 0 {
			opts = append(opts, approval.WithTimeout(o.ApprovalTimeout))
		}
		if o.TOTPSecretFile != "" {
			secret, err := readTrimmed(o.TOTPSecretFile, "TOTP secret file")
			if err != nil {
				return nil, err
			}
			v, err := totp.NewReplayGuardedVerifier(string(secret))
			if err != nil {
				return nil, fmt.Errorf("TOTP secret: %w", err)
			}
			opts = append(opts, approval.WithTOTPVerifier(v.Verify))
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
		verifier = hv
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
	if broker != nil {
		cfg.Approval = broker
	}
	v, err := vault.Open(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &Stack{Vault: v, Broker: broker, Actions: acts, Capabilities: caps, DBPath: dbPath}, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
