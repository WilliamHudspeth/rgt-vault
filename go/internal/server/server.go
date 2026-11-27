package server

import (
	"errors"
	"net/http"
	"time"

	"rgt-vault-server/internal/actions"
	"rgt-vault-server/internal/approval"
	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/capabilities"
	"rgt-vault-server/internal/server/handlers"
	"rgt-vault-server/internal/vault"
)

// Config configures New.
type Config struct {
	// Vault is the open vault the server fronts. Required. The server does
	// not close it.
	Vault *vault.Vault
	// Tokens is the per-agent token store (batch H1): every token maps to
	// one agent_id and a scope set, and the ABAC subject of a request is
	// the token's agent. Exactly one of Tokens and AgentTokens is required.
	Tokens *auth.Store
	// AgentTokens is the DEPRECATED legacy shared bearer token file
	// (--legacy-shared-token): every caller holds the same token and the
	// subject is the self-asserted "agent" field, as in Python.
	AgentTokens *auth.TokenStore
	// OperatorTokens is the legacy operator token for /v1/requests* (legacy
	// mode only). Nil means the approval endpoints accept the agent token
	// (Python's behaviour without --operator-token-file; an agent could
	// then self-approve).
	OperatorTokens *auth.TokenStore
	// LegacyPrivilegedRoutes (legacy mode only) lets the shared token reach
	// POST .../lease, /v1/rotate and /v1/audit*, as before H1. Default off:
	// those routes answer 403 in legacy mode.
	LegacyPrivilegedRoutes bool
	// AuthFailureLimit / AuthFailureWindow bound audited authentication
	// failures per source address (zero = DefaultAuthFailureLimit per
	// DefaultAuthFailureWindow); beyond them failures get 429.
	AuthFailureLimit  int
	AuthFailureWindow time.Duration
	// Broker serves /v1/requests*. It should be the vault's approval gate.
	// Nil means those endpoints answer 409.
	Broker *approval.Broker
	// GatedOps are the mutating operations (set, rotate, revoke) that wait
	// for operator approval before they run (--require-approval-for). Needs
	// a Broker.
	GatedOps []approval.GatedOp
	// Notifier receives approval security events (bad / replayed TOTP codes,
	// lockouts, self-approval attempts). Nil logs a warning line.
	Notifier approval.Notifier
	// Actions backs /use and /v1/actions. Nil means none registered.
	Actions *actions.Registry
	// Capabilities is what /v1/capabilities* lists. Nil means the vault's
	// registry when it is a *capabilities.Registry.
	Capabilities *capabilities.Registry
	// AllowedOrigins is the exact-match CORS allow-list (empty = CORS denied).
	AllowedOrigins []string
	// MaxBodyBytes caps request bodies (<= 0 = DefaultMaxBodyBytes).
	MaxBodyBytes int64
}

// New returns the HTTP handler of the rgt-vault server over cfg.Vault, with
// the full hardened middleware stack (loopback binding is the caller's job:
// see cmd/server).
//
// Identity is the per-agent token store (cfg.Tokens): the token decides the
// agent and the scopes. cfg.AgentTokens selects the deprecated legacy shared
// token instead (the caller warns about it).
func New(cfg Config) (http.Handler, error) {
	if cfg.Vault == nil {
		return nil, errors.New("server: Config.Vault is required")
	}
	if (cfg.Tokens == nil) == (cfg.AgentTokens == nil) {
		return nil, errors.New("server: exactly one of Config.Tokens and Config.AgentTokens (legacy) is required")
	}
	if cfg.Tokens != nil && cfg.OperatorTokens != nil {
		return nil, errors.New("server: Config.OperatorTokens applies to the legacy shared token only; use an operator-scoped token")
	}
	if cfg.Tokens != nil && cfg.LegacyPrivilegedRoutes {
		return nil, errors.New("server: Config.LegacyPrivilegedRoutes applies to the legacy shared token only")
	}
	if len(cfg.GatedOps) > 0 && cfg.Broker == nil {
		return nil, errors.New("server: Config.GatedOps needs an approval Broker")
	}
	h := &handlers.Handlers{
		Vault:        cfg.Vault,
		Actions:      cfg.Actions,
		Capabilities: cfg.Capabilities,
		Broker:       cfg.Broker,
		Notifier:     cfg.Notifier,
	}
	h.SetGatedOps(cfg.GatedOps)
	var mw *Middleware
	if cfg.Tokens != nil {
		mw = NewStoreMiddleware(cfg.Tokens)
	} else {
		mw = NewMiddleware(cfg.AgentTokens)
		mw.OperatorTokenStore = cfg.OperatorTokens
		mw.LegacyPrivilegedRoutes = cfg.LegacyPrivilegedRoutes
	}
	mw.Auditor = h
	mw.SetAuthFailureLimit(cfg.AuthFailureLimit, cfg.AuthFailureWindow)
	mw.AllowedOrigins = cfg.AllowedOrigins
	if cfg.MaxBodyBytes > 0 {
		mw.MaxBodyBytes = cfg.MaxBodyBytes
	}
	return NewRouter(h, mw), nil
}
