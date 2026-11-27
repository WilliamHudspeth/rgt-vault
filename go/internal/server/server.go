package server

import (
	"errors"
	"net/http"

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
	// AgentTokens holds the agent bearer token (every /v1 route except
	// /v1/requests*). Required.
	AgentTokens *auth.TokenStore
	// OperatorTokens holds the operator token for /v1/requests*. Nil means
	// the approval endpoints accept the agent token (Python's behaviour
	// without --operator-token-file; an agent could then self-approve).
	OperatorTokens *auth.TokenStore
	// Broker serves /v1/requests*. It should be the vault's approval gate.
	// Nil means those endpoints answer 409.
	Broker *approval.Broker
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
// Identity is the shared agent bearer token plus the self-asserted "agent"
// field of each request, as in Python; per-agent identity is batch H1.
func New(cfg Config) (http.Handler, error) {
	if cfg.Vault == nil {
		return nil, errors.New("server: Config.Vault is required")
	}
	if cfg.AgentTokens == nil {
		return nil, errors.New("server: Config.AgentTokens is required")
	}
	h := &handlers.Handlers{
		Vault:        cfg.Vault,
		Actions:      cfg.Actions,
		Capabilities: cfg.Capabilities,
		Broker:       cfg.Broker,
	}
	mw := NewMiddleware(cfg.AgentTokens)
	mw.OperatorTokenStore = cfg.OperatorTokens
	mw.AllowedOrigins = cfg.AllowedOrigins
	if cfg.MaxBodyBytes > 0 {
		mw.MaxBodyBytes = cfg.MaxBodyBytes
	}
	return NewRouter(h, mw), nil
}
