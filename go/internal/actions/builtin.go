package actions

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/netguard"
)

// Defaults.
const (
	DefaultTimeout          = 15 * time.Second
	DefaultMaxResponseBytes = 1 << 20 // 1 MiB, as Python's _MAX_RESPONSE_BYTES
	DefaultMaxRequestBytes  = 1 << 20
	DefaultOpenAIBaseURL    = "https://api.openai.com"
)

// Config is the operator-level policy for the built-in HTTP actions. The zero
// value is the strictest: https only, public addresses only, no redirects.
type Config struct {
	// AllowPrivateNetwork is the --allow-private-network switch: loopback,
	// RFC1918, CGNAT and ULA targets become reachable. Link-local/metadata,
	// multicast and unspecified addresses never are.
	AllowPrivateNetwork bool
	// AllowInsecureHTTP permits http:// targets (the bearer token would travel
	// in clear text).
	AllowInsecureHTTP bool
	// HostAllowlist restricts targets per action: the key is an action name
	// (or "*" for every HTTP action without its own entry), the value a list of
	// "host", "host:port" or "*.suffix[:port]" entries. An action with no entry
	// is limited only by the address policy; an entry with an EMPTY list denies
	// every host (fail closed).
	HostAllowlist map[string][]string
	// HeaderAllowlist, when non-empty, limits which caller headers are accepted
	// (case-insensitive names).
	HeaderAllowlist []string
	// MaxRedirects is how many redirects are followed (0 = refuse; max 10).
	MaxRedirects int
	// Timeout bounds one upstream request (default 15 s).
	Timeout time.Duration
	// MaxResponseBytes caps the response body returned (default 1 MiB; the
	// rest is dropped and "truncated" is set).
	MaxResponseBytes int64
	// MaxRequestBytes caps a request body (default 1 MiB).
	MaxRequestBytes int64
	// RootCAs replaces the system trust pool. Verification stays on.
	RootCAs *x509.CertPool
	// Resolver and DialFunc are test seams below the guard (see netguard).
	Resolver netguard.Resolver
	DialFunc netguard.DialFunc
	// Logger receives action, host and status only; never the secret, headers,
	// bodies or paths. nil discards.
	Logger *slog.Logger
}

func (c *Config) defaults() {
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	if c.MaxResponseBytes <= 0 {
		c.MaxResponseBytes = DefaultMaxResponseBytes
	}
	if c.MaxRequestBytes <= 0 {
		c.MaxRequestBytes = DefaultMaxRequestBytes
	}
}

type builtins struct {
	cfg     Config
	log     *slog.Logger
	allowed map[string]struct{}
	eps     map[string]*endpoint
}

func newBuiltins(cfg Config) (*builtins, error) {
	cfg.defaults()
	b := &builtins{cfg: cfg, log: loggerOrDiscard(cfg.Logger), eps: map[string]*endpoint{}}
	if len(cfg.HeaderAllowlist) > 0 {
		b.allowed = map[string]struct{}{}
		for _, h := range cfg.HeaderAllowlist {
			b.allowed[strings.ToLower(strings.TrimSpace(h))] = struct{}{}
		}
	}
	for _, n := range []string{"openai_chat", "http_get_with_auth", "http_post_with_auth"} {
		ep, err := b.newEndpoint(n)
		if err != nil {
			return nil, err
		}
		b.eps[n] = ep
	}
	return b, nil
}

func (b *builtins) newEndpoint(name string) (*endpoint, error) {
	opts := []netguard.Option{
		netguard.WithAllowPrivate(b.cfg.AllowPrivateNetwork),
		netguard.WithAllowInsecureHTTP(b.cfg.AllowInsecureHTTP),
		netguard.WithMaxRedirects(b.cfg.MaxRedirects),
		netguard.WithTimeout(b.cfg.Timeout),
	}
	// A present entry, even an empty one, restricts the action (an empty list
	// denies every host); only an absent entry falls through to "*".
	list, ok := b.cfg.HostAllowlist[name]
	if !ok {
		list, ok = b.cfg.HostAllowlist["*"]
	}
	if ok {
		opts = append(opts, netguard.WithAllowedHosts(list...))
	}
	if b.cfg.RootCAs != nil {
		opts = append(opts, netguard.WithRootCAs(b.cfg.RootCAs))
	}
	if b.cfg.Resolver != nil {
		opts = append(opts, netguard.WithResolver(b.cfg.Resolver))
	}
	if b.cfg.DialFunc != nil {
		opts = append(opts, netguard.WithDialFunc(b.cfg.DialFunc))
	}
	g, err := netguard.NewGuard(opts...)
	if err != nil {
		return nil, fmt.Errorf("actions: %s: %w", name, err)
	}
	return &endpoint{name: name, guard: g, client: g.Client()}, nil
}

// NewBuiltinRegistry returns a registry holding the four built-in actions.
func NewBuiltinRegistry(cfg Config) (*Registry, error) {
	r := NewRegistry(cfg.Logger)
	if err := RegisterBuiltins(r, cfg); err != nil {
		return nil, err
	}
	return r, nil
}

// RegisterBuiltins registers openai_chat, http_get_with_auth,
// http_post_with_auth and echo (in Python's order).
func RegisterBuiltins(r *Registry, cfg Config) error {
	b, err := newBuiltins(cfg)
	if err != nil {
		return err
	}
	specs := []Spec{
		{
			Name: "openai_chat",
			Description: "POST to an OpenAI-compatible /v1/chat/completions endpoint. " +
				"The leased secret is sent as a Bearer token. Returns the " +
				"upstream response (status, headers, body_text).",
			ParamsSchema: []string{"model", "messages", "base_url", "max_tokens", "temperature"},
			Fn:           b.openaiChat,
		},
		{
			Name:         "http_get_with_auth",
			Description:  "GET a URL with the leased secret as a Bearer token.",
			ParamsSchema: []string{"url", "headers"},
			Fn:           b.httpGet,
		},
		{
			Name:         "http_post_with_auth",
			Description:  "POST to a URL with the leased secret as a Bearer token.",
			ParamsSchema: []string{"url", "body", "headers"},
			Fn:           b.httpPost,
		},
		{
			Name: "echo",
			Description: "Diagnostic. Returns a fixed object confirming the lease " +
				"worked; the secret is NEVER included in the response.",
			ParamsSchema: []string{"message"},
			Fn:           echo,
		},
	}
	for _, s := range specs {
		if err := r.Register(s); err != nil {
			return err
		}
	}
	return nil
}

func echo(_ context.Context, secret []byte, params map[string]any) (map[string]any, error) {
	// Deliberately does NOT return the secret: this exists so an operator can
	// confirm the lease + auth + policy path end to end.
	msg, ok := params["message"]
	if !ok {
		msg = "lease ok; secret NOT returned"
	}
	return map[string]any{
		"ok":            true,
		"leaked_secret": false,
		"secret_len":    len(secret),
		"message":       msg,
	}, nil
}

func (b *builtins) requestHeaders(params map[string]any) (map[string]string, error) {
	return ValidateHeaders(params["headers"], b.allowed)
}

// planGet validates params and builds the request (no network, no secret).
func (b *builtins) planGet(params map[string]any) (*outReq, error) {
	url, ok := params["url"].(string)
	if !ok || url == "" {
		return nil, execErr("'url' is required and must be a string.")
	}
	h, err := b.requestHeaders(params)
	if err != nil {
		return nil, err
	}
	if _, err := b.eps["http_get_with_auth"].guard.CheckURL(url); err != nil {
		return nil, guardOrGeneric(err)
	}
	return &outReq{method: http.MethodGet, url: url, headers: h}, nil
}

func (b *builtins) planPost(params map[string]any) (*outReq, error) {
	url, ok := params["url"].(string)
	if !ok || url == "" {
		return nil, execErr("'url' is required and must be a string.")
	}
	h, err := b.requestHeaders(params)
	if err != nil {
		return nil, err
	}
	var body []byte
	switch v := params["body"].(type) {
	case nil:
	case string:
		body = []byte(v)
	default:
		body, err = json.Marshal(v)
		if err != nil {
			return nil, execErr("'body' is not JSON-serialisable.")
		}
	}
	if int64(len(body)) > b.cfg.MaxRequestBytes {
		return nil, execErr("Request body exceeds %d bytes.", b.cfg.MaxRequestBytes)
	}
	if _, err := b.eps["http_post_with_auth"].guard.CheckURL(url); err != nil {
		return nil, guardOrGeneric(err)
	}
	if len(body) > 0 {
		if _, has := h["Content-Type"]; !has {
			h["Content-Type"] = "application/json"
		}
	}
	return &outReq{method: http.MethodPost, url: url, headers: h, body: body}, nil
}

func guardOrGeneric(err error) error {
	if m := mapGuard(err); m != nil {
		return m
	}
	return execErr("'url' is not acceptable.")
}

func (b *builtins) httpGet(ctx context.Context, secret []byte, params map[string]any) (map[string]any, error) {
	r, err := b.planGet(params)
	if err != nil {
		return nil, err
	}
	return b.eps["http_get_with_auth"].send(ctx, &b.cfg, b.log, r, secret)
}

func (b *builtins) httpPost(ctx context.Context, secret []byte, params map[string]any) (map[string]any, error) {
	r, err := b.planPost(params)
	if err != nil {
		return nil, err
	}
	return b.eps["http_post_with_auth"].send(ctx, &b.cfg, b.log, r, secret)
}

type chatBody struct {
	Model       string   `json:"model"`
	Messages    []any    `json:"messages"`
	MaxTokens   *int64   `json:"max_tokens,omitempty"`
	Temperature *float64 `json:"temperature,omitempty"`
}

func (b *builtins) planOpenAI(params map[string]any) (*outReq, error) {
	model, _ := params["model"].(string)
	if model == "" {
		return nil, execErr("'model' is required and must be a string.")
	}
	messages, ok := params["messages"].([]any)
	if !ok {
		return nil, execErr("'messages' is required and must be a list.")
	}
	if len(messages) == 0 {
		return nil, execErr("'messages' must not be empty.")
	}
	for i, m := range messages {
		msg, ok := m.(map[string]any)
		if !ok {
			return nil, execErr("'messages[%d]' must be a JSON object with 'role' and 'content' keys.", i)
		}
		if role, _ := msg["role"].(string); role == "" {
			return nil, execErr("'messages[%d].role' is required and must be a non-empty string.", i)
		}
		switch msg["content"].(type) {
		case string, []any:
		default:
			return nil, execErr("'messages[%d].content' is required and must be a string or list.", i)
		}
	}
	body := chatBody{Model: model, Messages: messages}
	if v, present := params["max_tokens"]; present && v != nil {
		n, ok := asInt64(v)
		if !ok {
			return nil, execErr("'max_tokens' must be an integer if provided.")
		}
		if n <= 0 || n > 1_000_000 {
			return nil, execErr("'max_tokens' must be an integer between 1 and 1,000,000.")
		}
		body.MaxTokens = &n
	}
	if v, present := params["temperature"]; present && v != nil {
		f, ok := asFloat64(v)
		if !ok {
			return nil, execErr("'temperature' must be a number if provided.")
		}
		if f < 0.0 || f > 2.0 || math.IsNaN(f) {
			return nil, execErr("'temperature' must be between 0.0 and 2.0 inclusive.")
		}
		body.Temperature = &f
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, execErr("'messages' is not JSON-serialisable.")
	}
	base := DefaultOpenAIBaseURL
	if v, present := params["base_url"]; present {
		s, ok := v.(string)
		if !ok {
			return nil, execErr("'base_url' must be a string if provided.")
		}
		base = s
	}
	ep := b.eps["openai_chat"]
	u, err := ep.guard.CheckURL(base)
	if err != nil {
		return nil, guardOrGeneric(err)
	}
	if strings.ContainsAny(base, "?#") || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return nil, execErr("'base_url' must not contain a query or fragment.")
	}
	full := strings.TrimRight(base, "/") + "/v1/chat/completions"
	return &outReq{
		method:  http.MethodPost,
		url:     full,
		headers: map[string]string{"Content-Type": "application/json"},
		body:    raw,
	}, nil
}

func (b *builtins) openaiChat(ctx context.Context, secret []byte, params map[string]any) (map[string]any, error) {
	r, err := b.planOpenAI(params)
	if err != nil {
		return nil, err
	}
	return b.eps["openai_chat"].send(ctx, &b.cfg, b.log, r, secret)
}
