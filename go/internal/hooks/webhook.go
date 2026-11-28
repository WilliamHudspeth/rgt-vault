package hooks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/hooks/pyfmt"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/netguard"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/vault"
)

// DefaultWebhookTimeout is WebhookHook's default timeout_seconds.
const DefaultWebhookTimeout = 5 * time.Second

// maxWebhookResponse is the response read cap (Python resp.read(64 KiB)).
const maxWebhookResponse = 64 * 1024

// WebhookHook POSTs a JSON envelope describing each operation to a harness
// URL and honours its {"decision": "allow"|"deny"|"freeze", "reason": ...}
// answer (python WebhookHook). Anything else (unreachable, HTTP error,
// non-JSON, unknown decision) is a deny.
//
// Unlike Python's urllib, redirects are not followed, only 2xx answers are
// honoured, and the client dials through netguard: link-local and
// cloud-metadata addresses are always refused, non-loopback hosts are
// refused unless WithAllowRemote(true), and HTTP(S)_PROXY is ignored (a
// proxy would hide the real destination from the dial-time check).
type WebhookHook struct {
	*Base
	url         string
	timeout     time.Duration
	bearer      string
	allowRemote bool
	client      *http.Client
}

// WebhookOption configures NewWebhookHook.
type WebhookOption func(*WebhookHook)

// WithTimeout sets the request timeout (default 5s; <= 0 keeps the default).
func WithTimeout(d time.Duration) WebhookOption {
	return func(h *WebhookHook) {
		if d > 0 {
			h.timeout = d
		}
	}
}

// WithBearerToken sends "Authorization: Bearer <token>".
func WithBearerToken(token string) WebhookOption { return func(h *WebhookHook) { h.bearer = token } }

// WithAllowRemote lets the hook reach non-loopback hosts (link-local and
// metadata addresses stay forbidden).
func WithAllowRemote(allow bool) WebhookOption { return func(h *WebhookHook) { h.allowRemote = allow } }

// NewWebhookHook returns a hook calling rawURL (http or https).
func NewWebhookHook(rawURL string, opts ...WebhookOption) (*WebhookHook, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, validationErr("webhook hook url must be an absolute http(s) URL")
	}
	// The hook id goes into every audit row and denial message, so it is
	// only scheme://host[:port]. Everything else may carry a credential:
	// userinfo (a password, or a token used as the user name), the query,
	// the fragment, and the path (Slack/Teams-style webhook URLs embed
	// their secret there). Python used the full URL.
	idURL := url.URL{Scheme: u.Scheme, Host: u.Host}
	h := &WebhookHook{
		Base:    NewBase("webhook:" + idURL.String()),
		url:     rawURL,
		timeout: DefaultWebhookTimeout,
	}
	for _, o := range opts {
		o(h)
	}
	dialer := netguard.NewDialer(h.allowRemote)
	h.client = &http.Client{
		Timeout: h.timeout,
		// Never follow redirects: a redirect could pivot the request (and
		// the bearer token) to another host or scheme.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   h.timeout,
			ResponseHeaderTimeout: h.timeout,
			MaxIdleConns:          4,
			IdleConnTimeout:       30 * time.Second,
			ForceAttemptHTTP2:     true,
		},
	}
	return h, nil
}

// legacyBody is the wire envelope on the secret-access path; field order is
// Python's.
type legacyBody struct {
	Operation  string  `json:"operation"`
	Agent      string  `json:"agent"`
	Namespace  string  `json:"namespace"`
	Purpose    string  `json:"purpose"`
	SecretName *string `json:"secret_name"`
	RequestID  string  `json:"request_id"`
}

// capabilityBody adds the capability fields.
type capabilityBody struct {
	legacyBody
	Capability        string `json:"capability"`
	CapabilityVersion int    `json:"capability_version"`
	Payload           any    `json:"payload"`
	TokenMetadata     any    `json:"token_metadata"`
}

// Consult POSTs the envelope and maps the answer.
func (h *WebhookHook) Consult(ctx context.Context, req vault.HookRequest) (vault.HookResponse, error) {
	base := legacyBody{
		Operation: req.Operation, Agent: req.Agent, Namespace: req.Namespace,
		Purpose: req.Purpose, SecretName: req.SecretName, RequestID: req.RequestID,
	}
	var body any = base
	if req.IsCapability() {
		body = capabilityBody{
			legacyBody: base, Capability: req.Capability, CapabilityVersion: req.CapabilityVersion,
			Payload: req.Payload, TokenMetadata: req.TokenMetadata,
		}
	}
	data, err := json.Marshal(body)
	if err != nil {
		return deny(fmt.Sprintf("hook call failed: %v", err)), nil
	}
	rq, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(data))
	if err != nil {
		return deny(fmt.Sprintf("hook call failed: %v", err)), nil
	}
	rq.Header.Set("Content-Type", "application/json")
	if h.bearer != "" {
		rq.Header.Set("Authorization", "Bearer "+h.bearer)
	}
	resp, err := h.client.Do(rq)
	if err != nil {
		// Report the cause without the URL (it may carry credentials).
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return deny(fmt.Sprintf("hook URL unreachable: %v", err)), nil
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// urllib raises HTTPError (a URLError) whose reason is the status
		// phrase. Redirects are not followed, so a 3xx is a deny too.
		return deny("hook URL unreachable: " + http.StatusText(resp.StatusCode)), nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxWebhookResponse))
	if err != nil {
		return deny(fmt.Sprintf("hook URL unreachable: %v", err)), nil
	}
	var parsed any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&parsed); err != nil {
		return deny("hook response not valid JSON"), nil
	}
	if _, err := dec.Token(); err != io.EOF {
		return deny("hook response not valid JSON"), nil // trailing data
	}
	obj, ok := parsed.(map[string]any)
	if !ok {
		// Python: parsed.get raises AttributeError -> pre_op_check deny.
		return vault.HookResponse{}, fmt.Errorf("hook response is a JSON %s, not an object", jsonKind(parsed))
	}
	decision := vault.HookDeny
	if d, ok := obj["decision"]; ok {
		switch strings.ToLower(pyfmt.Str(d)) {
		case "allow":
			decision = vault.HookAllow
		case "freeze":
			decision = vault.HookFreeze
		}
	}
	reason := ""
	if r, ok := obj["reason"]; ok {
		reason = pyfmt.Str(r)
	}
	extra := map[string]any{}
	for k, v := range obj {
		if k != "decision" && k != "reason" {
			extra[k] = v
		}
	}
	return vault.HookResponse{Decision: decision, Reason: reason, Extra: extra}, nil
}

func jsonKind(v any) string {
	switch v.(type) {
	case []any:
		return "array"
	case string:
		return "string"
	case nil:
		return "null"
	case bool:
		return "boolean"
	default:
		return "number"
	}
}
