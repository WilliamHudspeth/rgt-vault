package hooks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"rgt-vault-server/internal/approval"
	"rgt-vault-server/internal/netguard"
)

// maxEventsInFlight bounds concurrent webhook deliveries of ordinary events;
// further ones are dropped (and logged) rather than queued without limit.
// maxCriticalInFlight is a SEPARATE budget for events that must not be lost
// to flood noise (approval.EventKind.Critical): a lockout alert is delivered
// even while the ordinary slots are all busy with a slow receiver.
const (
	maxEventsInFlight   = 8
	maxCriticalInFlight = 4
)

// EventWebhook is an approval.Notifier that POSTs each security event to a
// URL as JSON (bad / replayed TOTP codes, lockouts, self-approval attempts).
//
// Delivery is best effort and never blocks the request that raised the
// event: it runs in a goroutine, with a timeout, no redirects, no proxy, and
// the same dial-time guard as WebhookHook (netguard: link-local and cloud
// metadata addresses always refused; non-loopback hosts only with
// allowRemote). A failed delivery is logged without the URL (it may embed a
// credential); the event itself is always audited and logged by the caller,
// so the webhook is an extra channel, not the record.
//
// The body carries the event kind, request id, agent, token id and a short
// description; never a TOTP code, a token or a secret value.
type EventWebhook struct {
	url     string
	client  *http.Client
	timeout time.Duration
	sem     chan struct{}
	critSem chan struct{}
	logf    func(format string, args ...any)
	// done is signalled after each delivery attempt (tests).
	done chan struct{}
}

var _ approval.Notifier = (*EventWebhook)(nil)

// EventWebhookOption configures NewEventWebhook.
type EventWebhookOption func(*EventWebhook)

// WithEventTimeout sets the delivery timeout (default DefaultWebhookTimeout).
func WithEventTimeout(d time.Duration) EventWebhookOption {
	return func(w *EventWebhook) {
		if d > 0 {
			w.timeout = d
		}
	}
}

// NewEventWebhook returns a notifier posting to rawURL (absolute http(s)).
// allowRemote lets it reach non-loopback hosts.
func NewEventWebhook(rawURL string, allowRemote bool, opts ...EventWebhookOption) (*EventWebhook, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("security webhook url must be an absolute http(s) URL")
	}
	w := &EventWebhook{url: rawURL, timeout: DefaultWebhookTimeout, sem: make(chan struct{}, maxEventsInFlight), critSem: make(chan struct{}, maxCriticalInFlight), logf: log.Printf}
	for _, o := range opts {
		o(w)
	}
	dialer := netguard.NewDialer(allowRemote)
	w.client = &http.Client{
		Timeout:       w.timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   w.timeout,
			ResponseHeaderTimeout: w.timeout,
			MaxIdleConns:          2,
			IdleConnTimeout:       30 * time.Second,
		},
	}
	return w, nil
}

type eventBody struct {
	Event     string `json:"event"`
	RequestID string `json:"request_id,omitempty"`
	Agent     string `json:"agent,omitempty"`
	Operator  string `json:"operator,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Time      string `json:"time"`
}

// Notify implements approval.Notifier. It returns immediately.
func (w *EventWebhook) Notify(_ context.Context, e approval.Event) {
	sem := w.sem
	if e.Kind.Critical() {
		sem = w.critSem
	}
	select {
	case sem <- struct{}{}:
	default:
		w.logf("WARNING: security webhook busy, event %s dropped (it is still in the audit log)", string(e.Kind))
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	body, err := json.Marshal(eventBody{
		Event: string(e.Kind), RequestID: e.RequestID, Agent: e.Agent, Operator: e.Operator,
		Detail: e.Detail, Time: e.Time.UTC().Format(time.RFC3339),
	})
	if err != nil {
		<-sem
		return
	}
	go func() {
		defer func() {
			<-sem
			if w.done != nil {
				w.done <- struct{}{}
			}
		}()
		// Detached from the request: a client hanging up must not cancel the alert.
		ctx, cancel := context.WithTimeout(context.Background(), w.timeout)
		defer cancel()
		if err := w.send(ctx, e.Kind, body); err != nil {
			w.logf("WARNING: security webhook delivery of %s failed: %v", string(e.Kind), err)
		}
	}()
}

// Deliver posts one event and waits for the answer (the CLI uses it: the
// process exits right after). The error never contains the URL.
func (w *EventWebhook) Deliver(ctx context.Context, e approval.Event) error {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	body, err := json.Marshal(eventBody{
		Event: string(e.Kind), RequestID: e.RequestID, Agent: e.Agent, Operator: e.Operator,
		Detail: e.Detail, Time: e.Time.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	return w.send(ctx, e.Kind, body)
}

func (w *EventWebhook) send(ctx context.Context, _ approval.EventKind, body []byte) error {
	rq, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return errors.New("bad request")
	}
	rq.Header.Set("Content-Type", "application/json")
	resp, err := w.client.Do(rq)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the URL may carry a credential
		}
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
