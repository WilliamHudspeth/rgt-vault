package hooks

import (
	"context"
	"sync"
	"time"

	"rgt-vault-server/internal/vault"
)

// OffHook is the default no-op hook with freeze support (python OffHook).
type OffHook struct{ *Base }

// NewOffHook returns an OffHook (id "off").
func NewOffHook() *OffHook { return &OffHook{Base: NewBase("off")} }

// Consult always allows with "hook disabled".
func (*OffHook) Consult(context.Context, vault.HookRequest) (vault.HookResponse, error) {
	return allow("hook disabled"), nil
}

// MaxLogConsultations bounds LogHook's in-memory record (Python's is
// unbounded); the oldest entries are dropped first.
const MaxLogConsultations = 10_000

// Consultation is one LogHook record. It never contains a token or payload.
type Consultation struct {
	Operation  string
	Agent      string
	Namespace  string
	Purpose    string
	SecretName *string
	Capability string
	RequestID  string
	TS         time.Time
}

// LogHook allows everything and records each consultation (python LogHook);
// useful for staging a hook before enforcing it.
type LogHook struct {
	*Base
	mu   sync.Mutex
	log  []Consultation
	now  func() time.Time
	maxN int
}

// NewLogHook returns a LogHook (id "log").
func NewLogHook() *LogHook {
	return &LogHook{Base: NewBase("log"), now: time.Now, maxN: MaxLogConsultations}
}

// Consult records the request and allows with "log mode: not enforced".
func (h *LogHook) Consult(_ context.Context, req vault.HookRequest) (vault.HookResponse, error) {
	c := Consultation{
		Operation: req.Operation, Agent: req.Agent, Namespace: req.Namespace, Purpose: req.Purpose,
		Capability: req.Capability, RequestID: req.RequestID, TS: h.now(),
	}
	if req.SecretName != nil {
		s := *req.SecretName
		c.SecretName = &s
	}
	h.mu.Lock()
	if len(h.log) >= h.maxN {
		h.log = append(h.log[:0], h.log[len(h.log)-h.maxN+1:]...)
	}
	h.log = append(h.log, c)
	h.mu.Unlock()
	return allow("log mode: not enforced"), nil
}

// Consultations returns a copy of the recorded consultations, oldest first.
func (h *LogHook) Consultations() []Consultation {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Consultation(nil), h.log...)
}
