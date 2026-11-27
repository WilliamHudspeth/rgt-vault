// Package capabilities is the Go port of python/capabilities.py: the
// registry of named, versioned capabilities the vault executes on behalf of
// agents (vault.ExecuteCapability), payload schema validation, and the
// built-in capabilities secrets.echo and secrets.use.
//
// Registry implements vault.CapabilityRegistry; pass NewDefault(actions) as
// vault.Config.Capabilities. The attack surface is the set of registered
// names: re-registering a name is an error, never a silent replacement.
package capabilities

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"rgt-vault-server/internal/hooks/pyfmt"
	"rgt-vault-server/internal/vault"
)

// ErrRegistration is a programming error at registration time (Python
// ValueError from CapabilityRegistry.register).
var ErrRegistration = errors.New("capabilities: invalid registration")

// Error is this package's error type: Python's message plus the sentinels
// it matches (vault.ErrCapabilityNotFound, vault.ErrValidation, ...).
type Error struct {
	msg     string
	kinds   []error
	pyClass string
	cause   error
}

func (e *Error) Error() string { return e.msg }

// Is reports whether target is one of e's kinds.
func (e *Error) Is(target error) bool {
	for _, k := range e.kinds {
		if k == target {
			return true
		}
	}
	return false
}

// Unwrap returns the cause, if any.
func (e *Error) Unwrap() error { return e.cause }

// PyClass is the Python exception class name recorded in audit rows.
func (e *Error) PyClass() string { return e.pyClass }

func newError(class string, cause error, kinds []error, format string, a ...any) *Error {
	return &Error{msg: fmt.Sprintf(format, a...), kinds: kinds, pyClass: class, cause: cause}
}

// Handler runs a capability. It receives the validated payload and the
// context (never the raw token or a secret).
type Handler func(ctx context.Context, payload map[string]any, cctx vault.CapabilityContext) (any, error)

// Spec is one registered capability (python CapabilitySpec). It implements
// vault.CapabilitySpec.
type Spec struct {
	Name        string
	Description string
	// Versions are the supported capability_version values (sorted,
	// deduplicated; default [1]).
	Versions []int
	// Schema validates payloads; nil means "accept anything".
	Schema  Schema
	Handler Handler
}

var _ vault.CapabilitySpec = (*Spec)(nil)

// SupportsVersion reports whether version is supported.
func (s *Spec) SupportsVersion(version int) bool {
	for _, v := range s.Versions {
		if v == version {
			return true
		}
	}
	return false
}

// SupportedVersions returns a sorted copy of the supported versions.
func (s *Spec) SupportedVersions() []int { return append([]int(nil), s.Versions...) }

// ValidatePayload runs the schema (python validate_payload).
func (s *Spec) ValidatePayload(payload map[string]any) error {
	if s.Schema == nil {
		return nil
	}
	return s.Schema.Validate(s.Name, payload)
}

// Invoke runs the handler.
func (s *Spec) Invoke(ctx context.Context, payload map[string]any, cctx vault.CapabilityContext) (any, error) {
	return s.Handler(ctx, payload, cctx)
}

// Registry is the in-process capability registry (python
// CapabilityRegistry). It is safe for concurrent use.
type Registry struct {
	mu    sync.RWMutex
	specs map[string]*Spec
	order []string
}

var _ vault.CapabilityRegistry = (*Registry)(nil)

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{specs: map[string]*Spec{}} }

// NewDefault returns a registry with the built-in capabilities registered
// (what Python's VaultManager does with an empty registry). actions backs
// secrets.use and may be nil (every action is then unknown).
func NewDefault(actions ActionRegistry) *Registry {
	r := NewRegistry()
	if err := RegisterBuiltins(r, actions); err != nil {
		panic(err) // unreachable: a fresh registry has no names
	}
	return r
}

// Register adds a capability. An empty name, a nil handler, a version < 1
// or an already registered name is an ErrRegistration error.
func (r *Registry) Register(spec Spec) error {
	if spec.Name == "" {
		return newError("ValueError", nil, []error{ErrRegistration}, "capability name must be a non-empty string")
	}
	if spec.Handler == nil {
		return newError("ValueError", nil, []error{ErrRegistration}, "capability handler must be callable")
	}
	versions := spec.Versions
	if len(versions) == 0 {
		versions = []int{1}
	}
	set := map[int]bool{}
	for _, v := range versions {
		if v < 1 {
			return newError("ValueError", nil, []error{ErrRegistration}, "supported_versions must be positive ints")
		}
		set[v] = true
	}
	uniq := make([]int, 0, len(set))
	for v := range set {
		uniq = append(uniq, v)
	}
	sort.Ints(uniq)
	s := spec
	s.Versions = uniq
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.specs[s.Name]; dup {
		return newError("ValueError", nil, []error{ErrRegistration}, "capability %s is already registered", pyfmt.Repr(s.Name))
	}
	r.specs[s.Name] = &s
	r.order = append(r.order, s.Name)
	return nil
}

// Unregister removes a capability (tests; not exposed over HTTP).
func (r *Registry) Unregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.specs[name]; !ok {
		return
	}
	delete(r.specs, name)
	for i, n := range r.order {
		if n == name {
			r.order = append(r.order[:i:i], r.order[i+1:]...)
			break
		}
	}
}

// Get returns the spec or a vault.ErrCapabilityNotFound error with
// Python's message ("unknown capability 'x'. Registered: [...]").
func (r *Registry) Get(name string) (*Spec, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if s, ok := r.specs[name]; ok {
		return s, nil
	}
	return nil, newError("CapabilityNotFoundError", nil, []error{vault.ErrCapabilityNotFound},
		"unknown capability %s. Registered: %s", pyfmt.Repr(name), pyfmt.SortedStringsRepr(r.order))
}

// Lookup implements vault.CapabilityRegistry.
func (r *Registry) Lookup(name string) (vault.CapabilitySpec, error) {
	s, err := r.Get(name)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Has reports whether name is registered.
func (r *Registry) Has(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.specs[name]
	return ok
}

// List returns the registered specs in registration order.
func (r *Registry) List() []*Spec {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Spec, 0, len(r.order))
	for _, n := range r.order {
		out = append(out, r.specs[n])
	}
	return out
}

// CheckVersion returns a vault.ErrCapabilityVersion error if name does not
// support version (or the not-found error).
func (r *Registry) CheckVersion(name string, version int) error {
	s, err := r.Get(name)
	if err != nil {
		return err
	}
	if !s.SupportsVersion(version) {
		return newError("CapabilityVersionError", nil, []error{vault.ErrCapabilityVersion},
			"capability %s version %d is not supported; supported versions: %s",
			pyfmt.Repr(name), version, pyfmt.SortedIntsRepr(s.Versions))
	}
	return nil
}
