package actions

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
)

// Func is an action body. secret is owned by the caller and must not be
// retained or logged. The returned map must be JSON-serialisable.
type Func func(ctx context.Context, secret []byte, params map[string]any) (map[string]any, error)

// Spec describes one registered action.
type Spec struct {
	Name         string
	Description  string
	ParamsSchema []string // the only param keys the action accepts
	Fn           Func
}

// ValidateParams mirrors ActionSpec.validate_params: params must be present
// (nil is treated as empty) and contain no key outside ParamsSchema.
func (s Spec) ValidateParams(params map[string]any) error {
	allowed := make(map[string]struct{}, len(s.ParamsSchema))
	for _, k := range s.ParamsSchema {
		allowed[k] = struct{}{}
	}
	var unknown []string
	for k := range params {
		if _, ok := allowed[k]; !ok {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		schema := append([]string(nil), s.ParamsSchema...)
		sort.Strings(schema)
		return execErr("Action '%s' got unknown param(s): %s. Allowed: %s", s.Name, pyList(unknown), pyList(schema))
	}
	return nil
}

func pyList(xs []string) string {
	out := "["
	for i, x := range xs {
		if i > 0 {
			out += ", "
		}
		out += "'" + x + "'"
	}
	return out + "]"
}

// Registry is a name -> Spec map. It is safe for concurrent use.
type Registry struct {
	mu     sync.RWMutex
	order  []string
	byName map[string]Spec
	log    *slog.Logger
}

// NewRegistry returns an empty registry. log may be nil (discard).
func NewRegistry(log *slog.Logger) *Registry {
	return &Registry{byName: map[string]Spec{}, log: loggerOrDiscard(log)}
}

// Register adds spec; duplicate or empty names are an error.
func (r *Registry) Register(spec Spec) error {
	if spec.Name == "" {
		return fmt.Errorf("action name must be a non-empty string")
	}
	if spec.Fn == nil {
		return fmt.Errorf("action %q has no function", spec.Name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.byName[spec.Name]; dup {
		return fmt.Errorf("action %q is already registered", spec.Name)
	}
	r.byName[spec.Name] = spec
	r.order = append(r.order, spec.Name)
	return nil
}

// Get returns the spec or an ErrActionNotFound error listing registered names.
func (r *Registry) Get(name string) (Spec, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.byName[name]
	if !ok {
		names := append([]string(nil), r.order...)
		sort.Strings(names)
		return Spec{}, notFound("Unknown action '%s'. Registered: %s", name, pyList(names))
	}
	return s, nil
}

// List returns the specs in registration order.
func (r *Registry) List() []Spec {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Spec, 0, len(r.order))
	for _, n := range r.order {
		out = append(out, r.byName[n])
	}
	return out
}

// Execute looks the action up, validates params, runs it, and converts any
// non-*Error failure or panic into a fixed message: raw error text can embed
// request headers, so it is never returned to the caller (Python's P0-2 rule).
func (r *Registry) Execute(ctx context.Context, name string, secret []byte, params map[string]any) (out map[string]any, err error) {
	spec, err := r.Get(name)
	if err != nil {
		return nil, err
	}
	if err := spec.ValidateParams(params); err != nil {
		return nil, err
	}
	defer func() {
		if rec := recover(); rec != nil {
			// The panic value is deliberately not logged or returned.
			r.log.Error("action panicked; details suppressed", "action", name)
			out, err = nil, execErr("Action '%s' failed; see server logs for details.", name)
		}
	}()
	out, err = spec.Fn(ctx, secret, params)
	if err != nil {
		var ae *Error
		if asError(err, &ae) {
			return nil, ae // not err: a wrapper around it could carry other text
		}
		r.log.Error("action failed; details suppressed", "action", name)
		return nil, execErr("Action '%s' failed; see server logs for details.", name)
	}
	return out, nil
}
