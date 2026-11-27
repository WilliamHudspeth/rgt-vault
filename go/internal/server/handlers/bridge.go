package handlers

import (
	"context"
	"errors"

	"rgt-vault-server/internal/actions"
	"rgt-vault-server/internal/capabilities"
)

// ActionBridge adapts the built-in action registry (internal/actions) to
// the capabilities.ActionRegistry seam, so the secrets.use capability runs
// the same actions as POST /v1/secrets/{ns}/{name}/use.
type ActionBridge struct{ Registry *actions.Registry }

var _ capabilities.ActionRegistry = ActionBridge{}

// Action implements capabilities.ActionRegistry. An unknown name is
// Python's ActionNotFoundError listing the registered names.
func (b ActionBridge) Action(name string) (capabilities.Action, error) {
	if b.Registry == nil {
		return nil, capabilities.ActionNotFound(name, nil)
	}
	spec, err := b.Registry.Get(name)
	if err != nil {
		if errors.Is(err, actions.ErrActionNotFound) {
			var names []string
			for _, s := range b.Registry.List() {
				names = append(names, s.Name)
			}
			return nil, capabilities.ActionNotFound(name, names)
		}
		return nil, err
	}
	return bridgedAction{reg: b.Registry, spec: spec}, nil
}

type bridgedAction struct {
	reg  *actions.Registry
	spec actions.Spec
}

func (a bridgedAction) ValidateParams(params map[string]any) error {
	return a.spec.ValidateParams(params)
}

// Run goes through Registry.Execute, which masks unexpected errors and
// panics so an action's raw error text never reaches the caller.
func (a bridgedAction) Run(ctx context.Context, secret []byte, params map[string]any) (any, error) {
	out, err := a.reg.Execute(ctx, a.spec.Name, secret, params)
	if err != nil {
		return nil, err
	}
	return out, nil
}
