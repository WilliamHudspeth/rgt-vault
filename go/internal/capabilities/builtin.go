package capabilities

import (
	"context"
	"errors"

	"rgt-vault-server/internal/hooks/pyfmt"
	"rgt-vault-server/internal/vault"
)

// Built-in capability names.
const (
	EchoCapability = "secrets.echo"
	UseCapability  = "secrets.use"
)

var (
	// ErrActionNotFound is Python's ActionNotFoundError (HTTP 404).
	ErrActionNotFound = errors.New("capabilities: action not found")
	// ErrActionExecution is Python's ActionExecutionError (HTTP 500).
	ErrActionExecution = errors.New("capabilities: action execution failed")
)

// Action is one outbound action secrets.use can run against a leased
// secret (python server/actions.py ActionSpec). The real actions are
// provided by batch G8b; this package only defines the seam.
type Action interface {
	// ValidateParams checks the action parameters before any secret is
	// leased.
	ValidateParams(params map[string]any) error
	// Run performs the action. secret is wiped when Run returns: it must
	// not be retained, and the result must not contain it.
	Run(ctx context.Context, secret []byte, params map[string]any) (any, error)
}

// ActionRegistry resolves action names for secrets.use.
type ActionRegistry interface {
	// Action returns the named action or an error matching
	// ErrActionNotFound.
	Action(name string) (Action, error)
}

// ActionNotFound returns Python's ActionNotFoundError for name, given the
// registered names (for ActionRegistry implementations).
func ActionNotFound(name string, registered []string) error {
	return newError("ActionNotFoundError", nil, []error{ErrActionNotFound},
		"Unknown action '%s'. Registered: %s", name, pyfmt.SortedStringsRepr(registered))
}

func actionErr(cause error, format string, a ...any) error {
	return newError("ActionExecutionError", cause, []error{ErrActionExecution}, format, a...)
}

// RegisterBuiltins registers secrets.echo and secrets.use (python
// register_builtin_capabilities). Calling it twice on one registry fails
// (names cannot be re-registered).
func RegisterBuiltins(r *Registry, actions ActionRegistry) error {
	if err := r.Register(Spec{
		Name:        EchoCapability,
		Description: "Diagnostic capability. Returns a fixed shape; never includes secrets.",
		Versions:    []int{1},
		Schema:      ParamList{"message"},
		Handler:     echo,
	}); err != nil {
		return err
	}
	return r.Register(Spec{
		Name: UseCapability,
		Description: "Lease a stored secret and run a registered v0.2 action against it. " +
			"Bridges legacy server-side actions into the capability model.",
		Versions: []int{1},
		Schema:   ParamList{"secret_name", "namespace", "action", "params"},
		Handler:  useHandler(actions),
	})
}

// echo proves the path end to end; it never includes secrets.
func echo(_ context.Context, payload map[string]any, c vault.CapabilityContext) (any, error) {
	msg := ""
	if m, ok := payload["message"]; ok {
		msg = pyfmt.Str(m)
	}
	return map[string]any{
		"ok":         true,
		"capability": c.Capability,
		"agent_id":   c.AgentID,
		"token_id":   c.TokenID,
		"message":    msg,
	}, nil
}

// useHandler leases a secret and runs an action against it; the secret
// never leaves the vault process.
func useHandler(actions ActionRegistry) Handler {
	return func(ctx context.Context, payload map[string]any, c vault.CapabilityContext) (any, error) {
		secretName, _ := payload["secret_name"].(string)
		if secretName == "" {
			return nil, actionErr(nil, "'secret_name' is required")
		}
		actionName, _ := payload["action"].(string)
		if actionName == "" {
			return nil, actionErr(nil, "'action' is required")
		}
		namespace := vault.DefaultNamespace
		if ns, ok := payload["namespace"]; ok {
			s, isStr := ns.(string)
			if !isStr {
				return nil, newError("ValidationError", nil, []error{vault.ErrValidation},
					"'namespace' must be a string. Got %s.", pyTypeName(ns))
			}
			namespace = s
		}
		params := map[string]any{}
		if p, ok := payload["params"]; ok && pyTruthy(p) {
			m, isMap := p.(map[string]any)
			if !isMap {
				return nil, actionErr(nil, "'params' must be a dict")
			}
			params = m
		}
		if actions == nil {
			return nil, ActionNotFound(actionName, nil)
		}
		act, err := actions.Action(actionName)
		if err != nil {
			return nil, err
		}
		if err := act.ValidateParams(params); err != nil {
			return nil, err
		}
		if c.Vault == nil {
			return nil, actionErr(nil, "secrets.use requires a vault")
		}
		var result any
		err = c.Vault.Lease(ctx, vault.LeaseRequest{
			Name:      secretName,
			Namespace: namespace,
			Agent:     c.AgentID,
			Purpose:   "capability:" + c.Capability,
		}, func(secret []byte) error {
			r, rerr := act.Run(ctx, secret, params)
			if rerr != nil {
				return actionErr(rerr, "action %s failed; see server logs for details", pyfmt.Repr(actionName))
			}
			result = r
			return nil
		})
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "action": actionName, "result": result}, nil
	}
}

// pyTruthy is Python truthiness for a JSON value (`x or {}`).
func pyTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case map[string]any:
		return len(x) > 0
	case []any:
		return len(x) > 0
	case float64:
		return x != 0
	case int:
		return x != 0
	}
	if s, ok := v.(interface{ String() string }); ok { // json.Number
		switch s.String() {
		case "0", "-0", "0.0", "-0.0":
			return false
		}
	}
	return true
}

func pyTypeName(v any) string {
	switch v.(type) {
	case nil:
		return "NoneType"
	case bool:
		return "bool"
	case float64:
		return "float"
	case int, int64:
		return "int"
	case map[string]any:
		return "dict"
	case []any:
		return "list"
	}
	return "object"
}
