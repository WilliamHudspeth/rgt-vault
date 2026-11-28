package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// maxParamsJSONBytes bounds --params-json (the server's request limit is far
// above any sane parameter set; this keeps a wrong file or an endless pipe
// from filling memory).
const maxParamsJSONBytes = 4 << 20

// buildUseParams merges --params-json (a JSON object, from a file or "-" for
// stdin) with the repeated --param key=value pairs (string values). A key in
// both places is an error rather than a silent override.
func buildUseParams(stdin io.Reader, paramsJSON string, pairs []string) (map[string]any, error) {
	params := map[string]any{}
	if paramsJSON != "" {
		var r io.Reader
		if paramsJSON == "-" {
			r = stdin
		} else {
			f, err := os.Open(paramsJSON)
			if err != nil {
				return nil, fmt.Errorf("reading --params-json: %w", err)
			}
			defer f.Close()
			r = f
		}
		raw, err := io.ReadAll(io.LimitReader(r, maxParamsJSONBytes+1))
		if err != nil {
			return nil, fmt.Errorf("reading --params-json: %w", err)
		}
		if len(raw) > maxParamsJSONBytes {
			return nil, fmt.Errorf("--params-json is larger than %d bytes", maxParamsJSONBytes)
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		if err := dec.Decode(&params); err != nil || params == nil {
			return nil, errors.New("--params-json must hold one JSON object, e.g. {\"url\": \"https://api.example.com/v1/me\"}")
		}
		if dec.More() {
			return nil, errors.New("--params-json must hold exactly one JSON object")
		}
	}
	for _, kv := range pairs {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("--param %q: expected key=value", kv)
		}
		if _, dup := params[k]; dup {
			return nil, fmt.Errorf("parameter %q is given twice (--param and/or --params-json)", k)
		}
		params[k] = v
	}
	return params, nil
}

// runUse is POST /v1/secrets/{ns}/{name}/use: the server leases the secret,
// runs the action with it and returns only the action's result. The secret
// value never reaches this process.
func (c *cli) runUse(name, namespace, agent, purpose, action string, params map[string]any) error {
	if name == "" {
		return errors.New("secret name must not be empty")
	}
	if action == "" {
		return errors.New("--action is required (rgt-vault actions lists them)")
	}
	reqBody := struct {
		Action  string         `json:"action"`
		Agent   string         `json:"agent,omitempty"`
		Purpose string         `json:"purpose,omitempty"`
		Params  map[string]any `json:"params"`
	}{Action: action, Agent: agent, Purpose: purpose, Params: params}
	body, status, err := c.do(http.MethodPost, c.secretURL(namespace, name, "use"), reqBody)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return apiError("use", status, body)
	}
	var resp struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || len(resp.Result) == 0 {
		return errors.New("parsing response: no result in the server's answer")
	}
	var out bytes.Buffer
	if err := json.Indent(&out, resp.Result, "", "  "); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}
	fmt.Fprintln(c.stdout, out.String())
	return nil
}

func newUseCmd(newCLI func() *cli) *cobra.Command {
	var namespace, agent, purpose, action, paramsJSON string
	var pairs []string
	cmd := &cobra.Command{
		Use:   "use <name> --action ACTION [--purpose P] [--param k=v ...] [--params-json FILE|-]",
		Short: "Run an action with a secret (the server uses it; you never see it)",
		Long: "Ask the server to run a registered action with a secret and print the action's result as JSON.\n" +
			"The server unseals the secret, calls the upstream service with it and returns only the result:\n" +
			"the secret value never reaches this process or its output. `rgt-vault actions` lists the actions\n" +
			"and the parameters each accepts.\n\n" +
			"Parameters: --param key=value (repeatable, the value is always a string) and/or --params-json\n" +
			"FILE (or - for stdin), a JSON object for values that are not strings (messages, headers, ...).\n" +
			"A key given twice is an error. The token needs the agent scope; a refusal prints the server's reason\n" +
			"and incident id.\n\n" +
			"Examples:\n" +
			"  rgt-vault use GITHUB_TOKEN --namespace ci --action http_get_with_auth \\\n" +
			"      --purpose ci-build --param url=https://api.github.com/user\n" +
			"  echo '{\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}' | \\\n" +
			"      rgt-vault use OPENAI_KEY --action openai_chat --purpose chat --params-json -",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := newCLI()
			params, err := buildUseParams(c.stdin, paramsJSON, pairs)
			if err != nil {
				return err
			}
			return c.runUse(args[0], namespace, agent, purpose, action, params)
		},
	}
	cmd.Flags().StringVar(&namespace, "namespace", "default", "secret namespace")
	cmd.Flags().StringVar(&action, "action", "", "action to run (required; see `rgt-vault actions`)")
	cmd.Flags().StringVar(&purpose, "purpose", "", "purpose label, checked by the policy")
	cmd.Flags().StringVar(&agent, "agent", "", "agent label: with per-agent tokens the server uses the token's agent and refuses a different one (only legacy shared-token servers use it)")
	cmd.Flags().StringArrayVar(&pairs, "param", nil, "action parameter key=value (repeatable; string values)")
	cmd.Flags().StringVar(&paramsJSON, "params-json", "", "JSON object of action parameters from FILE, or - for stdin")
	_ = cmd.MarkFlagRequired("action")
	return cmd
}

// runActions is GET /v1/actions.
func (c *cli) runActions() error {
	body, status, err := c.do(http.MethodGet, c.host+"/v1/actions", nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return apiError("actions", status, body)
	}
	var resp struct {
		Actions []struct {
			Name        string   `json:"name"`
			Description string   `json:"description"`
			Params      []string `json:"params_schema"`
		} `json:"actions"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}
	sort.Slice(resp.Actions, func(i, j int) bool { return resp.Actions[i].Name < resp.Actions[j].Name })
	for _, a := range resp.Actions {
		fmt.Fprintf(c.stdout, "%s\t%s\tparams: %s\n", safeText(a.Name, maxNameCol), safeText(a.Description, maxDescCol),
			safeText(strings.Join(a.Params, ", "), maxDescCol))
	}
	return nil
}

// Column caps for server text in tab-separated listings.
const (
	maxNameCol = 64
	maxDescCol = 200
)

func newActionsCmd(newCLI func() *cli) *cobra.Command {
	return &cobra.Command{
		Use:   "actions",
		Short: "List the actions `use` can run, with their parameters",
		Long:  "List the actions the server registers (GET /v1/actions): name, description and the only parameter keys\neach accepts, one per line, tab-separated. Needs a token with the agent scope.",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, args []string) error { return newCLI().runActions() },
	}
}
