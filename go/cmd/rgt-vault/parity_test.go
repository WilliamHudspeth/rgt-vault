package main

import (
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/server"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/server/handlers"
)

// routeToCommand maps every authenticated /v1 route of the server to the CLI
// command that calls it, or to the reason it has none. A new route fails
// TestRouteCLIParity until it is listed here (RGT-525: the product's main
// action had no command for months).
var routeToCommand = map[string]string{
	"POST /v1/secrets":                           "set",
	"GET /v1/secrets":                            "list",
	"GET /v1/secrets/{namespace}/{name}/":        "fingerprint",
	"POST /v1/secrets/{namespace}/{name}/use":    "use",
	"POST /v1/secrets/{namespace}/{name}/revoke": "revoke",
	"POST /v1/secrets/{namespace}/{name}/lease":  "get",
	"POST /v1/rotate":                            "rotate",
	"GET /v1/audit":                              "audit",
	"POST /v1/audit/verify":                      "verify-audit",
	"POST /v1/policy/simulate":                   "simulate",
	"GET /v1/requests":                           "requests list",
	"POST /v1/requests/{id}/approve":             "requests approve",
	"POST /v1/requests/{id}/deny":                "requests deny",
	"GET /v1/actions":                            "actions",
	"POST /v1/capabilities/execute":              "-: agents call it with a v2 capability token through the MCP server (mcp), not a human command",
	"GET /v1/capabilities":                       "-: MCP tool list_capabilities",
	"GET /v1/capabilities/list":                  "-: MCP tool list_capabilities",
}

func TestRouteCLIParity(t *testing.T) {
	r := server.NewRouter(&handlers.Handlers{}, server.NewMiddleware(nil))
	root := newRootCmd(strings.NewReader(""), io.Discard)

	seen := map[string]bool{}
	err := chi.Walk(r, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if !strings.HasPrefix(route, "/v1") {
			return nil
		}
		key := method + " " + route
		seen[key] = true
		target, ok := routeToCommand[key]
		if !ok {
			t.Errorf("route %q has no entry in routeToCommand: add the CLI command that calls it, or say why there is none", key)
			return nil
		}
		if strings.HasPrefix(target, "-:") {
			return nil
		}
		cmd, _, err := root.Find(strings.Fields(target))
		if err != nil || cmd == root || cmd.Name() != strings.Fields(target)[len(strings.Fields(target))-1] {
			t.Errorf("route %q: command %q is not registered", key, target)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var stale []string
	for k := range routeToCommand {
		if !seen[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("routeToCommand lists routes the server no longer has: %v", stale)
	}
}

// Every command, and every subcommand of requests, has help text.
func TestCommandsHaveHelp(t *testing.T) {
	root := newRootCmd(strings.NewReader(""), io.Discard)
	for _, c := range root.Commands() {
		if c.Name() == "help" || c.Name() == "completion" {
			continue
		}
		if strings.TrimSpace(c.Short) == "" {
			t.Errorf("%s has no short help", c.Name())
		}
		for _, sub := range c.Commands() {
			if strings.TrimSpace(sub.Short) == "" {
				t.Errorf("%s %s has no short help", c.Name(), sub.Name())
			}
		}
	}
	for _, name := range []string{"use", "actions", "requests"} {
		c, _, err := root.Find([]string{name})
		if err != nil || c.Name() != name || strings.TrimSpace(c.Long) == "" {
			t.Errorf("%s: missing long help", name)
		}
	}
	for _, name := range []string{"approve", "deny", "list"} {
		c, _, err := root.Find([]string{"requests", name})
		if err != nil || c.Name() != name {
			t.Errorf("requests %s is not registered", name)
		}
	}
	// The TOTP flag warns about the process list.
	c, _, _ := root.Find([]string{"requests", "approve"})
	if f := c.Flags().Lookup("totp-code"); f == nil || !strings.Contains(f.Usage, "process list") {
		t.Errorf("--totp-code help must warn that it is visible in the process list")
	}
}
