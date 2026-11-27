package compat

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// pythonSource reads a file of the frozen Python tree, or skips the test once
// python/ has been removed (the end of the Python line, batch GZ).
func pythonSource(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "python", rel))
	if err != nil {
		t.Skipf("python/%s not present (Python line removed): %v", rel, err)
	}
	return string(b)
}

// Python routes that Go deliberately does not serve.
var omittedPythonRoutes = map[string]string{
	"GET /docs":         "interactive API docs: not served (Python only enables them outside production)",
	"GET /redoc":        "interactive API docs: not served",
	"GET /openapi.json": "OpenAPI document: not served",
}

// Go routes with no Python counterpart (documented extras).
var goOnlyRoutes = map[string]string{
	"GET /v1/secrets/{namespace}/{name}": "ciphertext fingerprint over HTTP (RGT-502)",
	"GET /v1/actions":                    "registered actions listing",
}

// TestRouteParity enumerates every HTTP route of python/server/app.py and of
// the Go router: each Python route has a Go route, or is a documented
// deliberate omission, and every Go-only route is documented. (Python's CSRF
// double-submit cookie is a middleware, not a route: Go's token-in-header
// model has no cookie, see the migration guide.)
func TestRouteParity(t *testing.T) {
	src := pythonSource(t, "server/app.py")
	py := map[string]bool{}
	re := regexp.MustCompile(`@app\.(get|post|put|delete|patch)\(\s*"([^"]+)"`)
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		path := strings.ReplaceAll(m[2], "{request_id}", "{id}")
		py[strings.ToUpper(m[1])+" "+path] = true
	}
	if len(py) < 15 {
		t.Fatalf("parsed only %d Python routes: %v", len(py), py)
	}
	if strings.Contains(src, `"/openapi.json"`) {
		py["GET /openapi.json"] = true // FastAPI's openapi_url, configured in build_app
	}

	routes, ok := open(t, emptyDir(t)).h.(chi.Routes)
	if !ok {
		t.Fatal("server.New did not return a chi router")
	}
	goRoutes := map[string]bool{}
	err := chi.Walk(routes, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		route = strings.TrimSuffix(route, "/")
		if route == "" {
			route = "/"
		}
		goRoutes[method+" "+route] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for r := range py {
		if goRoutes[r] {
			continue
		}
		if why, ok := omittedPythonRoutes[r]; ok {
			t.Logf("deliberate omission: %s (%s)", r, why)
			continue
		}
		t.Errorf("Python route %s has no Go counterpart and is not a documented omission", r)
	}
	var extras []string
	for r := range goRoutes {
		if !py[r] {
			extras = append(extras, r)
		}
	}
	sort.Strings(extras)
	for _, r := range extras {
		if _, ok := goOnlyRoutes[r]; !ok {
			t.Errorf("Go route %s has no Python counterpart and is not documented as Go-only", r)
		}
	}
	for r := range omittedPythonRoutes {
		if !py[r] {
			t.Errorf("stale omission %q: Python no longer has it", r)
		}
	}
	t.Logf("%d Python routes, %d Go routes, %d deliberate omissions, %d Go-only", len(py), len(goRoutes), len(omittedPythonRoutes), len(goOnlyRoutes))
}

// TestCLICommandParity: every subcommand of python/cli.py exists in the Go
// CLI, plus the migration-era additions (export, import, provider, migrate).
func TestCLICommandParity(t *testing.T) {
	src := pythonSource(t, "cli.py")
	re := regexp.MustCompile(`add_parser\(\s*"([a-z0-9-]+)"`)
	var pyCmds []string
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		pyCmds = append(pyCmds, m[1])
	}
	if len(pyCmds) < 13 {
		t.Fatalf("parsed only %d Python subcommands: %v", len(pyCmds), pyCmds)
	}
	help, _, code := runBin(t, nil, "--help")
	if code != 0 {
		t.Fatalf("rgt-vault --help: exit %d", code)
	}
	have := map[string]bool{}
	in := false
	for _, line := range strings.Split(help, "\n") {
		switch {
		case strings.HasPrefix(line, "Available Commands:"):
			in = true
		case in && strings.TrimSpace(line) == "":
			in = false
		case in:
			if f := strings.Fields(line); len(f) > 0 {
				have[f[0]] = true
			}
		}
	}
	for _, c := range pyCmds {
		if !have[c] {
			t.Errorf("Python subcommand %q has no Go counterpart", c)
		}
	}
	for _, c := range []string{"export", "import", "provider", "migrate"} {
		if !have[c] {
			t.Errorf("Go CLI lacks %q (decision D4 / migration)", c)
		}
	}
	t.Logf("Python subcommands %v all present in Go", pyCmds)
}
