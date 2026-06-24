package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newBackend returns a test HTTP server that responds with bodyText for every request.
func newBackend(t *testing.T, bodyText string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, bodyText)
	}))
}

// makeGateway is a test helper that builds a Gateway and fails the test on error.
func makeGateway(t *testing.T, pyURL, goURL string, goPercent int) *Gateway {
	t.Helper()
	gw, err := NewGateway(pyURL, goURL, goPercent)
	if err != nil {
		t.Fatalf("NewGateway(%q, %q, %d): %v", pyURL, goURL, goPercent, err)
	}
	return gw
}

// body reads the body of an httptest.ResponseRecorder.
func body(rr *httptest.ResponseRecorder) string {
	return strings.TrimSpace(rr.Body.String())
}

// doRequest fires a GET / at the gateway and returns the ResponseRecorder.
func doRequest(gw *Gateway) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, req)
	return rr
}

// TestGoPercent0_AllPython verifies that with go_percent=0 all requests go to Python.
func TestGoPercent0_AllPython(t *testing.T) {
	py := newBackend(t, "PY")
	defer py.Close()
	go_ := newBackend(t, "GO")
	defer go_.Close()

	gw := makeGateway(t, py.URL, go_.URL, 0)

	const n = 100
	for i := 0; i < n; i++ {
		rr := doRequest(gw)
		if got := body(rr); got != "PY" {
			t.Fatalf("request %d: expected PY, got %q", i, got)
		}
	}

	stats := gw.Stats()
	if stats["python_reqs"] != n {
		t.Errorf("python_reqs: want %d, got %d", n, stats["python_reqs"])
	}
	if stats["go_reqs"] != 0 {
		t.Errorf("go_reqs: want 0, got %d", stats["go_reqs"])
	}
}

// TestGoPercent100_AllGo verifies that with go_percent=100 all requests go to Go.
func TestGoPercent100_AllGo(t *testing.T) {
	py := newBackend(t, "PY")
	defer py.Close()
	go_ := newBackend(t, "GO")
	defer go_.Close()

	gw := makeGateway(t, py.URL, go_.URL, 0)
	gw.SetGoPercent(100)

	const n = 100
	for i := 0; i < n; i++ {
		rr := doRequest(gw)
		if got := body(rr); got != "GO" {
			t.Fatalf("request %d: expected GO, got %q", i, got)
		}
	}

	stats := gw.Stats()
	if stats["go_reqs"] != n {
		t.Errorf("go_reqs: want %d, got %d", n, stats["go_reqs"])
	}
	if stats["python_reqs"] != 0 {
		t.Errorf("python_reqs: want 0, got %d", stats["python_reqs"])
	}
}

// TestGoPercent50_BothHit verifies that with go_percent=50, over 200 requests
// both backends receive at least one request.
func TestGoPercent50_BothHit(t *testing.T) {
	py := newBackend(t, "PY")
	defer py.Close()
	go_ := newBackend(t, "GO")
	defer go_.Close()

	gw := makeGateway(t, py.URL, go_.URL, 50)

	const n = 200
	for i := 0; i < n; i++ {
		doRequest(gw)
	}

	stats := gw.Stats()
	if stats["python_reqs"] == 0 {
		t.Error("python_reqs==0: expected Python to receive some requests at 50%")
	}
	if stats["go_reqs"] == 0 {
		t.Error("go_reqs==0: expected Go to receive some requests at 50%")
	}
	if total := stats["python_reqs"] + stats["go_reqs"]; total != n {
		t.Errorf("total reqs: want %d, got %d", n, total)
	}
}

// TestAdminCutover_PutSetsPercent verifies that PUT /__cutover?go=100 returns 200
// with {"go_percent":100} and that subsequent requests route to Go.
func TestAdminCutover_PutSetsPercent(t *testing.T) {
	py := newBackend(t, "PY")
	defer py.Close()
	go_ := newBackend(t, "GO")
	defer go_.Close()

	gw := makeGateway(t, py.URL, go_.URL, 0)

	// PUT /__cutover?go=100
	req := httptest.NewRequest(http.MethodPut, "/__cutover?go=100", nil)
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("PUT /__cutover?go=100: want 200, got %d", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type: want application/json, got %q", ct)
	}

	var resp map[string]int
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response body JSON parse: %v (body=%q)", err, body(rr))
	}
	if resp["go_percent"] != 100 {
		t.Errorf("go_percent in response: want 100, got %d", resp["go_percent"])
	}
	if gw.GoPercent() != 100 {
		t.Errorf("GoPercent(): want 100, got %d", gw.GoPercent())
	}

	// Subsequent request must go to Go backend.
	rr2 := doRequest(gw)
	if got := body(rr2); got != "GO" {
		t.Errorf("after setting go=100: expected GO, got %q", got)
	}
}

// TestAdminCutover_PostAlsoWorks verifies that POST /__cutover?go=0 is also accepted.
func TestAdminCutover_PostAlsoWorks(t *testing.T) {
	py := newBackend(t, "PY")
	defer py.Close()
	go_ := newBackend(t, "GO")
	defer go_.Close()

	gw := makeGateway(t, py.URL, go_.URL, 100)

	req := httptest.NewRequest(http.MethodPost, "/__cutover?go=0", nil)
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("POST /__cutover?go=0: want 200, got %d", rr.Code)
	}
	if gw.GoPercent() != 0 {
		t.Errorf("GoPercent(): want 0, got %d", gw.GoPercent())
	}
}

// TestAdminCutover_MissingParam returns 400 when "go" query param is absent.
func TestAdminCutover_MissingParam(t *testing.T) {
	py := newBackend(t, "PY")
	defer py.Close()
	go_ := newBackend(t, "GO")
	defer go_.Close()

	gw := makeGateway(t, py.URL, go_.URL, 0)

	req := httptest.NewRequest(http.MethodPut, "/__cutover", nil)
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("missing 'go': want 400, got %d", rr.Code)
	}
}

// TestAdminCutover_InvalidParam returns 400 when "go" is not an integer.
func TestAdminCutover_InvalidParam(t *testing.T) {
	py := newBackend(t, "PY")
	defer py.Close()
	go_ := newBackend(t, "GO")
	defer go_.Close()

	gw := makeGateway(t, py.URL, go_.URL, 0)

	req := httptest.NewRequest(http.MethodPut, "/__cutover?go=banana", nil)
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid 'go': want 400, got %d", rr.Code)
	}
}

// TestAdminStats_ReturnsValidJSON verifies GET /__cutover/stats returns valid JSON
// with all expected keys.
func TestAdminStats_ReturnsValidJSON(t *testing.T) {
	py := newBackend(t, "PY")
	defer py.Close()
	go_ := newBackend(t, "GO")
	defer go_.Close()

	gw := makeGateway(t, py.URL, go_.URL, 42)

	// Fire a few requests to populate counters.
	gw.SetGoPercent(100)
	doRequest(gw)
	doRequest(gw)
	gw.SetGoPercent(0)
	doRequest(gw)

	req := httptest.NewRequest(http.MethodGet, "/__cutover/stats", nil)
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /__cutover/stats: want 200, got %d", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type: want application/json, got %q", ct)
	}

	var stats map[string]int64
	if err := json.Unmarshal(rr.Body.Bytes(), &stats); err != nil {
		t.Fatalf("stats JSON parse: %v (body=%q)", err, rr.Body.String())
	}

	expectedKeys := []string{"go_percent", "python_reqs", "go_reqs", "go_fails"}
	for _, k := range expectedKeys {
		if _, ok := stats[k]; !ok {
			t.Errorf("stats JSON missing key %q", k)
		}
	}

	if stats["go_reqs"] < 2 {
		t.Errorf("go_reqs: want >=2, got %d", stats["go_reqs"])
	}
	if stats["python_reqs"] < 1 {
		t.Errorf("python_reqs: want >=1, got %d", stats["python_reqs"])
	}
}

// TestCanaryFallback verifies that when the Go backend is unreachable (connection refused),
// requests still succeed via the Python fallback, and go_fails is incremented.
func TestCanaryFallback(t *testing.T) {
	py := newBackend(t, "PY")
	defer py.Close()

	// Start a Go backend, capture its URL, then immediately close it so any
	// connection attempt will be refused.
	go_ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "GO")
	}))
	goURL := go_.URL
	go_.Close() // close before any request — all connections will be refused

	gw := makeGateway(t, py.URL, goURL, 100)

	// With go_percent=100, every request should hit the (dead) Go backend,
	// trigger the ErrorHandler, and fall back to Python.
	const n = 5
	for i := 0; i < n; i++ {
		rr := doRequest(gw)
		got, err := io.ReadAll(rr.Body)
		if err != nil {
			t.Fatalf("request %d: reading body: %v", i, err)
		}
		if strings.TrimSpace(string(got)) != "PY" {
			t.Errorf("request %d: expected PY (fallback), got %q (status=%d)", i, got, rr.Code)
		}
	}

	stats := gw.Stats()
	if stats["go_fails"] < 1 {
		t.Errorf("go_fails: want >=1, got %d", stats["go_fails"])
	}
	// go_reqs should still be incremented (the attempt was made before the failure)
	if stats["go_reqs"] < 1 {
		t.Errorf("go_reqs: want >=1, got %d (counter should reflect the attempt)", stats["go_reqs"])
	}
}

// TestNewGateway_InvalidURL verifies that malformed URLs are rejected.
func TestNewGateway_InvalidURL(t *testing.T) {
	_, err := NewGateway("://bad-url", "http://localhost:9999", 0)
	if err == nil {
		t.Error("expected error for invalid pythonURL, got nil")
	}

	_, err = NewGateway("http://localhost:8080", "://bad-url", 0)
	if err == nil {
		t.Error("expected error for invalid goURL, got nil")
	}
}

// TestClamp verifies the clamp helper (package-internal).
func TestClamp(t *testing.T) {
	cases := []struct {
		in   int
		want int64
	}{
		{-1, 0},
		{0, 0},
		{50, 50},
		{100, 100},
		{101, 100},
		{999, 100},
	}
	for _, c := range cases {
		if got := clamp(c.in); got != c.want {
			t.Errorf("clamp(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestGoPercent_ClampOnSet verifies SetGoPercent clamps out-of-range values.
func TestGoPercent_ClampOnSet(t *testing.T) {
	py := newBackend(t, "PY")
	defer py.Close()
	go_ := newBackend(t, "GO")
	defer go_.Close()

	gw := makeGateway(t, py.URL, go_.URL, 0)

	gw.SetGoPercent(200)
	if gw.GoPercent() != 100 {
		t.Errorf("SetGoPercent(200): want 100, got %d", gw.GoPercent())
	}

	gw.SetGoPercent(-50)
	if gw.GoPercent() != 0 {
		t.Errorf("SetGoPercent(-50): want 0, got %d", gw.GoPercent())
	}
}
