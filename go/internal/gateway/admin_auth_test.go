package gateway

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/auth"
)

const testOperatorToken = "operator-test-token-0123456789abcdef"

func newOperatorStore(t *testing.T) *auth.TokenStore {
	t.Helper()
	ts := auth.NewTokenStore(filepath.Join(t.TempDir(), "operator.token"))
	if err := ts.Write(testOperatorToken); err != nil {
		t.Fatal(err)
	}
	return ts
}

// countingBackend records whether any request reached it.
func countingBackend(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		_, _ = w.Write([]byte("backend"))
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

// RGT-162: the admin API must reject unauthenticated callers, must not change
// the split for them, and must never forward admin paths to a backend.
func TestAdmin_RequiresOperatorToken(t *testing.T) {
	py, pyHits := countingBackend(t)
	goB, goHits := countingBackend(t)
	gw := makeGateway(t, py.URL, goB.URL, 0)

	cases := []struct {
		name, method, target, authz string
	}{
		{"no header PUT", http.MethodPut, "/__cutover?go=100", ""},
		{"no header POST", http.MethodPost, "/__cutover?go=100", ""},
		{"no header stats", http.MethodGet, "/__cutover/stats", ""},
		{"wrong token", http.MethodPut, "/__cutover?go=100", "Bearer nope"},
		{"empty bearer", http.MethodPut, "/__cutover?go=100", "Bearer "},
		{"prefix of token", http.MethodPut, "/__cutover?go=100", "Bearer " + testOperatorToken[:10]},
		{"token in query is not auth", http.MethodPut, "/__cutover?go=100&token=" + testOperatorToken, ""},
		{"unknown admin subpath", http.MethodGet, "/__cutover/anything", ""},
		{"GET on setter", http.MethodGet, "/__cutover?go=100", ""},
		{"double slash", http.MethodPut, "//__cutover?go=100", ""},
		{"dot segments", http.MethodPut, "/x/../__cutover?go=100", ""},
		{"trailing slash", http.MethodPut, "/__cutover/?go=100", ""},
		{"stats via dot segment", http.MethodGet, "/__cutover/./stats", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.target, nil)
			if tc.authz != "" {
				req.Header.Set("Authorization", tc.authz)
			}
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, req)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("want 401, got %d (%s)", rr.Code, rr.Body.String())
			}
			if !strings.HasPrefix(rr.Header().Get("WWW-Authenticate"), "Bearer") {
				t.Errorf("missing WWW-Authenticate header")
			}
			if strings.Contains(rr.Body.String(), testOperatorToken) {
				t.Errorf("response echoes the token")
			}
		})
	}
	if gw.GoPercent() != 0 {
		t.Fatalf("unauthenticated calls changed go_percent to %d", gw.GoPercent())
	}
	if pyHits.Load() != 0 || goHits.Load() != 0 {
		t.Fatalf("admin paths were proxied: python=%d go=%d", pyHits.Load(), goHits.Load())
	}
}

func TestAdmin_FailsClosedWithoutTokenStore(t *testing.T) {
	py, pyHits := countingBackend(t)
	gw, err := NewGateway(py.URL, py.URL, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ method, target string }{
		{http.MethodPut, "/__cutover?go=100"}, {http.MethodGet, "/__cutover/stats"},
	} {
		target := tc.target
		req := httptest.NewRequest(tc.method, target, nil)
		req.Header.Set("Authorization", "Bearer "+testOperatorToken)
		rr := httptest.NewRecorder()
		gw.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("%s: want 403, got %d", target, rr.Code)
		}
	}
	if gw.GoPercent() != 0 || pyHits.Load() != 0 {
		t.Fatal("disabled admin API had an effect")
	}
	// Non-admin traffic still flows.
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/secrets", nil))
	if rr.Code != http.StatusOK || pyHits.Load() != 1 {
		t.Fatalf("proxying broken: %d hits=%d", rr.Code, pyHits.Load())
	}
}

func TestAdmin_AuthorizedMethodAndPathChecks(t *testing.T) {
	py, _ := countingBackend(t)
	gw := makeGateway(t, py.URL, py.URL, 0)
	for _, tc := range []struct {
		method, target string
		want           int
	}{
		{http.MethodGet, "/__cutover?go=5", http.StatusMethodNotAllowed},
		{http.MethodDelete, "/__cutover/stats", http.StatusMethodNotAllowed},
		{http.MethodGet, "/__cutover/other", http.StatusNotFound},
		{http.MethodPut, "/__cutover?go=42", http.StatusOK},
		{http.MethodGet, "/__cutover/stats", http.StatusOK},
	} {
		req := httptest.NewRequest(tc.method, tc.target, nil)
		req.Header.Set("Authorization", "bearer "+testOperatorToken) // scheme is case-insensitive
		rr := httptest.NewRecorder()
		gw.ServeHTTP(rr, req)
		if rr.Code != tc.want {
			t.Errorf("%s %s: want %d, got %d", tc.method, tc.target, tc.want, rr.Code)
		}
	}
	if gw.GoPercent() != 42 {
		t.Fatalf("go_percent = %d, want 42", gw.GoPercent())
	}
}

func TestAdmin_TokenStoreUnreadable(t *testing.T) {
	py, _ := countingBackend(t)
	gw := makeGateway(t, py.URL, py.URL, 0)
	gw.SetOperatorTokenStore(auth.NewTokenStore(filepath.Join(t.TempDir(), "missing.token")))
	req := httptest.NewRequest(http.MethodPut, "/__cutover?go=100", nil)
	req.Header.Set("Authorization", "Bearer "+testOperatorToken)
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized || gw.GoPercent() != 0 {
		t.Fatalf("missing token file must fail closed: %d pct=%d", rr.Code, gw.GoPercent())
	}
	if strings.Contains(rr.Body.String(), "missing.token") {
		t.Error("response leaks token file path")
	}
}
