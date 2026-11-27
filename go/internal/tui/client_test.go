package tui

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const (
	testAgentToken = "agent-token-AAAA"
	testOpToken    = "operator-token-OOOO"
)

// fakeServer imitates the routes the TUI client uses.
type fakeServer struct {
	mu        sync.Mutex
	reqs      []string // "METHOD URI"
	auths     map[string]string
	bodies    map[string]map[string]any
	status    map[string]int // path -> forced status
	inflight  atomic.Int32
	maxFlight atomic.Int32
	fpDelay   chan struct{}
}

func newFakeServer() *fakeServer {
	return &fakeServer{auths: map[string]string{}, bodies: map[string]map[string]any{}, status: map[string]int{}}
}

func (f *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	key := r.Method + " " + r.URL.Path
	f.reqs = append(f.reqs, r.Method+" "+r.URL.RequestURI())
	f.auths[key] = r.Header.Get("Authorization")
	var body map[string]any
	if json.Unmarshal(raw, &body) == nil {
		f.bodies[key] = body
	}
	forced := f.status[r.URL.Path]
	f.mu.Unlock()

	if forced != 0 {
		w.WriteHeader(forced)
		fmt.Fprint(w, `{"error":"X","detail":"SERVER-SIDE-DETAIL `+testAgentToken+` plaintext-value"}`)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/healthz":
		fmt.Fprint(w, `{"status":"ok"}`)
	case r.URL.Path == "/v1/audit/verify":
		fmt.Fprint(w, `{"ok":true}`)
	case r.URL.Path == "/v1/secrets":
		// A (hypothetical) server that still leaks a value: it must be dropped.
		fmt.Fprint(w, `{"namespace":"prod","secrets":[
			{"name":"api key","note":"prod api","require_2fa":true,"value":"LEAKED-VALUE","status":"ACTIVE"},
			{"name":"db","note":"","require_2fa":false,"type":"totp","fingerprint":"preset01"},
			{"name":"broken","note":"x","require_2fa":false}]}`)
	case strings.HasPrefix(r.URL.Path, "/v1/secrets/prod/"):
		n := f.inflight.Add(1)
		for {
			m := f.maxFlight.Load()
			if n <= m || f.maxFlight.CompareAndSwap(m, n) {
				break
			}
		}
		if f.fpDelay != nil {
			<-f.fpDelay
		}
		f.inflight.Add(-1)
		name := strings.TrimPrefix(r.URL.EscapedPath(), "/v1/secrets/prod/")
		if name == "broken" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		sum := sha256.Sum256([]byte("ciphertext:" + name))
		fmt.Fprintf(w, `{"namespace":"prod","name":%q,"fingerprint":%q}`, name, hex.EncodeToString(sum[:])[:8])
	case r.URL.Path == "/v1/audit":
		fmt.Fprint(w, `{"entries":[
			{"id":3,"action":"C","timestamp":"2026-11-26T10:00:03+00:00","details":"third","entry_hash":"h3","agent_id":"bot"},
			{"id":2,"action":"B","timestamp":"2026-11-26T10:00:02+00:00","details":null,"entry_hash":"h2","agent_id":null},
			{"id":1,"action":"A","timestamp":"2026-11-26T10:00:01+00:00","details":"first","entry_hash":"h1","agent_id":"x"}]}`)
	case r.URL.Path == "/v1/rotate":
		fmt.Fprint(w, `{"ok":true}`)
	case r.URL.Path == "/v1/requests":
		fmt.Fprint(w, `{"requests":[{"request_id":"r1","agent":"bot","namespace":"prod","secret_name":"guarded","purpose":"deploy","action":"read","require_2fa":true,"created_at":1700000000.5}]}`)
	case strings.HasSuffix(r.URL.Path, "/approve"), strings.HasSuffix(r.URL.Path, "/deny"):
		fmt.Fprint(w, `{"ok":true}`)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeServer) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.reqs...)
}

func newTestClient(t *testing.T) (*HTTPClient, *fakeServer) {
	t.Helper()
	fs := newFakeServer()
	ts := httptest.NewServer(fs)
	t.Cleanup(ts.Close)
	c := NewHTTPClient(ts.URL, testAgentToken)
	c.SetOperatorToken(testOpToken)
	return c, fs
}

func TestNewHTTPClient_DefaultBaseURL(t *testing.T) {
	for _, in := range []string{"", "  "} {
		if got := NewHTTPClient(in, "t").baseURL; got != "http://127.0.0.1:8765" {
			t.Errorf("NewHTTPClient(%q).baseURL = %q, want the 8765 default", in, got)
		}
	}
	if got := NewHTTPClient("http://h:1///", "t").baseURL; got != "http://h:1" {
		t.Errorf("trailing slashes kept: %q", got)
	}
}

func TestListSecrets_MetadataAndFingerprints(t *testing.T) {
	c, fs := newTestClient(t)
	infos, err := c.ListSecrets("prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 3 {
		t.Fatalf("got %d secrets: %+v", len(infos), infos)
	}
	by := map[string]SecretInfo{}
	for _, s := range infos {
		by[s.Name] = s
	}
	api := by["api key"]
	if !api.Require2FA || api.Note != "prod api" {
		t.Errorf("api key metadata = %+v", api)
	}
	if want := fmt.Sprintf("%x", sha256.Sum256([]byte("ciphertext:api%20key")))[:8]; api.Fingerprint != want {
		t.Errorf("api key fingerprint = %q, want %q (fetched from the server)", api.Fingerprint, want)
	}
	// The pre-fix client hashed the (absent) value: every secret shared this.
	emptyHash := fmt.Sprintf("%x", sha256.Sum256(nil))[:8]
	for _, s := range infos {
		if s.Fingerprint == emptyHash {
			t.Errorf("%s shows the fingerprint of the empty string", s.Name)
		}
	}
	if by["db"].Fingerprint != "preset01" || by["db"].Type != "totp" || !IsTOTP(by["db"]) {
		t.Errorf("db = %+v (a list-provided fingerprint/type must be used as is)", by["db"])
	}
	if by["broken"].Fingerprint != "" {
		t.Errorf("failed fingerprint lookup should leave it empty, got %q", by["broken"].Fingerprint)
	}
	if fmt.Sprintf("%+v", infos) != strings.ReplaceAll(fmt.Sprintf("%+v", infos), "LEAKED-VALUE", "") {
		t.Error("a value sent by the server was kept")
	}

	// The list call carries the namespace and no agent label (the server
	// takes the agent from the token, H1); the secret name is path-escaped.
	got := fs.requests()
	if got[0] != "GET /v1/secrets?namespace=prod" {
		t.Errorf("list request = %q", got[0])
	}
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "GET /v1/secrets/prod/api%20key") {
		t.Errorf("fingerprint path not escaped: %s", joined)
	}
	if fs.auths["GET /v1/secrets"] != "Bearer "+testAgentToken {
		t.Errorf("list auth = %q", fs.auths["GET /v1/secrets"])
	}
}

func TestListSecrets_FingerprintConcurrencyBounded(t *testing.T) {
	fs := newFakeServer()
	fs.fpDelay = make(chan struct{})
	ts := httptest.NewServer(fs)
	defer ts.Close()
	// 20 secrets without fingerprints.
	var items []string
	for i := 0; i < 20; i++ {
		items = append(items, fmt.Sprintf(`{"name":"s%d"}`, i))
	}
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/secrets" {
			fmt.Fprintf(w, `{"secrets":[%s]}`, strings.Join(items, ","))
			return
		}
		fs.ServeHTTP(w, r)
	}))
	defer big.Close()
	c := NewHTTPClient(big.URL, "t")
	done := make(chan []SecretInfo)
	go func() {
		infos, _ := c.ListSecrets("prod")
		done <- infos
	}()
	// Let a few lookups pile up, then release them all.
	for fs.inflight.Load() < maxFingerprintWorkers {
		select {
		case <-done:
			t.Fatal("finished before the gate opened")
		default:
		}
	}
	close(fs.fpDelay)
	infos := <-done
	if len(infos) != 20 {
		t.Fatalf("got %d", len(infos))
	}
	if m := fs.maxFlight.Load(); m > maxFingerprintWorkers {
		t.Errorf("%d concurrent fingerprint lookups, limit %d", m, maxFingerprintWorkers)
	}
	for _, s := range infos {
		if s.Fingerprint == "" {
			t.Errorf("%s: no fingerprint", s.Name)
		}
	}
}

func TestVerifyAudit_Spellings(t *testing.T) {
	for _, tc := range []struct {
		body string
		code int
		want bool
	}{
		{`{"ok":true}`, 200, true},
		{`{"ok":false}`, 200, false},
		{`{"valid":true}`, 200, true},
		{`{}`, 200, false},
		{`not json`, 200, false},
		{`{"ok":true}`, 500, false},
	} {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.code)
			fmt.Fprint(w, tc.body)
		}))
		if got := NewHTTPClient(ts.URL, "t").VerifyAudit(); got != tc.want {
			t.Errorf("VerifyAudit(%d %s) = %v, want %v", tc.code, tc.body, got, tc.want)
		}
		ts.Close()
	}
}

func TestGetAuditLog_MapsServerRowsOldestFirst(t *testing.T) {
	c, fs := newTestClient(t)
	entries, err := c.GetAuditLog(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || entries[0].Event != "A" || entries[2].Event != "C" {
		t.Fatalf("entries = %+v (want oldest first)", entries)
	}
	if e := entries[2]; e.Principal != "bot" || e.Detail != "third" || e.Hash != "h3" || e.Timestamp != "2026-11-26T10:00:03+00:00" {
		t.Errorf("mapped entry = %+v", e)
	}
	if e := entries[1]; e.Principal != "" || e.Detail != "" {
		t.Errorf("null columns = %+v", e)
	}
	if fs.requests()[0] != "GET /v1/audit?limit=50" {
		t.Errorf("request = %v", fs.requests())
	}
}

func TestHealthRotateAndErrors(t *testing.T) {
	c, fs := newTestClient(t)
	if !c.Health() || !c.VerifyAudit() {
		t.Fatal("health/verify against the fake server")
	}
	if err := c.Rotate("dek"); err != nil {
		t.Fatal(err)
	}
	if fs.bodies["POST /v1/rotate"]["target"] != "dek" {
		t.Errorf("rotate body = %v", fs.bodies["POST /v1/rotate"])
	}

	// Status errors carry the code, never the server's body or any token.
	fs.status["/v1/rotate"] = 403
	fs.status["/v1/secrets"] = 500
	fs.status["/v1/audit"] = 503
	fs.status["/healthz"] = 500
	err := c.Rotate("master")
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 403 || err.Error() != "rotate: HTTP 403 Forbidden" {
		t.Errorf("rotate error = %v", err)
	}
	if _, err := c.ListSecrets("prod"); err == nil || strings.Contains(err.Error(), "SERVER-SIDE") || strings.Contains(err.Error(), testAgentToken) {
		t.Errorf("list error = %v", err)
	}
	if _, err := c.GetAuditLog(5); err == nil || !strings.Contains(err.Error(), "503") {
		t.Errorf("audit error = %v", err)
	}
	if c.Health() {
		t.Error("Health true on 500")
	}
}

func TestTransportAndDecodeErrors(t *testing.T) {
	dead := NewHTTPClient("http://127.0.0.1:1", testAgentToken)
	if _, err := dead.ListSecrets("x"); err == nil || strings.Contains(err.Error(), testAgentToken) {
		t.Errorf("transport error = %v", err)
	}
	if dead.Health() || dead.VerifyAudit() {
		t.Error("dead server reported healthy")
	}
	if _, err := dead.ListRequests(); err == nil {
		t.Error("ListRequests on a dead server")
	}
	if err := dead.Approve("r", ""); err == nil || errors.Is(err, ErrRejected) {
		t.Errorf("approve on a dead server = %v", err)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"secrets": 5}`) }))
	defer bad.Close()
	if _, err := NewHTTPClient(bad.URL, "t").ListSecrets("x"); err == nil || err.Error() != "list secrets: invalid response" {
		t.Errorf("decode error = %v", err)
	}
	// A request that cannot even be built.
	if _, err := NewHTTPClient("http://[::1", "t").ListSecrets("x"); err == nil {
		t.Error("malformed base URL accepted")
	}
}

func TestSetAgent(t *testing.T) {
	c, fs := newTestClient(t)
	if err := c.SetAgent("ops.team@1"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListSecrets("prod"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fs.requests()[0], "agent=ops.team%401") {
		t.Errorf("agent label not sent: %v", fs.requests()[0])
	}
	if err := c.SetAgent("bad agent!"); err == nil {
		t.Error("invalid agent accepted")
	}
	if c.agent != "ops.team@1" {
		t.Errorf("invalid agent stored: %q", c.agent)
	}
}

func TestApprovalCalls_UseOperatorToken(t *testing.T) {
	c, fs := newTestClient(t)
	reqs, err := c.ListRequests()
	if err != nil || len(reqs) != 1 {
		t.Fatalf("ListRequests = %v, %v", reqs, err)
	}
	want := PendingRequest{RequestID: "r1", Agent: "bot", Namespace: "prod", SecretName: "guarded", Purpose: "deploy", Action: "read", Require2FA: true, CreatedAt: 1700000000.5}
	if reqs[0] != want {
		t.Errorf("request = %+v", reqs[0])
	}
	if err := c.Approve("r1", "123456"); err != nil {
		t.Fatal(err)
	}
	if err := c.Approve("r/2", ""); err != nil {
		t.Fatal(err)
	}
	if err := c.Deny("r1", ""); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"GET /v1/requests", "POST /v1/requests/r1/approve", "POST /v1/requests/r1/deny"} {
		if fs.auths[key] != "Bearer "+testOpToken {
			t.Errorf("%s used %q, want the operator token", key, fs.auths[key])
		}
	}
	// No operator label: the server records the token's agent (H1).
	if b := fs.bodies["POST /v1/requests/r1/approve"]; b["totp_code"] != "123456" || b["operator"] != nil {
		t.Errorf("approve body = %v", b)
	}
	if b := fs.bodies["POST /v1/requests/r1/deny"]; b["reason"] != "denied by operator" || b["operator"] != nil {
		t.Errorf("deny body = %v", b)
	}
	// A configured label (legacy servers) is sent as the operator name.
	if err := c.SetAgent("ops"); err != nil {
		t.Fatal(err)
	}
	if err := c.Deny("r1", ""); err != nil {
		t.Fatal(err)
	}
	if b := fs.bodies["POST /v1/requests/r1/deny"]; b["operator"] != "ops" {
		t.Errorf("deny body with label = %v", b)
	}
	if err := c.SetAgent(""); err != nil || c.agent != "" {
		t.Errorf("SetAgent(\"\") = %v %q", err, c.agent)
	}
	if got := strings.Join(fs.requests(), " "); !strings.Contains(got, "POST /v1/requests/r%2F2/approve") {
		t.Errorf("request id not path-escaped: %s", got)
	}
}

func TestApprovalNullCodeAndOperatorFallback(t *testing.T) {
	fs := newFakeServer()
	ts := httptest.NewServer(fs)
	defer ts.Close()
	c := NewHTTPClient(ts.URL, testAgentToken) // no operator token: the agent token is used
	if err := c.Approve("r9", ""); err != nil {
		t.Fatal(err)
	}
	b := fs.bodies["POST /v1/requests/r9/approve"]
	if v, present := b["totp_code"]; !present || v != nil {
		t.Errorf("empty code must be JSON null, body = %v", b)
	}
	if fs.auths["POST /v1/requests/r9/approve"] != "Bearer "+testAgentToken {
		t.Errorf("fallback auth = %q", fs.auths["POST /v1/requests/r9/approve"])
	}
}

func TestDecide_RejectedAndFailures(t *testing.T) {
	c, fs := newTestClient(t)
	fs.status["/v1/requests/r1/approve"] = 400
	fs.status["/v1/requests/r1/deny"] = 400
	if err := c.Approve("r1", "000000"); !errors.Is(err, ErrRejected) {
		t.Errorf("400 on approve = %v, want ErrRejected", err)
	}
	if err := c.Deny("r1", "x"); !errors.Is(err, ErrRejected) {
		t.Errorf("400 on deny = %v, want ErrRejected", err)
	}
	fs.status["/v1/requests/r1/approve"] = 401
	err := c.Approve("r1", "000000")
	var se *StatusError
	if errors.Is(err, ErrRejected) || !errors.As(err, &se) || se.Code != 401 {
		t.Errorf("401 on approve = %v", err)
	}
	if strings.Contains(err.Error(), "000000") || strings.Contains(err.Error(), testOpToken) {
		t.Errorf("error leaks the code or token: %v", err)
	}
	fs.status["/v1/requests"] = 409
	if _, err := c.ListRequests(); err == nil || !strings.Contains(err.Error(), "409") {
		t.Errorf("409 on list = %v", err)
	}
}
