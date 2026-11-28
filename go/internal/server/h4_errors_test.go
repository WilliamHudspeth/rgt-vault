package server

// Batch H4: errors and limits (RGT-418/419 incident ids on EVERY error,
// RGT-421/427 nothing internal in responses, RGT-345 fail secure, RGT-353/357
// request-field validation, RGT-376 bounded numbers, request body limits on
// every body-reading route, RGT-256/257 paging bounds). Each test fails when
// the control it names is removed.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/server/handlers"
)

var incidentIDRE = regexp.MustCompile(`^[0-9a-f]{16}$`)

// captureLog redirects the standard logger into the returned buffer until the
// test ends.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(io.Discard) })
	return &buf
}

// errorBody decodes an error response and checks the common envelope: JSON,
// error + detail + a well-formed incident id.
func errorBody(t *testing.T, name string, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("%s: Content-Type %q (body %q)", name, ct, rec.Body.String())
	}
	var m map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("%s: not a JSON error: %v (%q)", name, err, rec.Body.String())
	}
	if m["error"] == "" || m["detail"] == "" {
		t.Errorf("%s: missing error/detail: %v", name, m)
	}
	if !incidentIDRE.MatchString(m["incident_id"]) {
		t.Errorf("%s: status %d without a well-formed incident_id: %v", name, rec.Code, m)
	}
	return m
}

func req(method, path, token, remote string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, path, body)
	r.RemoteAddr = remote
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	return r
}

// RGT-418/419: every error answer of the middleware AND the handlers carries
// an incident_id, and the same id is in the server log line of that failure.
func TestEveryErrorResponseCarriesIncidentID(t *testing.T) {
	e := newAuthzEnv(t, false)
	logs := captureLog(t)

	const ipBase = "10.1.0."
	cases := []struct {
		name   string
		status int
		build  func() *http.Request
	}{
		{"401 missing credentials", 401, func() *http.Request { return req("GET", "/v1/actions", "", ipBase+"1:1", nil) }},
		{"401 unknown token", 401, func() *http.Request { return req("GET", "/v1/actions", "not-a-token", ipBase+"2:1", nil) }},
		{"403 insufficient scope", 403, func() *http.Request {
			return req("POST", "/v1/rotate", e.alice, ipBase+"3:1", strings.NewReader(`{"target":"dek"}`))
		}},
		{"404 unknown route", 404, func() *http.Request { return req("GET", "/v1/nope", e.alice, ipBase+"4:1", nil) }},
		{"405 wrong verb on a route", 405, func() *http.Request { return req("GET", "/v1/rotate", e.operator, ipBase+"5:1", nil) }},
		{"405 TRACE", 405, func() *http.Request { return req("TRACE", "/v1/actions", e.alice, ipBase+"6:1", nil) }},
		{"400 ambiguous path", 400, func() *http.Request { return req("GET", "/v1//actions", e.alice, ipBase+"7:1", nil) }},
		{"413 declared oversize", 413, func() *http.Request {
			return req("POST", "/v1/policy/simulate", e.alice, ipBase+"8:1", strings.NewReader(strings.Repeat("x", int(DefaultMaxBodyBytes)+1)))
		}},
		{"400 malformed body (handler)", 400, func() *http.Request {
			return req("POST", "/v1/policy/simulate", e.alice, ipBase+"9:1", strings.NewReader(`{`))
		}},
		{"422 missing field (handler)", 422, func() *http.Request {
			return req("POST", "/v1/rotate", e.operator, ipBase+"10:1", strings.NewReader(`{}`))
		}},
		{"404 secret not found (handler)", 404, func() *http.Request {
			return req("POST", "/v1/secrets/alice-ns/nope/lease", e.aliceLease, ipBase+"11:1", strings.NewReader(`{}`))
		}},
		{"403 agent mismatch (handler)", 403, func() *http.Request {
			return req("POST", "/v1/secrets/alice-ns/k/lease", e.aliceLease, ipBase+"12:1", strings.NewReader(`{"agent":"bob"}`))
		}},
	}
	for _, c := range cases {
		logs.Reset()
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, c.build())
		if rec.Code != c.status {
			t.Errorf("%s: status %d, want %d (%s)", c.name, rec.Code, c.status, rec.Body.String())
			continue
		}
		m := errorBody(t, c.name, rec)
		if id := m["incident_id"]; !strings.Contains(logs.String(), "incident="+id) {
			t.Errorf("%s: incident id %s is not in the server log:\n%s", c.name, id, logs.String())
		}
	}
}

// 429: the failed-authentication limiter's answer also carries the id (the
// shared 5-failures-per-minute limit of newAuthzEnv).
func TestRateLimitedAnswerCarriesIncidentID(t *testing.T) {
	e := newAuthzEnv(t, false)
	logs := captureLog(t)
	var last *httptest.ResponseRecorder
	for i := 0; i < 7; i++ {
		last = httptest.NewRecorder()
		e.h.ServeHTTP(last, req("GET", "/v1/actions", "wrong-"+strconv.Itoa(i), "10.2.0.1:1", nil))
	}
	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429", last.Code)
	}
	m := errorBody(t, "429", last)
	if !strings.Contains(logs.String(), "incident="+m["incident_id"]) {
		t.Errorf("429 incident id not logged:\n%s", logs.String())
	}
}

// AuthMiddleware 500 (token store unreadable): generic body with an id; the
// cause (a file path) is logged under the same id and never sent (RGT-421).
func TestAuthUnavailableIs500WithIncidentAndNoPathLeak(t *testing.T) {
	logs := captureLog(t)
	// A directory where the token file should be: the read fails with an
	// error that names the path.
	dir := filepath.Join(t.TempDir(), "secret-location-do-not-leak")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	h := NewRouter(&handlers.Handlers{}, NewMiddleware(auth.NewTokenStore(dir)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req("GET", "/v1/actions", "any-token", "10.3.0.1:1", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500: %s", rec.Code, rec.Body.String())
	}
	m := errorBody(t, "auth 500", rec)
	if strings.Contains(rec.Body.String(), "secret-location") || strings.Contains(rec.Body.String(), dir) {
		t.Errorf("response leaks the token path: %s", rec.Body.String())
	}
	// ONE log line carries both the response's incident id and the cause.
	found := false
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "incident="+m["incident_id"]) && strings.Contains(line, "secret-location") {
			found = true
		}
	}
	if !found {
		t.Errorf("the cause must be logged under the response's incident id:\n%s", logs.String())
	}
}

// RGT-421/427: whatever fails (a panic, an unclassified handler error, a
// token-store fault), no response in production mode, nor in any other,
// contains a stack, a Go file path, a goroutine dump or the failure's text.
func TestErrorResponsesLeakNoInternals(t *testing.T) {
	for _, env := range []string{"production", ""} {
		t.Setenv("APP_ENV", env)
		logs := captureLog(t)
		mw := &Middleware{}
		panicky := mw.RecoverMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic("db password hunter2 at /home/will/vault.db")
		}))
		rec := httptest.NewRecorder()
		panicky.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
		if rec.Code != 500 {
			t.Fatalf("status %d", rec.Code)
		}
		errorBody(t, "panic", rec)
		for _, bad := range []string{"hunter2", "/home/", ".go:", "goroutine", "runtime.", "panic"} {
			if strings.Contains(strings.ToLower(rec.Body.String()), strings.ToLower(bad)) {
				t.Errorf("APP_ENV=%q: response contains %q: %s", env, bad, rec.Body.String())
			}
		}
		if !strings.Contains(logs.String(), "goroutine") {
			t.Errorf("the stack must be in the server log")
		}
	}
}

// Request bodies: every body-reading POST route answers 413 (JSON, with an
// incident id) when the body exceeds the limit, declared or chunked.
func TestBodyLimitCoversEveryPostRoute(t *testing.T) {
	e := newAuthzEnv(t, true)
	const limit = 2048
	h, err := New(Config{
		Vault: e.stack.Vault, Tokens: e.store, Broker: e.stack.Broker,
		Actions: e.stack.Actions, Capabilities: e.stack.Capabilities,
		MaxBodyBytes: limit,
	})
	if err != nil {
		t.Fatal(err)
	}
	big := `{"x":"` + strings.Repeat("a", 4*limit) + `"}`
	routes := []struct {
		path, token string
		readsBody   bool
	}{
		{"/v1/secrets", e.alice, true},
		{"/v1/secrets/alice-ns/k/use", e.alice, true},
		{"/v1/secrets/alice-ns/k/lease", e.aliceLease, true},
		{"/v1/secrets/alice-ns/k/revoke", e.alice, false},
		{"/v1/rotate", e.operator, true},
		{"/v1/audit/verify", e.operator, false},
		{"/v1/policy/simulate", e.alice, true},
		{"/v1/requests/0000/approve", e.opOnly, true},
		{"/v1/requests/0000/deny", e.opOnly, true},
		{"/v1/capabilities/execute", e.alice, true},
	}
	for _, rt := range routes {
		// Declared Content-Length over the limit: refused before any read.
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req("POST", rt.path, rt.token, "127.0.0.1:1", strings.NewReader(big)))
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("%s declared: status %d, want 413 (%s)", rt.path, rec.Code, rec.Body.String())
		} else {
			errorBody(t, rt.path+" declared", rec)
		}
		if !rt.readsBody {
			continue
		}
		// No declared length (chunked): cut off while reading.
		r := req("POST", rt.path, rt.token, "127.0.0.1:1", strings.NewReader(big))
		r.ContentLength = -1
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("%s chunked: status %d, want 413 (%s)", rt.path, rec.Code, rec.Body.String())
		} else {
			errorBody(t, rt.path+" chunked", rec)
		}
	}
	// A body at the limit still works (the limit is not off by a factor).
	rec := httptest.NewRecorder()
	ok := `{"agent":"alice","namespace":"alice-ns"}`
	h.ServeHTTP(rec, req("POST", "/v1/policy/simulate", e.alice, "127.0.0.1:1", strings.NewReader(ok)))
	if rec.Code != 200 {
		t.Errorf("small body: %d %s", rec.Code, rec.Body.String())
	}
}

// The default limit (1 MiB) applies when none is configured.
func TestDefaultBodyLimitApplies(t *testing.T) {
	e := newAuthzEnv(t, false)
	r := req("POST", "/v1/policy/simulate", e.alice, "127.0.0.1:1", strings.NewReader(`{"namespace":"`+strings.Repeat("a", int(DefaultMaxBodyBytes))+`"}`))
	r.ContentLength = -1
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", rec.Code)
	}
	errorBody(t, "default limit", rec)
}

// RGT-256/376: list endpoints bound limit and offset; integers that do not
// fit are refused, never wrapped or passed on.
func TestPagingBoundsAndIntegerOverflow(t *testing.T) {
	e := newAuthzEnv(t, false)
	cases := []struct {
		path   string
		status int
	}{
		{"/v1/secrets?namespace=alice-ns&limit=1000&offset=0", 200},
		{"/v1/secrets?namespace=alice-ns&limit=1&offset=" + strconv.Itoa(handlers.MaxListOffset), 200},
		{"/v1/secrets?namespace=alice-ns&limit=0", 400},
		{"/v1/secrets?namespace=alice-ns&limit=-1", 400},
		{"/v1/secrets?namespace=alice-ns&limit=1001", 400},
		{"/v1/secrets?namespace=alice-ns&offset=-1", 400},
		{"/v1/secrets?namespace=alice-ns&offset=" + strconv.Itoa(handlers.MaxListOffset+1), 400},
		{"/v1/secrets?namespace=alice-ns&offset=9223372036854775807", 400},
		{"/v1/secrets?namespace=alice-ns&offset=-9223372036854775808", 400},
		{"/v1/secrets?namespace=alice-ns&offset=9223372036854775808", 422},
		{"/v1/secrets?namespace=alice-ns&limit=99999999999999999999999", 422},
		{"/v1/secrets?namespace=alice-ns&limit=1e3", 422},
		{"/v1/secrets/alice-ns/k?version=99999999999999999999", 422},
		{"/v1/secrets/alice-ns/k?version=0", 400},
		{"/v1/secrets/alice-ns/k?version=-4", 400},
	}
	for _, c := range cases {
		code, body, _ := e.do("GET", c.path, e.alice, nil)
		if code != c.status {
			t.Errorf("GET %s: %d, want %d (%s)", c.path, code, c.status, body)
		}
	}
	// Audit: limit bounds (scope audit).
	for path, want := range map[string]int{
		"/v1/audit?limit=1000": 200, "/v1/audit?limit=1001": 400, "/v1/audit?limit=0": 400,
		"/v1/audit?limit=-5": 400, "/v1/audit?limit=9223372036854775808": 422,
	} {
		if code, body, _ := e.do("GET", path, e.auditor, nil); code != want {
			t.Errorf("GET %s: %d, want %d (%s)", path, code, want, body)
		}
	}
	// A JSON integer that overflows int, and a version that would wrap when
	// incremented, never reach the vault.
	for _, body := range []string{
		`{"capability":"secrets.echo","capability_token":"x.y","capability_version":99999999999999999999}`,
		`{"capability":"secrets.echo","capability_token":"x.y","capability_version":9223372036854775807}`,
		`{"capability":"secrets.echo","capability_token":"x.y","capability_version":-9223372036854775808}`,
	} {
		code, out, _ := e.do("POST", "/v1/capabilities/execute", e.alice, body)
		if code != 400 && code != 422 && code != 403 && code != 404 {
			t.Errorf("capability_version %s: %d (%s)", body, code, out)
		}
		if code >= 500 {
			t.Errorf("capability_version %s: server error %d", body, code)
		}
	}
}

// RGT-256/257: a filtered audit read looks at a bounded number of the
// newest rows, however long the log is.
func TestAuditFilterScanIsBounded(t *testing.T) {
	e := newAuthzEnv(t, false)
	ctx := context.Background()
	for i := 0; i < 12; i++ {
		name := "old"
		if i >= 8 {
			name = "new"
		}
		details := `{"capability": "` + name + `", "n": ` + strconv.Itoa(i) + `}`
		if err := e.stack.Vault.Audit(ctx, "CAPABILITY_EXECUTED", nullStr(), details, nullStr()); err != nil {
			t.Fatal(err)
		}
	}
	h := &handlers.Handlers{Vault: e.stack.Vault, AuditScanLimit: 5}
	mw := NewStoreMiddleware(e.store)
	mw.Auditor = h
	router := NewRouter(h, mw)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req("GET", "/v1/audit?capability=old&limit=100", e.auditor, "127.0.0.1:1", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Entries []map[string]any `json:"entries"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	// The newest 5 rows hold the 4 "new" rows and 1 "old" row at most (plus
	// the HTTP_API row of this very request): the 8 older "old" rows are
	// outside the scan window.
	if len(out.Entries) > 1 {
		t.Errorf("filtered scan returned %d rows; it must stop at the newest %d rows", len(out.Entries), 5)
	}
	// ... and the answer says the window was exhausted (RGT-376), so an
	// empty result is not mistaken for "no such event".
	var flags struct {
		Truncated bool `json:"truncated"`
		Scanned   int  `json:"scanned"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &flags)
	if !flags.Truncated || flags.Scanned != 5 {
		t.Errorf("truncated=%v scanned=%d, want true / 5: %s", flags.Truncated, flags.Scanned, rec.Body.String())
	}
	// A window that covers the whole log: no flag.
	h.AuditScanLimit = 1000
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req("GET", "/v1/audit?capability=old&limit=100", e.auditor, "127.0.0.1:1", nil))
	if strings.Contains(rec.Body.String(), "truncated") {
		t.Errorf("complete scan flagged truncated: %s", rec.Body.String())
	}
	// Enough matches before the window ends: no flag either.
	h.AuditScanLimit = 5
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req("GET", "/v1/audit?capability=new&limit=1", e.auditor, "127.0.0.1:1", nil))
	if strings.Contains(rec.Body.String(), "truncated") || !strings.Contains(rec.Body.String(), "CAPABILITY_EXECUTED") {
		t.Errorf("limit reached inside the window: %s", rec.Body.String())
	}
	// Unfiltered default: still honours limit.
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req("GET", "/v1/audit?limit=3", e.auditor, "127.0.0.1:1", nil))
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 200 || len(out.Entries) != 3 {
		t.Errorf("limit=3: %d rows (status %d)", len(out.Entries), rec.Code)
	}
}

// RGT-353/357: request-supplied purposes, reasons, filters and operator
// names are validated at the HTTP layer too, on the routes that did not go
// through the vault's own check; the answer never quotes the value.
func TestRequestFieldValidation(t *testing.T) {
	e := newAuthzEnv(t, true)
	long := strings.Repeat("p", 300)
	hostile := []struct{ name, value string }{
		{"control character", "a\x01b"},
		{"newline", "a\nb"},
		{"too long", long},
		{"invalid utf-8", "a\xffb"},
		{"zero-width", "a​b"},
	}
	for _, hv := range hostile {
		enc := (&queryEscaper{}).escape(hv.value)
		paths := []struct {
			name, path, token string
		}{
			{"fingerprint purpose", "/v1/secrets/alice-ns/k?purpose=" + enc, e.alice},
			{"authorized capabilities purpose", "/v1/capabilities/list?purpose=" + enc, e.alice},
			{"authorized capabilities namespace", "/v1/capabilities/list?namespace=" + enc, e.alice},
			{"audit capability filter", "/v1/audit?capability=" + enc, e.auditor},
		}
		for _, p := range paths {
			code, body, _ := e.do("GET", p.path, p.token, nil)
			if code != http.StatusBadRequest {
				t.Errorf("%s with %s: %d, want 400 (%s)", p.name, hv.name, code, body)
			}
			if strings.Contains(body, "pppp") || strings.Contains(body, "\x01") {
				t.Errorf("%s with %s: the answer quotes the value: %s", p.name, hv.name, body)
			}
		}
		for _, p := range []struct{ name, path, body string }{
			{"deny reason", "/v1/requests/abc/deny", `{"reason":` + jsonStr(hv.value) + `}`},
			{"deny operator", "/v1/requests/abc/deny", `{"operator":` + jsonStr(hv.value) + `}`},
			{"approve operator", "/v1/requests/abc/approve", `{"operator":` + jsonStr(hv.value) + `}`},
		} {
			if hv.name == "newline" && p.name == "deny reason" {
				continue // a denial reason may span lines (TestDenyReasonAllowsLineBreaksOnly)
			}
			if hv.name == "invalid utf-8" {
				continue // encoding/json turns invalid bytes into U+FFFD: the handler never sees them
			}
			code, body, _ := e.do("POST", p.path, e.opOnly, p.body)
			// 400 is also what an unknown request id answers: insist on the
			// validation error itself.
			if code != http.StatusBadRequest || !strings.Contains(body, `"ValidationError"`) {
				t.Errorf("%s with %s: %d, want a 400 ValidationError (%s)", p.name, hv.name, code, body)
			}
		}
	}
	// An over-long TOTP code never reaches the verifier.
	code, body, _ := e.do("POST", "/v1/requests/abc/approve", e.opOnly, `{"totp_code":"`+strings.Repeat("1", 64)+`"}`)
	if code != http.StatusBadRequest || !strings.Contains(body, "'totp_code' is too long") {
		t.Errorf("long totp_code: %d (%s)", code, body)
	}
	// Valid values pass the field checks: the answer is about the request id
	// (unknown), not about validation.
	for _, p := range []struct{ path, body string }{
		{"/v1/requests/abc/deny", `{"reason":"not today: scope too wide","operator":"ops@example"}`},
		{"/v1/requests/abc/approve", `{"operator":"ops","totp_code":"123456"}`},
	} {
		code, body, _ := e.do("POST", p.path, e.opOnly, p.body)
		if code == http.StatusBadRequest && strings.Contains(body, "ValidationError") {
			t.Errorf("%s: valid input refused: %s", p.path, body)
		}
	}
	for _, path := range []string{
		"/v1/secrets/alice-ns/k?purpose=ci%20deploy", "/v1/capabilities/list?purpose=*&namespace=*",
		"/v1/capabilities/list?purpose=ci&namespace=alice-ns",
	} {
		if code, body, _ := e.do("GET", path, e.alice, nil); code != 200 && code != 404 {
			t.Errorf("GET %s: %d (%s)", path, code, body)
		}
	}
}

func jsonStr(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `"` + "\xff" + `"`
	}
	return string(b)
}

// queryEscaper percent-encodes every byte (so invalid UTF-8 survives).
type queryEscaper struct{}

func (queryEscaper) escape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		b.WriteString("%" + strings.ToUpper(strconv.FormatInt(int64(s[i])+256, 16)[1:]))
	}
	return b.String()
}

// RGT-345: access control fails secure. A vault that cannot answer (closed
// mid-flight) yields a generic 5xx, never an allow; a panic in the handler
// does not let the request through.
func TestAccessControlFailsSecure(t *testing.T) {
	e := newAuthzEnv(t, false)
	captureLog(t)
	if err := e.stack.Vault.Close(); err != nil {
		t.Fatal(err)
	}
	code, body, _ := e.do("POST", "/v1/secrets/alice-ns/k/lease", e.aliceLease, map[string]any{})
	if code < 500 || strings.Contains(body, "ALICE-SECRET") {
		t.Errorf("closed vault: %d %s (must fail closed, no value)", code, body)
	}
	var m map[string]string
	_ = json.Unmarshal([]byte(body), &m)
	if !incidentIDRE.MatchString(m["incident_id"]) {
		t.Errorf("closed vault answer without incident id: %s", body)
	}
}

func nullStr() sql.NullString { return sql.NullString{} }

// RGT-256/257: the per-source authentication-failure limit is race-free: of
// N simultaneous bad requests from one address exactly `limit` get the 401
// and the rest the 429, never more 401s than the cap (run with -race).
func TestAuthFailureLimiterIsAtomicUnderConcurrency(t *testing.T) {
	e := newAuthzEnv(t, false) // limit 5 per minute
	const workers = 80
	var wg sync.WaitGroup
	var n401, n429, other atomic.Int64
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			rec := httptest.NewRecorder()
			e.h.ServeHTTP(rec, req("GET", "/v1/actions", "bad-"+strconv.Itoa(i), "10.9.9.9:1", nil))
			switch rec.Code {
			case 401:
				n401.Add(1)
			case 429:
				n429.Add(1)
			default:
				other.Add(1)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if n401.Load() != 5 || n429.Load() != workers-5 || other.Load() != 0 {
		t.Fatalf("401=%d 429=%d other=%d, want 5 / %d / 0", n401.Load(), n429.Load(), other.Load(), workers-5)
	}
}
