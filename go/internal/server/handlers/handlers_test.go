package handlers

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"rgt-vault-server/internal/actions"
	"rgt-vault-server/internal/approval"
	"rgt-vault-server/internal/capabilities"
)

func TestSchemaKeys(t *testing.T) {
	if got := schemaKeys(capabilities.ParamList{"b", "a"}); strings.Join(got, ",") != "b,a" {
		t.Errorf("ParamList = %v", got)
	}
	if got := schemaKeys(capabilities.JSONSchema{"type": "object", "properties": map[string]any{}}); strings.Join(got, ",") != "properties,type" {
		t.Errorf("JSONSchema = %v", got)
	}
	if got := schemaKeys(nil); got == nil || len(got) != 0 {
		t.Errorf("nil schema = %v", got)
	}
}

func TestActionBridge(t *testing.T) {
	if _, err := (ActionBridge{}).Action("echo"); !errors.Is(err, capabilities.ErrActionNotFound) {
		t.Errorf("nil registry: %v", err)
	}
	reg, err := actions.NewBuiltinRegistry(actions.Config{})
	if err != nil {
		t.Fatal(err)
	}
	b := ActionBridge{Registry: reg}
	_, err = b.Action("nope")
	if !errors.Is(err, capabilities.ErrActionNotFound) || !strings.Contains(err.Error(), "'echo'") {
		t.Errorf("unknown action: %v", err)
	}
	a, err := b.Action("echo")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.ValidateParams(map[string]any{"zzz": 1}); err == nil {
		t.Error("unknown param accepted")
	}
	out, err := a.Run(context.Background(), []byte("s3cr3t"), map[string]any{})
	if err != nil || strings.Contains(strings.ToLower(toString(out)), "s3cr3t") {
		t.Errorf("echo: %v %v", out, err)
	}
	if err := reg.Register(actions.Spec{Name: "boom", Fn: func(context.Context, []byte, map[string]any) (map[string]any, error) {
		return nil, errors.New("raw upstream text")
	}}); err != nil {
		t.Fatal(err)
	}
	a, _ = b.Action("boom")
	if _, err := a.Run(context.Background(), nil, nil); err == nil || strings.Contains(err.Error(), "raw upstream") {
		t.Errorf("failure not masked: %v", err)
	}
}

func toString(v any) string {
	if m, ok := v.(map[string]any); ok {
		var b strings.Builder
		for k, x := range m {
			b.WriteString(k)
			if s, ok := x.(string); ok {
				b.WriteString(s)
			}
		}
		return b.String()
	}
	return ""
}

func TestClassifyAndAppError(t *testing.T) {
	e := badRequest("x")
	if e.Error() != "x" {
		t.Error(e.Error())
	}
	if _, known := classify(errors.New("plain")); known {
		t.Error("plain error classified")
	}
	if ae, _ := classify(approval.ErrInvalidTOTP); ae.Code != 400 || ae.Type != "ApprovalError" {
		t.Errorf("approval: %+v", ae)
	}
	rec := httptest.NewRecorder()
	writeError(rec, nil, errors.New("secret detail"))
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "secret detail") {
		t.Errorf("unexpected error leaked: %d %s", rec.Code, rec.Body.String())
	}
}

// Defence in depth: an operator handler refuses a request whose context
// does not carry the operator scope, even if routing let it through.
func TestOperatorHandlersRequireOperatorScope(t *testing.T) {
	h := &Handlers{Broker: approval.NewBroker()}
	for _, ctx := range []context.Context{context.Background(), WithAuth(context.Background(), "id", ScopeAgent)} {
		rec := httptest.NewRecorder()
		h.ListRequests(rec, httptest.NewRequest("GET", "/v1/requests", nil).WithContext(ctx))
		if rec.Code != http.StatusForbidden {
			t.Errorf("scope %v: %d", ctx, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.ListRequests(rec, httptest.NewRequest("GET", "/v1/requests", nil).WithContext(WithAuth(context.Background(), "id", ScopeOperator)))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"requests":[]`) {
		t.Errorf("operator: %d %s", rec.Code, rec.Body.String())
	}
}

func TestNoActionsRegistry(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	h.ListActions(rec, httptest.NewRequest("GET", "/v1/actions", nil))
	if !strings.Contains(rec.Body.String(), `"actions":[]`) {
		t.Errorf("actions = %s", rec.Body.String())
	}
	if len(h.capabilityList()) != 0 || len(h.actionNames()) != 0 {
		t.Error("nil registries are not empty")
	}
}

func TestLogSafe(t *testing.T) {
	for in, want := range map[string]string{
		"plain/path":         "plain/path",
		"a\nINFO forged":     `a\nINFO forged`,
		"a\r\nb\tc":          `a\r\nb\tc`,
		"nul\x00esc\x1b[31m": `nul\x00esc\x1b[31m`,
		"del\x7f":            `del\x7f`,
		"c1\u0085next":       `c1\xc2\x85next`,
		"bad\xffutf8":        `bad\xffutf8`,
		"ünï🔐":               "ünï🔐",
		"":                   "",
	} {
		if got := LogSafe(in); got != want {
			t.Errorf("LogSafe(%q) = %q, want %q", in, got, want)
		}
	}
	long := LogSafe(strings.Repeat("é", 400))
	if len(long) > maxLogField+3 || !strings.HasSuffix(long, "...") || !utf8.ValidString(long) {
		t.Errorf("long value: len %d %q", len(long), long[len(long)-8:])
	}
	for _, s := range []string{"x\ny", strings.Repeat("\n", 300), "\x00\r"} {
		if strings.ContainsAny(LogSafe(s), "\r\n") {
			t.Errorf("LogSafe(%q) keeps a line break", s)
		}
	}
}

// A request-derived string reaches the error log only encoded.
func TestWriteErrorLogsEncodedValues(t *testing.T) {
	var buf strings.Builder
	log.SetOutput(&buf)
	defer log.SetOutput(io.Discard)
	req := httptest.NewRequest("GET", "/v1/x", nil)
	req.URL.Path = "/v1/x\nWARNING forged entry"
	writeError(httptest.NewRecorder(), req, errors.New("boom\r\nERROR forged"))
	writeError(httptest.NewRecorder(), req, badRequest("x"))
	out := buf.String()
	if strings.Count(out, "\n") != 2 || strings.Contains(out, "\nWARNING forged") || strings.Contains(out, "\nERROR forged") {
		t.Errorf("log lines forged:\n%s", out)
	}
	if !strings.Contains(out, `/v1/x\nWARNING forged entry`) || !strings.Contains(out, `boom\r\nERROR forged`) {
		t.Errorf("values not encoded:\n%s", out)
	}
}
