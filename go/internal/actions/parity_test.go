package actions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// The vectors in testdata/vectors.json were generated from the real
// python/server/actions.py by testdata/gen_vectors.py (Python 3.12, DNS faked).
// Go must reach the same accept/reject verdict except where it deliberately
// hardens; every such case is listed in deviations_test.go with its reason and
// is asserted in BOTH directions (Python's verdict differs, Go's is the
// documented one), so a deviation can neither hide a regression nor go stale.

type pyVectors struct {
	Python  string              `json:"python"`
	FakeDNS map[string][]string `json:"fake_dns"`
	URLs    []struct {
		ID           string `json:"id"`
		URL          string `json:"url"`
		AllowPrivate bool   `json:"allow_private"`
		Validation   string `json:"validation"`
		E2E          string `json:"e2e"`
	} `json:"urls"`
	Headers []struct {
		ID      string            `json:"id"`
		Headers any               `json:"headers"`
		Verdict string            `json:"verdict"`
		Out     map[string]string `json:"out"`
	} `json:"headers"`
	Actions []struct {
		ID           string         `json:"id"`
		Action       string         `json:"action"`
		Params       map[string]any `json:"params"`
		AllowPrivate bool           `json:"allow_private"`
		Verdict      string         `json:"verdict"`
		Stage        string         `json:"stage"`
		Request      *struct {
			Method  string            `json:"method"`
			URL     string            `json:"url"`
			Headers map[string]string `json:"headers"`
			Data    *string           `json:"data"`
		} `json:"request"`
		Result map[string]any `json:"result"`
	} `json:"actions"`
}

func loadVectors(t testing.TB) *pyVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // keep 5 vs 5.0 distinguishable, like Python
	var v pyVectors
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	if len(v.URLs) < 300 || len(v.Headers) < 40 || len(v.Actions) < 100 {
		t.Fatalf("vector file looks truncated: %d/%d/%d", len(v.URLs), len(v.Headers), len(v.Actions))
	}
	return &v
}

// fakeResolver answers from the same table the Python generator used.
type fakeResolver struct {
	table map[string][]string
	calls atomic.Int64
}

func (f *fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	f.calls.Add(1)
	ips, ok := f.table[strings.ToLower(strings.TrimSuffix(host, "."))]
	if !ok {
		return nil, errors.New("no such host")
	}
	var out []net.IPAddr
	for _, s := range ips {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

var errReached = errors.New("reached dial")

// reachDial returns a registry whose connect step records that validation
// passed and the dial was attempted, then fails.
func reachDial(t testing.TB, cfg Config, table map[string][]string) (*Registry, *atomic.Int64) {
	t.Helper()
	var reached atomic.Int64
	cfg.Resolver = &fakeResolver{table: table}
	cfg.DialFunc = func(_ context.Context, _, _ string) (net.Conn, error) {
		reached.Add(1)
		return nil, errReached
	}
	reg, err := NewBuiltinRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return reg, &reached
}

// short truncates long vector values in failure messages.
func short(s string) string {
	if len(s) > 80 {
		return s[:80] + "...(" + strconv.Itoa(len(s)) + " bytes)"
	}
	return s
}

func verdict(b bool) string {
	if b {
		return "accept"
	}
	return "reject"
}

func TestParityURLs(t *testing.T) {
	v := loadVectors(t)
	seenDev := map[string]bool{}
	for _, r := range v.URLs {
		reg, reached := reachDial(t, Config{AllowPrivateNetwork: r.AllowPrivate, AllowInsecureHTTP: true}, v.FakeDNS)
		_, _ = reg.Execute(context.Background(), "http_get_with_auth", []byte("tok"), map[string]any{"url": r.URL})
		got := verdict(reached.Load() > 0)
		want := r.E2E
		if dev, ok := urlDeviations[r.ID]; ok {
			seenDev[r.ID] = true
			if want == dev.goVerdict {
				t.Errorf("%s %q: deviation listed but Python already gives %s (%s)", r.ID, r.URL, want, dev.reason)
			}
			want = dev.goVerdict
		}
		if os.Getenv("DUMP_DEV") != "" && got != r.E2E {
			fmt.Printf("URL|%s|%v|py=%s|go=%s|%q\n", r.ID, r.AllowPrivate, r.E2E, got, short(r.URL))
		}
		if got != want {
			t.Errorf("%s allow_private=%v url=%q: Go=%s want=%s (python validation=%s e2e=%s)", r.ID, r.AllowPrivate, short(r.URL), got, want, r.Validation, r.E2E)
		}
	}
	for id := range urlDeviations {
		if !seenDev[id] {
			t.Errorf("deviation %s does not match any vector", id)
		}
	}
}

func TestParityHeaders(t *testing.T) {
	v := loadVectors(t)
	seenDev := map[string]bool{}
	for _, r := range v.Headers {
		out, err := ValidateHeaders(r.Headers, nil)
		got := verdict(err == nil)
		want := r.Verdict
		if dev, ok := headerDeviations[r.ID]; ok {
			seenDev[r.ID] = true
			if want == dev.goVerdict {
				t.Errorf("%s: deviation listed but Python already gives %s", r.ID, want)
			}
			want = dev.goVerdict
		}
		if os.Getenv("DUMP_DEV") != "" && got != r.Verdict {
			fmt.Printf("HDR|%s|py=%s|go=%s\n", r.ID, r.Verdict, got)
		}
		if got != want {
			t.Errorf("%s: Go=%s want=%s (python=%s) headers=%v err=%v", r.ID, got, want, r.Verdict, r.Headers, err)
			continue
		}
		if got == "accept" && want == r.Verdict {
			wantOut := map[string]string{}
			for k, val := range r.Out {
				wantOut[textproto.CanonicalMIMEHeaderKey(k)] = val
			}
			if !reflect.DeepEqual(out, wantOut) {
				t.Errorf("%s: sanitised headers differ: Go=%v python=%v", r.ID, out, wantOut)
			}
		}
	}
	for id := range headerDeviations {
		if !seenDev[id] {
			t.Errorf("header deviation %s does not match any vector", id)
		}
	}
}

func TestParityActions(t *testing.T) {
	v := loadVectors(t)
	seenDev := map[string]bool{}
	for _, r := range v.Actions {
		reg, reached := reachDial(t, Config{AllowPrivateNetwork: r.AllowPrivate, AllowInsecureHTTP: true}, v.FakeDNS)
		out, err := reg.Execute(context.Background(), r.Action, []byte("SECRET-TOKEN"), r.Params)
		got := "reject"
		if err == nil || reached.Load() > 0 {
			got = "accept"
		}
		want := r.Verdict
		if dev, ok := actionDeviations[r.ID]; ok {
			seenDev[r.ID] = true
			if want == dev.goVerdict {
				t.Errorf("%s: deviation listed but Python already gives %s", r.ID, want)
			}
			want = dev.goVerdict
		}
		if os.Getenv("DUMP_DEV") != "" && got != r.Verdict {
			fmt.Printf("ACT|%s|py=%s|go=%s\n", r.ID, r.Verdict, got)
		}
		if got != want {
			t.Errorf("%s (%s, private=%v) params=%v: Go=%s want=%s (python=%s stage=%s) err=%v",
				r.ID, r.Action, r.AllowPrivate, r.Params, got, want, r.Verdict, r.Stage, err)
			continue
		}
		if got != "accept" || want != r.Verdict {
			continue
		}
		if r.Action == "echo" {
			wantRes := map[string]any{}
			for k, val := range r.Result {
				wantRes[k] = val
			}
			if !reflect.DeepEqual(normalizeJSON(out), normalizeJSON(wantRes)) {
				t.Errorf("%s: echo result differs: Go=%v python=%v", r.ID, out, wantRes)
			}
			continue
		}
		// Compare the request that would be sent.
		b, err := newBuiltins(Config{AllowPrivateNetwork: r.AllowPrivate, AllowInsecureHTTP: true})
		if err != nil {
			t.Fatal(err)
		}
		var o *outReq
		switch r.Action {
		case "openai_chat":
			o, err = b.planOpenAI(r.Params)
		case "http_get_with_auth":
			o, err = b.planGet(r.Params)
		case "http_post_with_auth":
			o, err = b.planPost(r.Params)
		}
		if err != nil || o == nil || r.Request == nil {
			t.Errorf("%s: cannot compare request (err=%v)", r.ID, err)
			continue
		}
		if o.method != r.Request.Method {
			t.Errorf("%s: method %s != %s", r.ID, o.method, r.Request.Method)
		}
		if o.url != r.Request.URL {
			t.Errorf("%s: url %s != %s", r.ID, o.url, r.Request.URL)
		}
		gotH := map[string]string{}
		for k, val := range o.headers {
			gotH[strings.ToLower(k)] = val
		}
		wantH := map[string]string{}
		for k, val := range r.Request.Headers {
			if k == "authorization" {
				continue
			}
			wantH[k] = val
		}
		if !reflect.DeepEqual(gotH, wantH) {
			t.Errorf("%s: headers %v != %v", r.ID, gotH, wantH)
		}
		wantData := ""
		if r.Request.Data != nil {
			wantData = *r.Request.Data
		}
		if !sameBody(string(o.body), wantData) {
			t.Errorf("%s: body %q != %q", r.ID, o.body, wantData)
		}
	}
	for id := range actionDeviations {
		if !seenDev[id] {
			t.Errorf("action deviation %s does not match any vector", id)
		}
	}
}

func normalizeJSON(m map[string]any) any {
	b, _ := json.Marshal(m)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

func sameBody(a, b string) bool {
	if a == b {
		return true
	}
	var ja, jb any
	if json.Unmarshal([]byte(a), &ja) == nil && json.Unmarshal([]byte(b), &jb) == nil {
		return reflect.DeepEqual(ja, jb)
	}
	return false
}
