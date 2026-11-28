package honeycap

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"rgt-vault-server/internal/approval"
	"rgt-vault-server/internal/vault"
)

type recorder struct {
	mu     sync.Mutex
	events []approval.Event
}

func (r *recorder) Notify(_ context.Context, e approval.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recorder) all() []approval.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]approval.Event(nil), r.events...)
}

func TestDefaultNamesValid(t *testing.T) {
	if len(DefaultNames) < 3 {
		t.Fatalf("RGT-30 acceptance: at least 3 default honey capabilities, have %d", len(DefaultNames))
	}
	s := Default()
	for _, n := range DefaultNames {
		if !validName(n) || !s.IsHoney(n) {
			t.Errorf("default %q not active", n)
		}
	}
	if got := len(s.Names()); got != len(DefaultNames) {
		t.Fatalf("Names() = %d entries", got)
	}
	if !strings.Contains(strings.Join(s.Names(), ","), "aws.admin.full") {
		t.Fatal("the issue's example name must be a default")
	}
}

func TestIsHoneyNormalization(t *testing.T) {
	s := Default()
	for _, n := range []string{"aws.admin.full", "AWS.Admin.FULL", "  aws.admin.full\t"} {
		if !s.IsHoney(n) {
			t.Errorf("%q should trip", n)
		}
	}
	for _, n := range []string{"", "aws.admin", "aws.admin.full2", "secrets.echo", "secrets.use", "aws.admin.full.x"} {
		if s.IsHoney(n) {
			t.Errorf("%q must not trip", n)
		}
	}
}

func TestNewValidation(t *testing.T) {
	s, err := New([]string{"payments.wire.unrestricted", "AWS.ADMIN.FULL", "k8s:cluster/admin"})
	if err != nil {
		t.Fatal(err)
	}
	if !s.IsHoney("payments.wire.unrestricted") || !s.IsHoney("k8s:cluster/admin") {
		t.Fatal("extra names")
	}
	if len(s.Names()) != len(DefaultNames)+2 {
		t.Fatalf("duplicate not merged: %v", s.Names())
	}
	for _, bad := range []string{"", "has space", strings.Repeat("a", MaxNameLen+1), "x\ny", "ünïcode", "a;b"} {
		if _, err := New([]string{bad}); !errors.Is(err, ErrConfig) {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
	if _, err := New([]string{strings.Repeat("a", MaxNameLen)}); err != nil {
		t.Fatalf("max length: %v", err)
	}
}

func TestFromPolicyYAML(t *testing.T) {
	for _, c := range []struct {
		name, yaml string
		extra      []string
		wantErr    bool
	}{
		{"empty", "", nil, false},
		{"bare list", "- {agent: '*', effect: allow}\n", nil, false},
		{"no key", "rules: []\n", nil, false},
		{"null", "honey_capabilities:\nrules: []\n", nil, false},
		{"list", "honey_capabilities:\n  - payments.wire.unrestricted\n  - hr.payroll.export\nrules: []\n",
			[]string{"payments.wire.unrestricted", "hr.payroll.export"}, false},
		{"flow", "{honey_capabilities: [ci.deploy.prod], rules: []}", []string{"ci.deploy.prod"}, false},
		{"bad yaml left to the policy engine", "rules: [\n", nil, false},
		{"scalar", "honey_capabilities: aws.x\n", nil, true},
		{"mapping", "honey_capabilities: {a: b}\n", nil, true},
		{"int entry", "honey_capabilities: [1]\n", nil, true},
		{"nested", "honey_capabilities: [[a]]\n", nil, true},
		{"bad name", "honey_capabilities: ['a b']\n", nil, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, err := FromPolicyYAML(c.yaml)
			if c.wantErr {
				if !errors.Is(err, ErrConfig) {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(s.Names()) != len(DefaultNames)+len(c.extra) {
				t.Fatalf("names = %v", s.Names())
			}
			for _, n := range append(c.extra, DefaultNames...) {
				if !s.IsHoney(n) {
					t.Errorf("%q missing", n)
				}
			}
		})
	}
}

func TestTrippedEvent(t *testing.T) {
	rec := &recorder{}
	at := time.Unix(1_900_000_000, 0)
	s := Default(WithNotifier(rec), WithClock(func() time.Time { return at }))
	s.Tripped(context.Background(), vault.HoneyProbe{Agent: "mallory", Capability: "AWS.admin.full", Version: 3,
		Source: "capability.execute", TokenPresented: true, PayloadKeys: 2})
	ev := rec.all()
	if len(ev) != 1 || s.Trips() != 1 {
		t.Fatalf("events = %v, trips = %d", ev, s.Trips())
	}
	e := ev[0]
	if e.Kind != approval.EventHoneyCapability || string(e.Kind) != Event || Event != "HONEY_CAPABILITY_TRIGGERED" {
		t.Fatalf("kind = %q", e.Kind)
	}
	if !e.Kind.Critical() {
		t.Fatal("a honey probe must be a Critical event (webhook keeps capacity for it)")
	}
	if e.Agent != "mallory" || !e.Time.Equal(at) {
		t.Fatalf("event = %+v", e)
	}
	want := `honey capability "AWS.admin.full" probed via capability.execute (version 3, token presented: true)`
	if e.Detail != want {
		t.Fatalf("detail = %q", e.Detail)
	}
}

func TestTrippedClipsAndQuotes(t *testing.T) {
	rec := &recorder{}
	s := Default(WithNotifier(rec))
	long := strings.Repeat("é", 200) + "\nINJECTED"
	s.Tripped(context.Background(), vault.HoneyProbe{Agent: strings.Repeat("a", 300), Capability: long})
	e := rec.all()[0]
	if strings.Contains(e.Detail, "\n") || strings.Contains(e.Detail, "INJECTED") {
		t.Fatalf("detail not clipped/quoted: %q", e.Detail)
	}
	if len(e.Agent) > maxDetailName+3 || !strings.HasSuffix(e.Agent, "...") {
		t.Fatalf("agent not clipped: %d", len(e.Agent))
	}
	if c := clip(strings.Repeat("é", 200)); !strings.HasSuffix(c, "...") || strings.ContainsRune(c, '�') ||
		len(c) > maxDetailName+3 {
		t.Fatalf("clip broke a rune: %q", c)
	}
}

func TestTrippedDefaultNotifierLogs(t *testing.T) {
	var buf bytes.Buffer
	old, flags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(old); log.SetFlags(flags) })
	s := Default(WithNotifier(nil)) // nil keeps the LogNotifier default
	s.Tripped(context.Background(), vault.HoneyProbe{Agent: "m", Capability: "aws.admin.full", Source: "capability.execute"})
	if !strings.Contains(buf.String(), "HONEY_CAPABILITY_TRIGGERED") {
		t.Fatalf("no log line: %q", buf.String())
	}
}

func TestTrippedContainsNotifierPanic(t *testing.T) {
	s := Default(WithNotifier(approval.NotifierFunc(func(context.Context, approval.Event) { panic("boom") })))
	s.Tripped(context.Background(), vault.HoneyProbe{Capability: "aws.admin.full"})
	if s.Trips() != 1 {
		t.Fatal("trip not counted")
	}
}
