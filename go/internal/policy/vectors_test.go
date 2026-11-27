package policy

import (
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"os"
	"testing"
)

// Vectors come from python/auth.py + stdlib fnmatch via
// testdata/gen_vectors.py. They are the reference; this test only reads them.

type vectors struct {
	Policies map[string]string `json:"policies"`
	Cases    []struct {
		Policy          string  `json:"policy"`
		Agent           string  `json:"agent"`
		Namespace       string  `json:"namespace"`
		Purpose         string  `json:"purpose"`
		Action          string  `json:"action"`
		Allowed         bool    `json:"allowed"`
		Reason          string  `json:"reason"`
		MatchedRuleJSON *string `json:"matched_rule_json"`
		Explain         string  `json:"explain"`
	} `json:"cases"`
	LeaseTTL []struct {
		Policy      string       `json:"policy"`
		Agent       string       `json:"agent"`
		Capability  string       `json:"capability"`
		TTL         *json.Number `json:"ttl"`
		PythonError *string      `json:"python_error"`
	} `json:"lease_ttl"`
	Hashes []struct {
		Policy string `json:"policy"`
		Hash   string `json:"hash"`
	} `json:"hashes"`
	LoadErrors []struct {
		Policy string `json:"policy"`
		YAML   string `json:"yaml"`
	} `json:"load_errors"`
	Raising []struct {
		Policy string `json:"policy"`
		YAML   string `json:"yaml"`
	} `json:"raising"`
	Fnmatch []struct {
		Value       string  `json:"value"`
		Pattern     string  `json:"pattern"`
		Match       *bool   `json:"match"`
		PythonError *string `json:"python_error"`
	} `json:"fnmatch"`
}

func loadVectors(t *testing.T) *vectors {
	t.Helper()
	b, err := os.ReadFile("testdata/policy_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return &v
}

func TestVectorsABAC(t *testing.T) {
	v := loadVectors(t)
	if len(v.Cases) < 60 {
		t.Fatalf("expected >=60 ABAC vectors, got %d", len(v.Cases))
	}
	engines := map[string]*Engine{}
	for name, y := range v.Policies {
		e, err := Parse(y)
		if err != nil {
			continue // policies Python loads but Go rejects are covered in TestVectorsRaising
		}
		engines[name] = e
	}
	for i, c := range v.Cases {
		e := engines[c.Policy]
		if e == nil {
			t.Fatalf("case %d: policy %q did not load", i, c.Policy)
		}
		d := e.Evaluate(c.Agent, c.Namespace, c.Purpose, c.Action)
		if d.Allowed != c.Allowed || d.Reason != c.Reason {
			t.Errorf("case %d (%s %q %q %q %q): got allowed=%v reason=%q, python allowed=%v reason=%q",
				i, c.Policy, c.Agent, c.Namespace, c.Purpose, c.Action, d.Allowed, d.Reason, c.Allowed, c.Reason)
		}
		if got := d.Explain(); got != c.Explain {
			t.Errorf("case %d (%s): explain mismatch\n got: %q\nwant: %q", i, c.Policy, got, c.Explain)
		}
		var gotRule *string
		if d.MatchedRule != nil {
			s := d.MatchedRule.PythonJSON()
			gotRule = &s
		}
		if (gotRule == nil) != (c.MatchedRuleJSON == nil) || (gotRule != nil && *gotRule != *c.MatchedRuleJSON) {
			t.Errorf("case %d (%s): matched rule json mismatch: got %v want %v", i, c.Policy, strOrNil(gotRule), strOrNil(c.MatchedRuleJSON))
		}
		if e.Explain(c.Agent, c.Namespace, c.Purpose, c.Action) != c.Explain {
			t.Errorf("case %d: Engine.Explain mismatch", i)
		}
		if sd := e.Simulate(c.Agent, c.Namespace, c.Purpose, c.Action); sd.Allowed != c.Allowed {
			t.Errorf("case %d: Simulate mismatch", i)
		}
	}
}

func strOrNil(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

func TestVectorsLeaseTTL(t *testing.T) {
	v := loadVectors(t)
	if len(v.LeaseTTL) < 20 {
		t.Fatalf("expected >=20 lease vectors, got %d", len(v.LeaseTTL))
	}
	for i, c := range v.LeaseTTL {
		e, err := Parse(v.Policies[c.Policy])
		if err != nil {
			t.Fatalf("policy %q: %v", c.Policy, err)
		}
		if c.PythonError != nil {
			continue
		}
		want, ok := new(big.Int).SetString(c.TTL.String(), 10)
		if !ok {
			t.Fatalf("lease %d: bad ttl %q", i, c.TTL)
		}
		// Go clamps arbitrary-precision Python ints to the platform int.
		if !want.IsInt64() {
			want = big.NewInt(math.MaxInt64)
		}
		if got := e.LeaseTTL(c.Agent, c.Capability); int64(got) != want.Int64() {
			t.Errorf("lease %d (%s %q %q): got %d, python %s", i, c.Policy, c.Agent, c.Capability, got, want)
		}
	}
}

func TestVectorsHash(t *testing.T) {
	v := loadVectors(t)
	for _, h := range v.Hashes {
		y := v.Policies[h.Policy]
		if got := HashPolicy(y); got != h.Hash {
			t.Errorf("%s: HashPolicy=%q want %q", h.Policy, got, h.Hash)
		}
		if e, err := Parse(y); err == nil && e.Hash() != h.Hash {
			t.Errorf("%s: Engine.Hash=%q want %q", h.Policy, e.Hash(), h.Hash)
		}
	}
}

func TestVectorsLoadErrors(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.LoadErrors {
		if _, err := Parse(c.YAML); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", c.Policy, err)
		}
	}
}

// Python loads these but raises on the first evaluation; Go fails closed at
// load time (documented deliberate difference).
func TestVectorsRaising(t *testing.T) {
	v := loadVectors(t)
	if len(v.Raising) == 0 {
		t.Fatal("no raising vectors")
	}
	for _, c := range v.Raising {
		if _, err := Parse(c.YAML); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", c.Policy, err)
		}
	}
}

func TestVectorsFnmatch(t *testing.T) {
	v := loadVectors(t)
	if len(v.Fnmatch) < 2000 {
		t.Fatalf("expected a large fnmatch corpus, got %d", len(v.Fnmatch))
	}
	for i, c := range v.Fnmatch {
		got, err := Match(c.Value, c.Pattern)
		if c.PythonError != nil {
			if err == nil {
				t.Errorf("%d: Match(%q,%q) python raised %s, Go did not", i, c.Value, c.Pattern, *c.PythonError)
			}
			continue
		}
		if err != nil {
			t.Errorf("%d: Match(%q,%q): unexpected error %v", i, c.Value, c.Pattern, err)
			continue
		}
		if got != *c.Match {
			t.Errorf("%d: Match(%q,%q)=%v python=%v", i, c.Value, c.Pattern, got, *c.Match)
		}
	}
}
