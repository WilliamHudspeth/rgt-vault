package audit

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// Golden vectors in testdata/ are generated from the real Python code by
// testdata/gen_vectors.py. Go must agree with Python on every one.

type vectors struct {
	Sanitize []struct {
		In  string `json:"in"`
		Out string `json:"out"`
	} `json:"sanitize"`
	EntryHash []struct {
		Prev          string  `json:"prev"`
		Timestamp     string  `json:"timestamp"`
		Action        string  `json:"action"`
		SecretName    *string `json:"secret_name"`
		Details       string  `json:"details"`
		PolicyHash    string  `json:"policy_hash"`
		Expected      string  `json:"expected"`
		StoredAction  string  `json:"stored_action"`
		StoredDetails string  `json:"stored_details"`
	} `json:"entry_hash"`
	ISOTime []struct {
		UnixSec     int64  `json:"unix_sec"`
		Microsecond int    `json:"microsecond"`
		Expected    string `json:"expected"`
	} `json:"iso_time"`
}

type chainVector struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Rows        []Row  `json:"rows"`
	PyVerdict   bool   `json:"python_verdict"`
	PyPrefixes  []bool `json:"python_prefix_verdicts"`
	PyFirstBad  int    `json:"python_first_bad"`
}

func load(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func loadChains(t *testing.T) map[string]chainVector {
	t.Helper()
	var f struct {
		Chains []chainVector `json:"chains"`
	}
	load(t, "chains.json", &f)
	if len(f.Chains) < 15 {
		t.Fatalf("expected >=15 chains, got %d", len(f.Chains))
	}
	m := map[string]chainVector{}
	for _, c := range f.Chains {
		m[c.Name] = c
	}
	return m
}

func TestSanitizeVectors(t *testing.T) {
	var v vectors
	load(t, "vectors.json", &v)
	if len(v.Sanitize) == 0 {
		t.Fatal("no vectors")
	}
	for _, c := range v.Sanitize {
		if got := Sanitize(c.In); got != c.Out {
			t.Errorf("Sanitize(%q) = %q, want %q", c.In, got, c.Out)
		}
		if got := Sanitize(c.Out); got != c.Out {
			t.Errorf("Sanitize not idempotent for %q", c.In)
		}
	}
}

func TestEntryHashVectors(t *testing.T) {
	var v vectors
	load(t, "vectors.json", &v)
	if len(v.EntryHash) == 0 {
		t.Fatal("no vectors")
	}
	for i, c := range v.EntryHash {
		sn := ""
		if c.SecretName != nil {
			sn = *c.SecretName
		}
		if got := EntryHash(c.Prev, c.Timestamp, c.Action, sn, c.Details, c.PolicyHash); got != c.Expected {
			t.Errorf("case %d: EntryHash = %s, want %s", i, got, c.Expected)
		}
		// Next stores the sanitised forms Python stores.
		if got := Sanitize(c.Action); got != c.StoredAction {
			t.Errorf("case %d: stored action %q != %q", i, got, c.StoredAction)
		}
		if got := Sanitize(c.Details); got != c.StoredDetails {
			t.Errorf("case %d: stored details %q != %q", i, got, c.StoredDetails)
		}
	}
}

func TestPyISOTimeVectors(t *testing.T) {
	var v vectors
	load(t, "vectors.json", &v)
	if len(v.ISOTime) == 0 {
		t.Fatal("no vectors")
	}
	for _, c := range v.ISOTime {
		tm := time.Unix(c.UnixSec, int64(c.Microsecond)*1000)
		if got := PyISOTime(tm); got != c.Expected {
			t.Errorf("PyISOTime(%d,%dus) = %s, want %s", c.UnixSec, c.Microsecond, got, c.Expected)
		}
		// Sub-microsecond digits are truncated, as Python has none.
		if c.Microsecond < 999999 {
			tm2 := time.Unix(c.UnixSec, int64(c.Microsecond)*1000+999)
			if got := PyISOTime(tm2); got != c.Expected {
				t.Errorf("truncation: PyISOTime(%d,%dus+999ns) = %s, want %s", c.UnixSec, c.Microsecond, got, c.Expected)
			}
		}
	}
}

func TestPyISOTimeNonUTCZoneAndFormat(t *testing.T) {
	loc := time.FixedZone("X", 5*3600+1800)
	tm := time.Date(2026, 11, 26, 17, 30, 1, 0, loc)
	if got, want := PyISOTime(tm), "2026-11-26T12:00:01+00:00"; got != want {
		t.Errorf("got %s want %s", got, want)
	}
	tm = time.Date(2026, 1, 2, 3, 4, 5, 6000, time.UTC)
	if got, want := PyISOTime(tm), "2026-01-02T03:04:05.000006+00:00"; got != want {
		t.Errorf("got %s want %s", got, want)
	}
}

// Every chain and every prefix: Go verdict == real Python verdict, row by row.
func TestChainsMatchPython(t *testing.T) {
	for name, c := range loadChains(t) {
		t.Run(name, func(t *testing.T) {
			if got := Verify(c.Rows); got != c.PyVerdict {
				t.Errorf("Verify = %v, Python = %v (%s)", got, c.PyVerdict, c.Description)
			}
			if got := FirstInvalid(c.Rows); got != c.PyFirstBad {
				t.Errorf("FirstInvalid = %d, Python first bad = %d", got, c.PyFirstBad)
			}
			if len(c.PyPrefixes) != len(c.Rows) {
				t.Fatalf("vector has %d prefix verdicts for %d rows", len(c.PyPrefixes), len(c.Rows))
			}
			for k := range c.Rows {
				if got := Verify(c.Rows[:k+1]); got != c.PyPrefixes[k] {
					t.Errorf("prefix %d: Verify = %v, Python = %v", k, got, c.PyPrefixes[k])
				}
			}
		})
	}
}

func TestRealPythonChainIsValid(t *testing.T) {
	c := loadChains(t)["real_vault_manager"]
	if len(c.Rows) < 8 || !c.PyVerdict || !Verify(c.Rows) {
		t.Fatalf("real chain: rows=%d py=%v", len(c.Rows), c.PyVerdict)
	}
	// Sanity: the chain really contains injection-encoded and NULL-secret rows
	// plus agent_id values, i.e. it exercises the interesting paths.
	var sawEscaped, sawNullName, sawAgent bool
	for _, r := range c.Rows {
		sawEscaped = sawEscaped || strings.Contains(r.Details.orEmpty(), `\r\n`) || strings.Contains(r.Action.orEmpty(), `\n`)
		sawNullName = sawNullName || r.SecretName.null
		sawAgent = sawAgent || (r.AgentID.set && !r.AgentID.null)
	}
	if !sawEscaped || !sawNullName || !sawAgent {
		t.Errorf("real chain lacks coverage: escaped=%v nullname=%v agent=%v", sawEscaped, sawNullName, sawAgent)
	}
}

// Writing with Go (Next) over Python's chain extends it validly, and a Go-built
// chain from genesis verifies, using the same recomputation Python uses.
func TestNextExtendsPythonChain(t *testing.T) {
	c := loadChains(t)["real_vault_manager"]
	rows := append([]Row(nil), c.Rows...)
	prev := rows[len(rows)-1].EntryHash.orEmpty()
	for i := 0; i < 5; i++ {
		e := Next(prev, time.Date(2030, 1, 1, 0, 0, i, i*250000*1000, time.UTC), "GO\nACTION", "sec", "a\tb\r\nc", "ph")
		if i == 0 && e.Timestamp != "2030-01-01T00:00:00+00:00" {
			t.Fatalf("timestamp %q", e.Timestamp)
		}
		if e.Action != `GO\nACTION` || e.Details != `a\tb\r\nc` || e.PrevHash != prev {
			t.Fatalf("entry not stored sanitised: %+v", e)
		}
		rows = append(rows, Row{
			Timestamp: Str(e.Timestamp), Action: Str(e.Action), SecretName: Str(e.SecretName),
			Details: Str(e.Details), PolicyHash: Str(e.PolicyHash), EntryHash: Str(e.EntryHash), PrevHash: Str(e.PrevHash),
		})
		prev = e.EntryHash
	}
	if !Verify(rows) {
		t.Fatalf("Go-extended chain does not verify; first invalid=%d", FirstInvalid(rows))
	}
}

func TestGoBuiltChainFromGenesis(t *testing.T) {
	var rows []Row
	prev := ""
	for i := 0; i < 20; i++ {
		e := Next(prev, time.Unix(1700000000+int64(i), int64(i)*1000), "A", "n", "d", "")
		rows = append(rows, Row{
			Timestamp: Str(e.Timestamp), Action: Str(e.Action), SecretName: Str(e.SecretName),
			Details: Str(e.Details), PolicyHash: Str(e.PolicyHash), EntryHash: Str(e.EntryHash),
		})
		prev = e.EntryHash
	}
	if !Verify(rows) {
		t.Fatal("genesis chain should verify")
	}
	if i := FirstInvalid(rows); i != -1 {
		t.Fatalf("FirstInvalid = %d", i)
	}
}

// Mutating each hashed field of a middle row breaks the chain at that row;
// agent_id and the stored prev_hash column do not (known limitation, below).
func TestMutatingEachHashedFieldBreaksChain(t *testing.T) {
	base := loadChains(t)["real_vault_manager"].Rows
	mid := len(base) / 2
	mutations := map[string]func(r *Row){
		"timestamp":   func(r *Row) { r.Timestamp = Str(r.Timestamp.orEmpty() + "1") },
		"action":      func(r *Row) { r.Action = Str(r.Action.orEmpty() + "x") },
		"secret_name": func(r *Row) { r.SecretName = Str(r.SecretName.orEmpty() + "x") },
		"details":     func(r *Row) { r.Details = Str(r.Details.orEmpty() + "x") },
		"policy_hash": func(r *Row) { r.PolicyHash = Str(r.PolicyHash.orEmpty() + "x") },
		"entry_hash":  func(r *Row) { r.EntryHash = Str(strings.Repeat("0", 64)) },
		"details_to_null": func(r *Row) {
			r.Details = Null()
		},
	}
	for name, mut := range mutations {
		t.Run(name, func(t *testing.T) {
			rows := append([]Row(nil), base...)
			mut(&rows[mid])
			if Verify(rows) {
				t.Fatalf("mutating %s did not break the chain", name)
			}
			if got := FirstInvalid(rows); got != mid {
				t.Fatalf("FirstInvalid = %d, want %d", got, mid)
			}
		})
	}
	t.Run("delete_middle", func(t *testing.T) {
		rows := append(append([]Row(nil), base[:mid]...), base[mid+1:]...)
		if Verify(rows) {
			t.Fatal("deleting a middle row must break the chain")
		}
	})
	t.Run("reorder", func(t *testing.T) {
		rows := append([]Row(nil), base...)
		rows[mid], rows[mid+1] = rows[mid+1], rows[mid]
		if Verify(rows) {
			t.Fatal("reordering must break the chain")
		}
	})
	t.Run("insert_forged", func(t *testing.T) {
		forged := Row{Timestamp: Str("t"), Action: Str("FORGED"), EntryHash: Str(EntryHash(base[mid-1].EntryHash.orEmpty(), "t", "FORGED", "", "", ""))}
		// Forged row linked correctly but the NEXT row still hashes the old prev.
		rows := append(append(append([]Row(nil), base[:mid]...), forged), base[mid:]...)
		if Verify(rows) {
			t.Fatal("insertion must break the chain at the following row")
		}
	})
}

// KNOWN LIMITATION (N4 / RGT-416): agent_id is not part of the hash, so
// rewriting it on a stored row is NOT detected. This mirrors Python exactly
// (chain "tamper_agent_id_only" is Python-verified True). The fix is a keyed
// chain, which is an on-disk format change and out of scope for a faithful port.
// If this test ever fails, the hash input changed and byte-compat with Python
// (and with existing vaults) is gone.
func TestAgentIDMutationIsNotDetectedKnownLimitation(t *testing.T) {
	chains := loadChains(t)
	py := chains["tamper_agent_id_only"]
	if !py.PyVerdict || !Verify(py.Rows) {
		t.Fatal("Python-generated agent_id-only tamper must still verify")
	}
	rows := append([]Row(nil), chains["real_vault_manager"].Rows...)
	for i := range rows {
		rows[i].AgentID = Str("attacker")
	}
	if !Verify(rows) {
		t.Fatal("agent_id is not hashed; mutation must not break the chain (documents N4/RGT-416)")
	}
	// Likewise the stored prev_hash column is never read by the verifier.
	for i := range rows {
		rows[i].PrevHash = Str("f")
	}
	if !Verify(rows) {
		t.Fatal("stored prev_hash is not read by Verify (Python parity)")
	}
}

func TestNullVersusMissingQuirk(t *testing.T) {
	// The verifier hashes a present NULL as the text "None", a missing key as "".
	hashWith := func(details, policy string) string {
		return hashRaw("", "ts", "ACT", "", details, policy)
	}
	row := func(d, p Field, hash string) Row {
		return Row{Timestamp: Str("ts"), Action: Str("ACT"), Details: d, PolicyHash: p, EntryHash: Str(hash)}
	}
	cases := []struct {
		name string
		row  Row
		ok   bool
	}{
		{"null details/policy hashed as None", row(Null(), Null(), hashWith("None", "None")), true},
		{"null details/policy hashed as empty (the quirk)", row(Null(), Null(), hashWith("", "")), false},
		{"missing details/policy hashed as empty", row(Field{}, Field{}, hashWith("", "")), true},
		{"missing details/policy hashed as None", row(Field{}, Field{}, hashWith("None", "None")), false},
		{"null details only", row(Null(), Str(""), hashWith("None", "")), true},
		{"null policy only", row(Str(""), Null(), hashWith("", "None")), true},
		{"empty string is not null", row(Str(""), Str(""), hashWith("None", "None")), false},
		{"null action renders None", Row{Timestamp: Str("ts"), Action: Null(), EntryHash: Str(hashRaw("", "ts", "None", "", "", ""))}, true},
		{"null timestamp renders None", Row{Timestamp: Null(), Action: Str("ACT"), EntryHash: Str(hashRaw("", "None", "ACT", "", "", ""))}, true},
		{"missing action renders empty", Row{Timestamp: Str("ts"), EntryHash: Str(hashRaw("", "ts", "", "", "", ""))}, true},
		{"null secret_name renders empty", Row{Timestamp: Str("ts"), Action: Str("ACT"), SecretName: Null(), EntryHash: Str(hashRaw("", "ts", "ACT", "", "", ""))}, true},
	}
	for _, c := range cases {
		if got := Verify([]Row{c.row}); got != c.ok {
			t.Errorf("%s: Verify = %v, want %v", c.name, got, c.ok)
		}
	}
}

func TestVerifyDoesNotResanitise(t *testing.T) {
	// A row stored with a raw newline but hashed with the sanitised form (what the
	// writer would produce) does NOT verify: Python hashes stored bytes as-is.
	h := EntryHash("", "ts", "A\nB", "", "", "")
	if Verify([]Row{{Timestamp: Str("ts"), Action: Str("A\nB"), EntryHash: Str(h)}}) {
		t.Fatal("raw newline row must not verify against sanitised hash")
	}
	if !Verify([]Row{{Timestamp: Str("ts"), Action: Str(`A\nB`), EntryHash: Str(h)}}) {
		t.Fatal("stored (sanitised) action must verify")
	}
}

func TestVerifyEdgeCases(t *testing.T) {
	if !Verify(nil) || !Verify([]Row{}) {
		t.Fatal("empty chain is vacuously valid (Python parity)")
	}
	if FirstInvalid(nil) != -1 {
		t.Fatal("FirstInvalid(nil)")
	}
	// Missing / NULL / empty entry_hash never verifies.
	for _, h := range []Field{{}, Null(), Str("")} {
		if Verify([]Row{{Timestamp: Str("ts"), Action: Str("A"), EntryHash: h}}) {
			t.Errorf("entry_hash %+v must not verify", h)
		}
	}
	// Non-ASCII stored hash: Python raises TypeError; Go fails closed.
	if Verify([]Row{{Timestamp: Str("ts"), Action: Str("A"), EntryHash: Str("é")}}) {
		t.Fatal("non-ASCII hash must not verify")
	}
	// Wrong-length and wrong-case hashes do not verify.
	good := EntryHash("", "ts", "A", "", "", "")
	for _, h := range []string{good[:63], good + "0", strings.ToUpper(good)} {
		if Verify([]Row{{Timestamp: Str("ts"), Action: Str("A"), EntryHash: Str(h)}}) {
			t.Errorf("hash %q must not verify", h)
		}
	}
	// A broken first row is reported at index 0 and 2 for a break at row 2.
	e0 := Next("", time.Unix(1, 0), "A", "", "", "")
	e1 := Next(e0.EntryHash, time.Unix(2, 0), "B", "", "", "")
	mk := func(e Entry) Row {
		return Row{Timestamp: Str(e.Timestamp), Action: Str(e.Action), EntryHash: Str(e.EntryHash)}
	}
	rows := []Row{mk(e0), mk(e1), {Timestamp: Str("x"), Action: Str("C"), EntryHash: Str("bad")}}
	if got := FirstInvalid(rows); got != 2 {
		t.Fatalf("FirstInvalid = %d, want 2", got)
	}
}

func TestFieldHelpersAndJSON(t *testing.T) {
	if f := FromNullable("x", true); f != Str("x") {
		t.Errorf("FromNullable valid: %+v", f)
	}
	if f := FromNullable("ignored", false); f != Null() {
		t.Errorf("FromNullable null: %+v", f)
	}
	var r Row
	if err := json.Unmarshal([]byte(`{"action":"A","details":null,"secret_name":"s"}`), &r); err != nil {
		t.Fatal(err)
	}
	if r.Action != Str("A") || r.Details != Null() || r.SecretName != Str("s") || r.PolicyHash != (Field{}) {
		t.Errorf("JSON decode distinguished wrongly: %+v", r)
	}
	if err := json.Unmarshal([]byte(`{"action":5}`), &r); err == nil {
		t.Error("non-string field must be rejected")
	}
}

// TestWriteGoExtendedChain is a cross-implementation helper, not a normal test.
// With AUDIT_GO_CHAIN_OUT=<file> it extends Python's 1000-row chain with rows
// written by Go (Next) and writes the result as a chains JSON file, which
// `gen_vectors.py --verify <file>` then checks with the real Python verifier
// (RGT-151: "add a row in Go, verify in Python").
func TestWriteGoExtendedChain(t *testing.T) {
	out := os.Getenv("AUDIT_GO_CHAIN_OUT")
	if out == "" {
		t.Skip("set AUDIT_GO_CHAIN_OUT to write a Go-extended chain for the Python verifier")
	}
	py := loadChains(t)["real_1000_rows"]
	var raw struct {
		Chains []struct {
			Name string            `json:"name"`
			Rows []json.RawMessage `json:"rows"`
		} `json:"chains"`
	}
	load(t, "chains.json", &raw)
	var rows []map[string]any
	for _, c := range raw.Chains {
		if c.Name != "real_1000_rows" {
			continue
		}
		for _, r := range c.Rows {
			m := map[string]any{}
			if err := json.Unmarshal(r, &m); err != nil {
				t.Fatal(err)
			}
			rows = append(rows, m)
		}
	}
	if len(rows) != 1000 || len(py.Rows) != 1000 {
		t.Fatalf("expected 1000 rows, got %d/%d", len(rows), len(py.Rows))
	}
	prev := py.Rows[999].EntryHash.orEmpty()
	for i := 0; i < 25; i++ {
		e := Next(prev, time.Now().Add(time.Duration(i)*1500*time.Microsecond), "GO_WRITE\nX", "gosecret", "from go\t"+strings.Repeat("é", i), "ph0123456789abcd")
		rows = append(rows, map[string]any{
			"id": 1001 + i, "action": e.Action, "secret_name": e.SecretName, "timestamp": e.Timestamp,
			"details": e.Details, "prev_hash": e.PrevHash, "entry_hash": e.EntryHash, "policy_hash": e.PolicyHash, "agent_id": nil,
		})
		prev = e.EntryHash
	}
	b, err := json.Marshal(map[string]any{"chains": []any{map[string]any{"name": "python_1000_plus_25_from_go", "rows": rows}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
