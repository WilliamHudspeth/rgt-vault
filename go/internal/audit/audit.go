// Package audit is the Go port of the rgt-vault audit hash chain. It is
// byte-compatible with the Python implementation (python/storage/sqlite.py
// log_audit/_append_audit_in_tx and python/vault.py verify_audit_chain), so a
// chain written by either line verifies in the other.
//
// Hash input (sha256, lowercase hex):
//
//	prev | timestamp | sanitize(action) | secretName-or-"" | sanitize(details) | policyHash
//
// agent_id is NOT part of the hash. That is a faithful port of a known Python
// limitation: changing agent_id on a stored row is not detected (tracked as
// N4 / RGT-416, "keyed chain"). Do not "fix" it here: it would be an on-disk
// format change.
//
// The package is stdlib-only and has no storage dependency; the SQLite store
// (batch G3) feeds it rows.
package audit

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// sanitizer encodes CR, LF and TAB so a log entry cannot forge extra log lines
// downstream (RGT-415). Port of _sanitize_log_field: only these three bytes are
// touched, in this representation, and nothing else (other control characters
// and backslashes pass through unchanged).
var sanitizer = strings.NewReplacer("\r", `\r`, "\n", `\n`, "\t", `\t`)

// Sanitize returns s with CR, LF and TAB replaced by the two-character
// sequences \r, \n and \t. It is idempotent.
func Sanitize(s string) string { return sanitizer.Replace(s) }

// EntryHash computes the chain hash for a new entry exactly as Python's
// log_audit does. action and details are sanitised here; secretName is used
// as-is ("" stands for a NULL secret_name); timestamp, prev and policyHash are
// used as-is. prev is "" for the first row (genesis).
func EntryHash(prev, timestamp, action, secretName, details, policyHash string) string {
	return hashRaw(prev, timestamp, Sanitize(action), secretName, Sanitize(details), policyHash)
}

func hashRaw(prev, timestamp, action, secretName, details, policyHash string) string {
	var b strings.Builder
	b.Grow(len(prev) + len(timestamp) + len(action) + len(secretName) + len(details) + len(policyHash) + 5)
	b.WriteString(prev)
	b.WriteByte('|')
	b.WriteString(timestamp)
	b.WriteByte('|')
	b.WriteString(action)
	b.WriteByte('|')
	b.WriteString(secretName)
	b.WriteByte('|')
	b.WriteString(details)
	b.WriteByte('|')
	b.WriteString(policyHash)
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// PyISOTime formats t like Python's datetime.now(timezone.utc).isoformat():
// "2006-01-02T15:04:05+00:00", with a ".ffffff" microsecond part only when the
// microsecond is non-zero. Sub-microsecond precision is truncated, as Python
// has none. Valid for years 1..9999 (Python's range).
func PyISOTime(t time.Time) string {
	t = t.UTC()
	s := t.Format("2006-01-02T15:04:05")
	if us := t.Nanosecond() / 1000; us != 0 {
		s += fmt.Sprintf(".%06d", us)
	}
	return s + "+00:00"
}

// Entry is a ready-to-store audit row produced by Next. Action and Details are
// already sanitised, which is what Python stores and hashes.
type Entry struct {
	Timestamp  string
	Action     string
	SecretName string // "" means NULL
	Details    string
	PrevHash   string
	EntryHash  string
	PolicyHash string
}

// Next builds the next entry on a chain whose current tail hash is prev ("" for
// an empty chain), stamping it with t. Callers insert Action/Details as stored.
func Next(prev string, t time.Time, action, secretName, details, policyHash string) Entry {
	ts := PyISOTime(t)
	sa, sd := Sanitize(action), Sanitize(details)
	return Entry{
		Timestamp:  ts,
		Action:     sa,
		SecretName: secretName,
		Details:    sd,
		PrevHash:   prev,
		EntryHash:  hashRaw(prev, ts, sa, secretName, sd, policyHash),
		PolicyHash: policyHash,
	}
}

// Field is a nullable column value that also remembers whether the key was
// present at all. Python's verifier distinguishes the two: dict.get(k, "")
// yields "" for a missing key but None for a present NULL, and f-string
// interpolation then renders the literal text "None". Field reproduces that.
//
// The zero value is a MISSING key. Use Str for a value and Null for SQL NULL.
type Field struct {
	set  bool
	null bool
	v    string
}

// Str returns a present, non-NULL field.
func Str(s string) Field { return Field{set: true, v: s} }

// Null returns a present field whose value is SQL NULL.
func Null() Field { return Field{set: true, null: true} }

// FromNullable converts a database/sql-style (value, valid) pair into a Field.
func FromNullable(s string, valid bool) Field {
	if !valid {
		return Null()
	}
	return Str(s)
}

// UnmarshalJSON accepts a string or null. It is only invoked when the key is
// present in the JSON object, so an absent key stays the zero (missing) Field.
func (f *Field) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*f = Null()
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("audit: field must be a string or null: %w", err)
	}
	*f = Str(s)
	return nil
}

// render is the f-string view used by the verifier for action, timestamp,
// details and policy_hash: missing -> "", NULL -> "None", else the value.
func (f Field) render() string {
	switch {
	case !f.set:
		return ""
	case f.null:
		return "None"
	default:
		return f.v
	}
}

// orEmpty is Python's `entry.get(k) or ""`: missing, NULL and "" are all "".
func (f Field) orEmpty() string {
	if !f.set || f.null {
		return ""
	}
	return f.v
}

// Row is one stored audit_logs row as the verifier sees it. PrevHash and
// AgentID are carried for completeness but, as in Python, are never read by
// Verify (the chain is walked via the stored EntryHash, not PrevHash).
type Row struct {
	Timestamp  Field `json:"timestamp"`
	Action     Field `json:"action"`
	SecretName Field `json:"secret_name"`
	Details    Field `json:"details"`
	PolicyHash Field `json:"policy_hash"`
	EntryHash  Field `json:"entry_hash"`
	PrevHash   Field `json:"prev_hash"`
	AgentID    Field `json:"agent_id"`
}

// Verify reports whether rows (oldest first) form an intact chain. It is the
// port of VaultManager.verify_audit_chain, including its quirks:
//
//   - an empty slice verifies (vacuously true);
//   - the first row's prev is "" (genesis); every later row's prev is the
//     STORED entry_hash of the previous row (NULL/missing treated as "");
//   - stored values are hashed exactly as stored; nothing is re-sanitised;
//   - a present-NULL timestamp, action, details or policy_hash renders as the
//     literal "None", while a missing key renders ""; a NULL/missing
//     secret_name renders "";
//   - the stored prev_hash column and agent_id are not checked;
//   - tail truncation and whole-chain replacement are not detectable.
//
// The hash comparison is constant-time. Python's hmac.compare_digest raises
// TypeError on a non-ASCII stored hash; Go returns false (fail closed).
func Verify(rows []Row) bool { return FirstInvalid(rows) < 0 }

// FirstInvalid returns the index of the first row whose stored entry_hash does
// not match the recomputed one, or -1 if the whole chain verifies.
func FirstInvalid(rows []Row) int {
	prev := ""
	for i, r := range rows {
		want := hashRaw(prev, r.Timestamp.render(), r.Action.render(),
			r.SecretName.orEmpty(), r.Details.render(), r.PolicyHash.render())
		got := r.EntryHash.orEmpty()
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			return i
		}
		prev = got
	}
	return -1
}
