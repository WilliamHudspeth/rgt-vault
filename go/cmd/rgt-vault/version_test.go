package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/buildinfo"
)

// runRoot executes the real root command with args and returns its stdout.
func runRoot(t *testing.T, args ...string) string {
	t.Helper()
	root := newRootCmd(strings.NewReader(""), io.Discard)
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		t.Fatalf("rgt-vault %v: %v (stderr %q)", args, err, errb.String())
	}
	return out.String()
}

func TestVersionAndDashDashVersionAreIdentical(t *testing.T) {
	sub := runRoot(t, "version")
	flag := runRoot(t, "--version")
	if sub != flag {
		t.Fatalf("`version` = %q, `--version` = %q; they must be identical", sub, flag)
	}
	want := "rgt-vault version " + buildinfo.String() + "\n"
	if sub != want {
		t.Fatalf("version output = %q, want %q", sub, want)
	}
	if !strings.Contains(sub, buildinfo.Version()) {
		t.Errorf("output %q lacks buildinfo.Version() %q", sub, buildinfo.Version())
	}
}

func TestVersionJSONIsValidAndMatchesBuildinfo(t *testing.T) {
	raw := runRoot(t, "version", "--json")
	if !json.Valid([]byte(raw)) {
		t.Fatalf("--json output is not valid JSON: %q", raw)
	}
	var got map[string]any
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Errorf("want exactly version, commit, date, dirty; got %v", got)
	}
	for k, want := range map[string]any{
		"version": buildinfo.Version(),
		"commit":  buildinfo.Commit(),
		"date":    buildinfo.Date(),
		"dirty":   buildinfo.Dirty(),
	} {
		if got[k] != want {
			t.Errorf("json %q = %v, want %v", k, got[k], want)
		}
	}
}

func TestVersionRejectsArguments(t *testing.T) {
	root := newRootCmd(strings.NewReader(""), io.Discard)
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"version", "extra"})
	if err := root.Execute(); err == nil {
		t.Fatal("version with a stray argument must fail")
	}
}
