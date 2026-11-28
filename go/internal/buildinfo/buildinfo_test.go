package buildinfo

import (
	"runtime/debug"
	"testing"
)

// setLdflags installs ldflags-style values and a fake build-info reader for
// one test and restores everything afterwards.
func setLdflags(t *testing.T, v, c, d, dirtyVal string) {
	t.Helper()
	ov, oc, od, odirty := version, commit, date, dirty
	version, commit, date, dirty = v, c, d, dirtyVal
	t.Cleanup(func() { version, commit, date, dirty = ov, oc, od, odirty })
}

func setBuildInfo(t *testing.T, info *debug.BuildInfo) {
	t.Helper()
	orig := readBuildInfo
	readBuildInfo = func() *debug.BuildInfo { return info }
	t.Cleanup(func() { readBuildInfo = orig })
}

func vcs(kv ...string) []debug.BuildSetting {
	var out []debug.BuildSetting
	for i := 0; i+1 < len(kv); i += 2 {
		out = append(out, debug.BuildSetting{Key: kv[i], Value: kv[i+1]})
	}
	return out
}

func TestLdflagsWinOverBuildInfo(t *testing.T) {
	setLdflags(t, "1.2.3", "abc123", "2024-01-15T10:30:00Z", "true")
	setBuildInfo(t, &debug.BuildInfo{
		Main:     debug.Module{Version: "v9.9.9"},
		Settings: vcs("vcs.revision", "ffffff", "vcs.time", "1999-01-01T00:00:00Z", "vcs.modified", "false"),
	})
	if got := Version(); got != "1.2.3" {
		t.Errorf("Version = %q", got)
	}
	if got := Commit(); got != "abc123" {
		t.Errorf("Commit = %q", got)
	}
	if got := Date(); got != "2024-01-15T10:30:00Z" {
		t.Errorf("Date = %q", got)
	}
	if !Dirty() {
		t.Error("Dirty = false, want ldflags true to win over vcs.modified=false")
	}
	if got, want := String(), "1.2.3 (commit abc123, built 2024-01-15T10:30:00Z, dirty)"; got != want {
		t.Errorf("String = %q, want %q", got, want)
	}
}

func TestBuildInfoFallbackWhenLdflagsEmpty(t *testing.T) {
	setLdflags(t, "", "", "", "")
	setBuildInfo(t, &debug.BuildInfo{
		Main:     debug.Module{Version: "v0.4.0"},
		Settings: vcs("vcs.revision", "deadbeef", "vcs.time", "2026-11-28T00:00:00Z", "vcs.modified", "true"),
	})
	if got := Version(); got != "0.4.0" {
		t.Errorf("Version = %q", got)
	}
	if got := Commit(); got != "deadbeef" {
		t.Errorf("Commit = %q", got)
	}
	if got := Date(); got != "2026-11-28T00:00:00Z" {
		t.Errorf("Date = %q", got)
	}
	if !Dirty() {
		t.Error("Dirty = false, want true from vcs.modified")
	}
	if got, want := String(), "0.4.0 (commit deadbeef, built 2026-11-28T00:00:00Z, dirty)"; got != want {
		t.Errorf("String = %q, want %q", got, want)
	}
}

// The default of the dirty variable must be "unset", so that vcs.modified is
// read. (It used to default to "false", which made Dirty() ignore build info.)
func TestDirtyDefaultsToUnsetAndReadsVCSModified(t *testing.T) {
	if dirty != "" {
		t.Fatalf("package default dirty = %q, want \"\" (unset)", dirty)
	}
	for _, c := range []struct {
		name string
		info *debug.BuildInfo
		want bool
	}{
		{"modified true", &debug.BuildInfo{Settings: vcs("vcs.modified", "true")}, true},
		{"modified false", &debug.BuildInfo{Settings: vcs("vcs.modified", "false")}, false},
		{"modified absent", &debug.BuildInfo{Settings: vcs("vcs.revision", "x")}, false},
		{"modified garbage", &debug.BuildInfo{Settings: vcs("vcs.modified", "maybe")}, false},
		{"no build info", nil, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			setLdflags(t, "", "", "", "")
			setBuildInfo(t, c.info)
			if got := Dirty(); got != c.want {
				t.Errorf("Dirty = %v, want %v", got, c.want)
			}
		})
	}
}

func TestDirtyLdflagsValues(t *testing.T) {
	for _, c := range []struct {
		flag     string
		modified string
		want     bool
	}{
		{"true", "false", true},
		{"True", "false", true},
		{"false", "true", false},
		{"FALSE", "true", false},
		// Not a boolean: ignored, build info decides.
		{"garbage", "true", true},
		{"garbage", "false", false},
	} {
		setLdflags(t, "", "", "", c.flag)
		setBuildInfo(t, &debug.BuildInfo{Settings: vcs("vcs.modified", c.modified)})
		if got := Dirty(); got != c.want {
			t.Errorf("dirty=%q vcs.modified=%q: Dirty = %v, want %v", c.flag, c.modified, got, c.want)
		}
	}
}

func TestDefaultsWithoutAnyBuildInfo(t *testing.T) {
	setLdflags(t, "", "", "", "")
	setBuildInfo(t, nil)
	if Version() != "(devel)" || Commit() != "none" || Date() != "unknown" || Dirty() {
		t.Errorf("defaults = %q %q %q %v", Version(), Commit(), Date(), Dirty())
	}
	if got, want := String(), "(devel) (commit none, built unknown)"; got != want {
		t.Errorf("String = %q, want %q", got, want)
	}
}

func TestEmptyBuildInfoValuesFallBackToDefaults(t *testing.T) {
	setLdflags(t, "", "", "", "")
	// A plain `go build` outside a module cache: Main.Version is "" and the
	// vcs settings exist with empty values.
	setBuildInfo(t, &debug.BuildInfo{Settings: vcs("vcs.revision", "", "vcs.time", "")})
	if Version() != "(devel)" || Commit() != "none" || Date() != "unknown" {
		t.Errorf("got %q %q %q", Version(), Commit(), Date())
	}
}

func TestDevelMainVersionIsReportedAsIs(t *testing.T) {
	setLdflags(t, "", "", "", "")
	setBuildInfo(t, &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}})
	if got := Version(); got != "(devel)" {
		t.Errorf("Version = %q", got)
	}
}

func TestEachLdflagIsIndependent(t *testing.T) {
	setLdflags(t, "2.0.0", "", "", "")
	setBuildInfo(t, &debug.BuildInfo{
		Main:     debug.Module{Version: "v1.0.0"},
		Settings: vcs("vcs.revision", "cafe", "vcs.time", "t"),
	})
	if Version() != "2.0.0" || Commit() != "cafe" || Date() != "t" {
		t.Errorf("got %q %q %q", Version(), Commit(), Date())
	}
}

// The real seam (no fake) must not panic and must return something printable.
func TestRealReadBuildInfoSmoke(t *testing.T) {
	setLdflags(t, "", "", "", "")
	if Version() == "" || Commit() == "" || Date() == "" || String() == "" {
		t.Errorf("empty value: %q %q %q %q", Version(), Commit(), Date(), String())
	}
}

func TestReadBuildInfoReturnsNilWhenUnavailable(t *testing.T) {
	// The default reader maps ok=false to nil; under `go test` ok is true, so
	// only assert it never returns a non-nil info with an unusable shape.
	if info := readBuildInfo(); info != nil && info.GoVersion == "" {
		t.Errorf("build info without GoVersion: %+v", info)
	}
}

// A release build ({{.Version}}, no prefix) and `go install ...@v0.4.0`
// (Main.Version "v0.4.0") must read the same.
func TestVersionLeadingVIsNormalised(t *testing.T) {
	for _, c := range []struct{ ldflags, main, want string }{
		{"0.4.0", "", "0.4.0"},
		{"v0.4.0", "", "0.4.0"},
		{"", "v0.4.0", "0.4.0"},
		{"", "v1.2.3-rc.1+meta", "1.2.3-rc.1+meta"},
		{"", "(devel)", "(devel)"},
		{"dev", "", "dev"},
		{"vault-build", "", "vault-build"},
		{"v", "", "v"},
	} {
		setLdflags(t, c.ldflags, "", "", "")
		setBuildInfo(t, &debug.BuildInfo{Main: debug.Module{Version: c.main}})
		if got := Version(); got != c.want {
			t.Errorf("ldflags %q main %q: Version = %q, want %q", c.ldflags, c.main, got, c.want)
		}
	}
}
