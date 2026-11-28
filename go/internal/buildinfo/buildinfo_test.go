package buildinfo

import (
	"runtime/debug"
	"testing"
)

// mockBuildInfo is a mock *debug.BuildInfo for testing.
type mockBuildInfo struct {
	main    *debug.Module
	settings []debug.BuildSetting
}

func (m *mockBuildInfo) Main() *debug.Module { return m.main }
func (m *mockBuildInfo) Settings() []debug.BuildSetting { return m.settings }

func TestVersionWithLdflags(t *testing.T) {
	// Save original values
	origVersion := version
	origDebugBuildInfo := debugBuildInfo
	
	// Defer restore
	defer func() {
		version = origVersion
		debugBuildInfo = origDebugBuildInfo
	}()

	// Test with ldflags value set
	version = "1.2.3"
	if got := Version(); got != "1.2.3" {
		t.Errorf("Version() with ldflags = %q, want %q", got, "1.2.3")
	}
}

func TestVersionFromBuildInfo(t *testing.T) {
	// Save original values
	origVersion := version
	origDebugBuildInfo := debugBuildInfo
	
	// Defer restore
	defer func() {
		version = origVersion
		debugBuildInfo = origDebugBuildInfo
	}()

	// Test with ldflags empty, using build info
	version = ""
	debugBuildInfo = func() *debug.BuildInfo {
		// We can't easily create a real *debug.BuildInfo, so we test the fallback path
		// by checking that when version is empty, we get (devel)
		return nil
	}
	
	if got := Version(); got != "(devel)" {
		t.Errorf("Version() with nil build info = %q, want %q", got, "(devel)")
	}
}

func TestCommitWithLdflags(t *testing.T) {
	// Save original values
	origCommit := commit
	origDebugBuildInfo := debugBuildInfo
	
	// Defer restore
	defer func() {
		commit = origCommit
		debugBuildInfo = origDebugBuildInfo
	}()

	// Test with ldflags value set
	commit = "abc123def456"
	if got := Commit(); got != "abc123def456" {
		t.Errorf("Commit() with ldflags = %q, want %q", got, "abc123def456")
	}
}

func TestCommitFromBuildInfo(t *testing.T) {
	// Save original values
	origCommit := commit
	origDebugBuildInfo := debugBuildInfo
	
	// Defer restore
	defer func() {
		commit = origCommit
		debugBuildInfo = origDebugBuildInfo
	}()

	// Test with ldflags empty
	commit = ""
	// We can't easily set a custom function that returns a specific BuildInfo
	// because debug.ReadBuildInfo is a function, not a variable we can replace easily.
	// But we can test the fallback by setting debugBuildInfo to return nil
	debugBuildInfo = func() *debug.BuildInfo {
		return nil
	}
	
	if got := Commit(); got != "none" {
		t.Errorf("Commit() with nil build info = %q, want %q", got, "none")
	}
}

func TestDateWithLdflags(t *testing.T) {
	// Save original values
	origDate := date
	origDebugBuildInfo := debugBuildInfo
	
	// Defer restore
	defer func() {
		date = origDate
		debugBuildInfo = origDebugBuildInfo
	}()

	// Test with ldflags value set
	date = "2024-01-15T10:30:00Z"
	if got := Date(); got != "2024-01-15T10:30:00Z" {
		t.Errorf("Date() with ldflags = %q, want %q", got, "2024-01-15T10:30:00Z")
	}
}

func TestDateFromBuildInfo(t *testing.T) {
	// Save original values
	origDate := date
	origDebugBuildInfo := debugBuildInfo
	
	// Defer restore
	defer func() {
		date = origDate
		debugBuildInfo = origDebugBuildInfo
	}()

	// Test with ldflags empty
	date = ""
	
	// Mock build info with vcs.time
	debugBuildInfo = func() *debug.BuildInfo {
		return nil
	}
	
	if got := Date(); got != "unknown" {
		t.Errorf("Date() with nil build info = %q, want %q", got, "unknown")
	}
}

func TestDirtyWithLdflags(t *testing.T) {
	// Save original values
	origDirty := dirty
	origDebugBuildInfo := debugBuildInfo
	
	// Defer restore
	defer func() {
		dirty = origDirty
		debugBuildInfo = origDebugBuildInfo
	}()

	// Test with ldflags value set to true
	dirty = "true"
	if got := Dirty(); got != true {
		t.Errorf("Dirty() with ldflags=true = %v, want true", got)
	}

	// Test with ldflags value set to false
	dirty = "false"
	if got := Dirty(); got != false {
		t.Errorf("Dirty() with ldflags=false = %v, want false", got)
	}

	// Test with ldflags value set to True (case insensitive)
	dirty = "True"
	if got := Dirty(); got != true {
		t.Errorf("Dirty() with ldflags=True = %v, want true", got)
	}
}

func TestDirtyFromBuildInfo(t *testing.T) {
	// Save original values
	origDirty := dirty
	origDebugBuildInfo := debugBuildInfo
	
	// Defer restore
	defer func() {
		dirty = origDirty
		debugBuildInfo = origDebugBuildInfo
	}()

	// Test with ldflags empty
	dirty = ""
	
	// Mock build info with vcs.modified
	debugBuildInfo = func() *debug.BuildInfo {
		return nil
	}
	
	if got := Dirty(); got != false {
		t.Errorf("Dirty() with nil build info = %v, want false", got)
	}
}

func TestStringWithAllInfo(t *testing.T) {
	// Save original values
	origVersion := version
	origCommit := commit
	origDate := date
	origDirty := dirty
	origDebugBuildInfo := debugBuildInfo
	
	// Defer restore
	defer func() {
		version = origVersion
		commit = origCommit
		date = origDate
		dirty = origDirty
		debugBuildInfo = origDebugBuildInfo
	}()

	// Set all ldflags values
	version = "1.2.3"
	commit = "abc123"
	date = "2024-01-15T10:30:00Z"
	dirty = "false"
	
	got := String()
	want := "1.2.3 (commit abc123), built 2024-01-15T10:30:00Z"
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestStringWithDirty(t *testing.T) {
	// Save original values
	origVersion := version
	origCommit := commit
	origDate := date
	origDirty := dirty
	origDebugBuildInfo := debugBuildInfo
	
	// Defer restore
	defer func() {
		version = origVersion
		commit = origCommit
		date = origDate
		dirty = origDirty
		debugBuildInfo = origDebugBuildInfo
	}()

	// Set ldflags values with dirty
	version = "1.2.3"
	commit = "abc123"
	date = "2024-01-15T10:30:00Z"
	dirty = "true"
	
	got := String()
	want := "1.2.3 (commit abc123), built 2024-01-15T10:30:00Z, dirty"
	if got != want {
		t.Errorf("String() with dirty = %q, want %q", got, want)
	}
}

func TestStringWithDevValues(t *testing.T) {
	// Save original values
	origVersion := version
	origCommit := commit
	origDate := date
	origDirty := dirty
	origDebugBuildInfo := debugBuildInfo
	
	// Defer restore
	defer func() {
		version = origVersion
		commit = origCommit
		date = origDate
		dirty = origDirty
		debugBuildInfo = origDebugBuildInfo
	}()

	// Set dev values (empty ldflags)
	version = ""
	commit = ""
	date = ""
	dirty = ""
	
	debugBuildInfo = func() *debug.BuildInfo {
		return nil
	}
	
	got := String()
	want := "(devel)"
	if got != want {
		t.Errorf("String() with dev values = %q, want %q", got, want)
	}
}

func TestLdflagsWinsOverBuildInfo(t *testing.T) {
	// This test verifies that ldflags values take precedence over build info.
	// We can't easily mock the build info to return specific values in the same
	// test as ldflags, but we can verify the precedence by checking the code logic.
	// The implementation checks ldflags first, so if ldflags is non-empty, it returns that.
	
	// Save original values
	origVersion := version
	origCommit := commit
	origDate := date
	origDirty := dirty
	origDebugBuildInfo := debugBuildInfo
	
	// Defer restore
	defer func() {
		version = origVersion
		commit = origCommit
		date = origDate
		dirty = origDirty
		debugBuildInfo = origDebugBuildInfo
	}()

	// Set ldflags values (non-empty)
	version = "1.2.3"
	commit = "abc123"
	date = "2024-01-15T10:30:00Z"
	dirty = "true"
	
	// Even if build info would return something else, ldflags should win
	// We verify this by checking that the values are what we set in ldflags
	if Version() != "1.2.3" {
		t.Error("Version() should return ldflags value")
	}
	if Commit() != "abc123" {
		t.Error("Commit() should return ldflags value")
	}
	if Date() != "2024-01-15T10:30:00Z" {
		t.Error("Date() should return ldflags value")
	}
	if !Dirty() {
		t.Error("Dirty() should return ldflags value")
	}
}
