// Package buildinfo provides build-time metadata for the rgt-vault binary.
//
// The package exposes version, commit, date, and dirty status information
// that is injected at build time via -ldflags. When ldflags are not set
// (e.g., during development with `go build` or `go test`), it falls back
// to reading build info from runtime/debug.ReadBuildInfo().
//
// The ldflags variables are:
//   -X github.com/WilliamHudspeth/rgt-vault/go/internal/buildinfo.version
//   -X github.com/WilliamHudspeth/rgt-vault/go/internal/buildinfo.commit
//   -X github.com/WilliamHudspeth/rgt-vault/go/internal/buildinfo.date
//   -X github.com/WilliamHudspeth/rgt-vault/go/internal/buildinfo.dirty
package buildinfo

import (
	"runtime/debug"
	"strings"
)

// Build metadata, injected at release time via -ldflags by GoReleaser.
// These variables are set by the linker when building with ldflags.
var (
	version = ""
	commit  = ""
	date    = ""
	dirty   = "false"
)

// debugBuildInfo is a variable that can be replaced by tests to mock
// runtime/debug.ReadBuildInfo() return value.
var debugBuildInfo = func() *debug.BuildInfo {
	info, _ := debug.ReadBuildInfo()
	return info
}

// Version returns the version string.
// If the ldflags variable is set, it returns that value.
// Otherwise, it reads from debug.ReadBuildInfo() and returns Main.Version
// (which is "v0.4.0" for `go install ...@v0.4.0`, else "(devel)").
func Version() string {
	if version != "" {
		return version
	}
	info := debugBuildInfo()
	if info == nil || info.Main.Path == "" {
		return "(devel)"
	}
	v := info.Main.Version
	if v == "" || v == "(devel)" {
		return "(devel)"
	}
	return v
}

// Commit returns the commit hash.
// If the ldflags variable is set, it returns that value.
// Otherwise, it reads from debug.ReadBuildInfo() and returns vcs.revision.
func Commit() string {
	if commit != "" {
		return commit
	}
	info := debugBuildInfo()
	if info == nil {
		return "none"
	}
	// Try to get revision from VCS settings
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			return setting.Value
		}
	}
	return "none"
}

// Date returns the build date.
// If the ldflags variable is set, it returns that value.
// Otherwise, it reads from debug.ReadBuildInfo() and returns vcs.time.
func Date() string {
	if date != "" {
		return date
	}
	info := debugBuildInfo()
	if info == nil {
		return "unknown"
	}
	// Try to get time from VCS settings
	for _, setting := range info.Settings {
		if setting.Key == "vcs.time" {
			return setting.Value
		}
	}
	return "unknown"
}

// Dirty returns whether the working directory was dirty at build time.
// If the ldflags variable is set, it returns that value.
// Otherwise, it reads from debug.ReadBuildInfo() and returns vcs.modified.
func Dirty() bool {
	if dirty != "" {
		return strings.ToLower(dirty) == "true"
	}
	info := debugBuildInfo()
	if info == nil {
		return false
	}
	// Try to get modified from VCS settings
	for _, setting := range info.Settings {
		if setting.Key == "vcs.modified" {
			return strings.ToLower(setting.Value) == "true"
		}
	}
	return false
}

// String returns a human-readable version string in the format:
// "version (commit, built date)" with " (dirty)" appended if the build was dirty.
// This matches the format used by cobra's Version field.
func String() string {
	v := Version()
	c := Commit()
	d := Date()
	
	result := v
	if c != "" && c != "none" {
		result += " (commit " + c + ")"
	}
	if d != "" && d != "unknown" {
		result += ", built " + d
	}
	if Dirty() {
		result += ", dirty"
	}
	return result
}
