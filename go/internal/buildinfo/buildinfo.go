// Package buildinfo is the single source of the rgt-vault version.
//
// Release builds (GoReleaser) inject the values with -ldflags -X:
//
//	-X github.com/WilliamHudspeth/rgt-vault/go/internal/buildinfo.version=...
//	-X github.com/WilliamHudspeth/rgt-vault/go/internal/buildinfo.commit=...
//	-X github.com/WilliamHudspeth/rgt-vault/go/internal/buildinfo.date=...
//	-X github.com/WilliamHudspeth/rgt-vault/go/internal/buildinfo.dirty=true|false
//
// A variable that is empty (the default) is not set: the value then comes
// from runtime/debug.ReadBuildInfo, so `go install ...@v0.4.0` reports v0.4.0
// and a plain `go build` in a git checkout reports the VCS revision, time and
// modified flag that the Go toolchain stamps in.
package buildinfo

import (
	"runtime/debug"
	"strconv"
)

// Set by -ldflags -X at release time. The empty string means "not set".
var (
	version = ""
	commit  = ""
	date    = ""
	dirty   = ""
)

// readBuildInfo is the seam tests replace; it returns nil when the binary
// carries no build information.
var readBuildInfo = func() *debug.BuildInfo {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return nil
	}
	return info
}

const (
	unknownVersion = "(devel)"
	unknownCommit  = "none"
	unknownDate    = "unknown"
)

// vcsSetting returns the value of a build setting (vcs.revision, vcs.time,
// vcs.modified) and whether it is present and non-empty.
func vcsSetting(key string) (string, bool) {
	info := readBuildInfo()
	if info == nil {
		return "", false
	}
	for _, s := range info.Settings {
		if s.Key == key && s.Value != "" {
			return s.Value, true
		}
	}
	return "", false
}

// trimV drops the "v" of a semantic-version tag ("v0.4.0" -> "0.4.0") so a
// GoReleaser build ({{.Version}} has no prefix) and `go install ...@v0.4.0`
// (Main.Version has one) report the same string. Other strings, such as
// "(devel)", are left alone.
func trimV(v string) string {
	if len(v) > 1 && v[0] == 'v' && v[1] >= '0' && v[1] <= '9' {
		return v[1:]
	}
	return v
}

// Version returns the ldflags version when set, else the module version from
// the build info (`go install ...@v0.4.0` reports 0.4.0), else "(devel)".
// A leading "v" is never part of the result.
func Version() string {
	if version != "" {
		return trimV(version)
	}
	if info := readBuildInfo(); info != nil && info.Main.Version != "" {
		return trimV(info.Main.Version)
	}
	return unknownVersion
}

// Commit returns the ldflags commit when set, else vcs.revision, else "none".
func Commit() string {
	if commit != "" {
		return commit
	}
	if v, ok := vcsSetting("vcs.revision"); ok {
		return v
	}
	return unknownCommit
}

// Date returns the ldflags build date when set, else vcs.time, else "unknown".
func Date() string {
	if date != "" {
		return date
	}
	if v, ok := vcsSetting("vcs.time"); ok {
		return v
	}
	return unknownDate
}

// Dirty reports whether the source tree had uncommitted changes at build
// time: the ldflags value when it is set to a boolean, else vcs.modified.
func Dirty() bool {
	if dirty != "" {
		if b, err := strconv.ParseBool(dirty); err == nil {
			return b
		}
	}
	if v, ok := vcsSetting("vcs.modified"); ok {
		b, _ := strconv.ParseBool(v)
		return b
	}
	return false
}

// String is the one-line description printed by `rgt-vault --version` and
// `rgt-vault version`: "<version> (commit <c>, built <d>)", with ", dirty"
// appended inside the parentheses for a build from a modified tree.
func String() string {
	s := Version() + " (commit " + Commit() + ", built " + Date()
	if Dirty() {
		s += ", dirty"
	}
	return s + ")"
}
