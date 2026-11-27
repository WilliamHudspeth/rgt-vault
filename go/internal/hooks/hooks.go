// Package hooks is the Go port of python/hook.py, python/watcher.py and
// python/hooks/log_redaction.py: the pluggable audit hooks the vault
// consults before every sensitive operation (vault.Hook).
//
// Modes (FromConfig):
//
//	off         OffHook: always allows ("hook disabled").
//	log         LogHook: allows and records each consultation in memory.
//	webhook     WebhookHook: POSTs the request to a harness URL through the
//	            netguard SSRF-safe dialer and honours its decision.
//	two_factor  TwoFactorHook: verifies harness-minted HMAC tokens locally
//	            (v1 namespace tokens and v2 capability tokens) with a
//	            replay cache keyed by token id.
//
// Every hook embeds Base, which provides the kill switch: Freeze/Unfreeze,
// an optional freeze file whose presence freezes the hook (checked on every
// call), and SIGUSR1/SIGUSR2 via InstallFreezeSignalHandler. FreezeWatcher
// is the watcher.py background poller. LogRedactionHook logs only redacted
// request metadata.
//
// Deliberate differences from Python (each noted at the definition):
//
//   - TwoFactorHook.Issue signs v1 tokens with the shared secret. Python's
//     CapabilityToken.to_compact signs with an EMPTY key, so its tokens never
//     verify (bug found by G5); captoken.CapabilityToken.ToCompact(nil)
//     still reproduces that output for compatibility tests.
//   - WebhookHook dials through netguard: link-local / cloud-metadata
//     addresses are always refused, and non-loopback hosts need
//     WithAllowRemote (WebhookConfig.AllowRemote). Proxies from the
//     environment are not used. Redirects are not followed and only 2xx
//     answers count. The hook id is only scheme://host[:port].
//   - TwoFactorHook checks for a replay before evicting and purges expired
//     ids on every accept (Python evicts first, only when full).
//   - Redact replaces a high-entropy string entirely by [REDACTED]; Python
//     keeps its first four characters.
//   - A freeze file that cannot be stat'ed (other than "does not exist")
//     counts as frozen.
//   - LogHook keeps at most MaxLogConsultations entries (Python's list is
//     unbounded).
//   - The shared secret for two_factor may be given only via config or an
//     environment variable, as in Python; the CLI wiring is batch G10.
package hooks

import (
	"errors"
	"io/fs"
	"os"
	"sync"

	"rgt-vault-server/internal/validation"
	"rgt-vault-server/internal/vault"
)

// Hook is a vault.Hook with the Base kill-switch controls.
type Hook interface {
	vault.Hook
	Freezer
	// SetFreezeFile sets (or, with "", clears) the freeze file path.
	SetFreezeFile(path string)
	// FreezeFile returns the configured freeze file path ("" if none).
	FreezeFile() string
}

// Freezer is the part of a hook the signal handler and the freeze watcher
// drive.
type Freezer interface {
	Freeze(reason string)
	Unfreeze(reason string)
}

// Base carries a hook's id and freeze state (python AuditHook). Embed it in
// a struct used by pointer; the zero value is not usable, use NewBase.
type Base struct {
	id string

	mu         sync.Mutex
	frozen     bool
	freezeFile string
	onChange   func(frozen bool, reason string)
}

// NewBase returns a Base with the given hook id.
func NewBase(id string) *Base { return &Base{id: id} }

// ID returns the hook id recorded in the audit chain.
func (b *Base) ID() string { return b.id }

// Frozen reports whether the hook is frozen: by Freeze, or because the
// freeze file exists. It is checked under a lock on every operation.
// Unlike Python, a stat error other than "does not exist" (EACCES, EIO, a
// broken parent) counts as frozen: the kill switch fails closed.
func (b *Base) Frozen() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.frozen {
		return true
	}
	return freezeFilePresent(b.freezeFile)
}

func freezeFilePresent(path string) bool {
	if path == "" {
		return false
	}
	// Lstat: a dangling symlink still freezes. Any error other than "does
	// not exist" freezes too (fail closed; Python's Path.exists treats it
	// as absent).
	_, err := os.Lstat(path)
	return err == nil || !errors.Is(err, fs.ErrNotExist)
}

// Freeze marks the hook frozen: every sensitive operation is denied.
func (b *Base) Freeze(reason string) {
	b.mu.Lock()
	b.frozen = true
	fn := b.onChange
	b.mu.Unlock()
	if fn != nil {
		fn(true, reason)
	}
}

// Unfreeze clears the in-memory freeze (a present freeze file still
// freezes).
func (b *Base) Unfreeze(reason string) {
	b.mu.Lock()
	b.frozen = false
	fn := b.onChange
	b.mu.Unlock()
	if fn != nil {
		fn(false, reason)
	}
}

// SetFreezeFile sets the freeze file path ("" disables the mechanism).
func (b *Base) SetFreezeFile(path string) {
	b.mu.Lock()
	b.freezeFile = path
	b.mu.Unlock()
}

// FreezeFile returns the freeze file path.
func (b *Base) FreezeFile() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.freezeFile
}

// OnFreezeChange registers fn to run after every Freeze/Unfreeze (Python
// _on_freeze_change), e.g. to write an audit row. fn runs without the
// lock held.
func (b *Base) OnFreezeChange(fn func(frozen bool, reason string)) {
	b.mu.Lock()
	b.onChange = fn
	b.mu.Unlock()
}

func allow(reason string) vault.HookResponse {
	return vault.HookResponse{Decision: vault.HookAllow, Reason: reason}
}

func deny(reason string) vault.HookResponse {
	return vault.HookResponse{Decision: vault.HookDeny, Reason: reason}
}

func validationErr(msg string) error { return &validation.Error{Message: msg} }
