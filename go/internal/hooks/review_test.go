package hooks

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"rgt-vault-server/internal/vault"
)

// Regression tests for the Gemini 4 Neon review of the G8a diff.

func TestWebhookReviewFixes(t *testing.T) {
	ctx := context.Background()
	var hitTarget atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitTarget.Store(true)
		_, _ = io.WriteString(w, `{"decision":"allow"}`)
	}))
	defer target.Close()
	var reply atomic.Value
	reply.Store(`{"decision":"allow"}}`)
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, target.URL+"/admin", http.StatusTemporaryRedirect)
		case "/multiple":
			w.WriteHeader(http.StatusMultipleChoices)
			_, _ = io.WriteString(w, `{"decision":"allow"}`)
		default:
			_, _ = io.WriteString(w, reply.Load().(string))
		}
	}))
	defer src.Close()

	// Trailing "}" / "]" after the object is not valid JSON (fail closed).
	wh, _ := NewWebhookHook(src.URL + "/x")
	for _, body := range []string{`{"decision":"allow"}}`, `{"decision":"allow"}]`, `{"decision":"allow"}{}`} {
		reply.Store(body)
		if r, _ := wh.Consult(ctx, vault.HookRequest{Operation: "list"}); r.Decision != vault.HookDeny || r.Reason != "hook response not valid JSON" {
			t.Errorf("%s: %+v", body, r)
		}
	}
	reply.Store("{\"decision\":\"allow\"}\n  ")
	if r, _ := wh.Consult(ctx, vault.HookRequest{Operation: "list"}); r.Decision != vault.HookAllow {
		t.Errorf("trailing whitespace is valid JSON: %+v", r)
	}
	// Redirects are not followed; 3xx is a deny.
	wh, _ = NewWebhookHook(src.URL+"/redirect", WithBearerToken("bt"))
	if r, _ := wh.Consult(ctx, vault.HookRequest{Operation: "list"}); r.Decision != vault.HookDeny || r.Reason != "hook URL unreachable: Temporary Redirect" {
		t.Fatalf("redirect: %+v", r)
	}
	if hitTarget.Load() {
		t.Fatal("redirect was followed")
	}
	wh, _ = NewWebhookHook(src.URL + "/multiple")
	if r, _ := wh.Consult(ctx, vault.HookRequest{Operation: "list"}); r.Decision != vault.HookDeny {
		t.Fatalf("300 must deny: %+v", r)
	}
	// Query string and fragment never reach the hook id.
	wh, _ = NewWebhookHook("https://u:pw@soar.example/hook?token=secret123#frag")
	if wh.ID() != "webhook:https://u:xxxxx@soar.example/hook" {
		t.Fatalf("hook id = %q", wh.ID())
	}
}

func TestFreezeFileFailsClosed(t *testing.T) {
	dir := t.TempDir()
	h := NewOffHook()
	// Dangling symlink: Lstat sees it.
	link := filepath.Join(dir, "freeze-link")
	if err := os.Symlink(filepath.Join(dir, "missing"), link); err != nil {
		t.Skip("symlinks unsupported:", err)
	}
	h.SetFreezeFile(link)
	if !h.Frozen() {
		t.Fatal("dangling symlink must freeze")
	}
	// A path whose parent is a regular file (ENOTDIR on POSIX; Windows
	// reports it as not-found): not "does not exist", so it freezes.
	if runtime.GOOS != "windows" {
		file := filepath.Join(dir, "plain")
		_ = os.WriteFile(file, nil, 0o600)
		h.SetFreezeFile(filepath.Join(file, "freeze"))
		if !h.Frozen() {
			t.Fatal("stat error other than not-exist must freeze (fail closed)")
		}
	}
	h.SetFreezeFile(filepath.Join(dir, "absent"))
	if h.Frozen() {
		t.Fatal("absent freeze file must not freeze")
	}
}

func TestFreezeWatcherStopBeforeStart(t *testing.T) {
	ff := filepath.Join(t.TempDir(), "freeze")
	_ = os.WriteFile(ff, nil, 0o600)
	var called atomic.Bool
	w := NewFreezeWatcher(ff, time.Millisecond, func() { called.Store(true) })
	w.Stop()
	w.Start()
	time.Sleep(20 * time.Millisecond)
	if called.Load() || w.IsFrozen() {
		t.Fatal("callback ran after Stop")
	}
	// Stop racing a running watcher: after Stop returns nothing runs.
	for i := 0; i < 50; i++ {
		var n atomic.Int32
		w := NewFreezeWatcher(filepath.Join(t.TempDir(), "never"), time.Microsecond, func() { n.Add(1) })
		go w.Start()
		w.Stop()
		w.Stop()
	}
}
