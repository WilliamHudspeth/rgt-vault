package hooks

import (
	"sync"
	"sync/atomic"
	"time"
)

// FreezeWatcher polls for a freeze file and, the first time it appears,
// marks itself frozen and runs the callback once, then stops (python
// watcher.py FreezeWatcher). It works on every platform, including Windows
// where there are no freeze signals.
type FreezeWatcher struct {
	path     string
	interval time.Duration
	callback func()

	frozen atomic.Bool
	stop   chan struct{}
	done   chan struct{}

	mu      sync.Mutex
	started bool
	stopped bool
}

// NewFreezeWatcher returns a watcher for path. interval <= 0 means 1s.
// callback may be nil; a panic in it is swallowed (Python: except
// Exception: pass).
func NewFreezeWatcher(path string, interval time.Duration, callback func()) *FreezeWatcher {
	if interval <= 0 {
		interval = time.Second
	}
	return &FreezeWatcher{path: path, interval: interval, callback: callback,
		stop: make(chan struct{}), done: make(chan struct{})}
}

// FreezeOnFile returns a watcher that freezes h with reason "freeze file"
// when path appears.
func FreezeOnFile(h Freezer, path string, interval time.Duration) *FreezeWatcher {
	return NewFreezeWatcher(path, interval, func() { h.Freeze("freeze file") })
}

// Start runs the watcher in a goroutine. Calling it twice, or after Stop,
// is a no-op.
func (w *FreezeWatcher) Start() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started || w.stopped {
		return
	}
	w.started = true
	go w.run()
}

func (w *FreezeWatcher) run() {
	defer close(w.done)
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-w.stop:
			return
		default:
		}
		if freezeFilePresent(w.path) {
			w.frozen.Store(true)
			w.fire()
			return
		}
		select {
		case <-w.stop:
			return
		case <-t.C:
		}
	}
}

func (w *FreezeWatcher) fire() {
	if w.callback == nil {
		return
	}
	defer func() { _ = recover() }()
	w.callback()
}

// Stop stops the watcher and waits for it (if it was started): once Stop
// returns, the callback is not running and will not run.
func (w *FreezeWatcher) Stop() {
	w.mu.Lock()
	if !w.stopped {
		w.stopped = true
		close(w.stop)
	}
	started := w.started
	w.mu.Unlock()
	if started {
		<-w.done
	}
}

// IsFrozen reports whether the freeze file has been seen.
func (w *FreezeWatcher) IsFrozen() bool { return w.frozen.Load() }

// Done is closed when the watcher goroutine exits.
func (w *FreezeWatcher) Done() <-chan struct{} { return w.done }
