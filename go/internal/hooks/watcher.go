package hooks

import (
	"os"
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

	frozen   atomic.Bool
	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
	started  atomic.Bool
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

// Start runs the watcher in a goroutine. Calling it twice is a no-op.
func (w *FreezeWatcher) Start() {
	if !w.started.CompareAndSwap(false, true) {
		return
	}
	go w.run()
}

func (w *FreezeWatcher) run() {
	defer close(w.done)
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		if _, err := os.Stat(w.path); err == nil {
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

// Stop stops the watcher and waits for it (if it was started).
func (w *FreezeWatcher) Stop() {
	w.stopOnce.Do(func() { close(w.stop) })
	if w.started.Load() {
		<-w.done
	}
}

// IsFrozen reports whether the freeze file has been seen.
func (w *FreezeWatcher) IsFrozen() bool { return w.frozen.Load() }

// Done is closed when the watcher goroutine exits.
func (w *FreezeWatcher) Done() <-chan struct{} { return w.done }
