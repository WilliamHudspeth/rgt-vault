// clipboard.go provides a clipboard abstraction for RGT-160 clipboard auto-clear.
package tui

import "sync"

type Clipboard interface {
    Write(s string) error
    Clear() error
}

type MemoryClipboard struct {
    mu      sync.Mutex
    content string
}

func (m *MemoryClipboard) Write(s string) error {
    m.mu.Lock()
    m.content = s
    m.mu.Unlock()
    return nil
}

func (m *MemoryClipboard) Clear() error {
    m.mu.Lock()
    m.content = ""
    m.mu.Unlock()
    return nil
}

func (m *MemoryClipboard) Content() string {
    m.mu.Lock()
    content := m.content
    m.mu.Unlock()
    return content
}

type NoopClipboard struct{}

func (NoopClipboard) Write(s string) error { return nil }

func (NoopClipboard) Clear() error { return nil }

var _ Clipboard = (*MemoryClipboard)(nil)
var _ Clipboard = NoopClipboard{}
