package logging

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Canonical attribute keys for operational JSON logs (RGT-247).
const (
	FieldTime       = slog.TimeKey    // "time" (UTC RFC3339Nano)
	FieldLevel      = slog.LevelKey   // "level" (DEBUG, INFO, WARN, ERROR)
	FieldMessage    = slog.MessageKey // "msg"
	FieldSource     = slog.SourceKey  // "source"
	FieldComponent  = "component"
	FieldEvent      = "event"
	FieldAgent      = "agent"
	FieldNamespace  = "namespace"
	FieldSecretName = "secret_name"
	FieldTokenID    = "token_id"
	FieldIncidentID = "incident_id"
	FieldRequestID  = "request_id"
	FieldHTTPMethod = "http_method"
	FieldHTTPPath   = "http_path"
	FieldHTTPStatus = "http_status"
	FieldDurationMS = "duration_ms"
	FieldAction     = "action"
	FieldErrorType  = "error_type"
	FieldReason     = "reason"
)

// ParseLevel parses a case-insensitive log level name ("debug", "info",
// "warn"/"warning", "error"). An empty string defaults to slog.LevelInfo.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("logging: invalid log level %q (want debug, info, warn, or error)", s)
	}
}

type config struct {
	writer        io.Writer
	filePath      string
	level         slog.Leveler
	levelErr      error
	addSource     bool
	component     string
	sensitiveKeys []string
	now           func() time.Time
}

// Option configures a logger created by New or NewWithCloser.
type Option func(*config)

// WithWriter directs JSON log output to w. Passing nil discards output.
func WithWriter(w io.Writer) Option {
	return func(c *config) {
		if w == nil {
			c.writer = io.Discard
			return
		}
		c.writer = w
		c.filePath = ""
	}
}

// WithStdout directs JSON log output to os.Stdout (the default).
func WithStdout() Option { return WithWriter(os.Stdout) }

// WithStderr directs JSON log output to os.Stderr.
func WithStderr() Option { return WithWriter(os.Stderr) }

// WithFile directs JSON log output to path. On POSIX platforms, parent
// directories are created/tightened to mode 0700 (when owned by the process),
// symlinks and non-regular files are refused (O_NOFOLLOW), and the log file
// is created or tightened to mode 0600. Use NewWithCloser so the caller can
// close or reopen the underlying FileWriter.
func WithFile(path string) Option {
	return func(c *config) {
		c.filePath = path
	}
}

// WithLevel sets the minimum log level (accepts slog.Level or *slog.LevelVar).
func WithLevel(level slog.Leveler) Option {
	return func(c *config) {
		if level != nil {
			c.level = level
		}
	}
}

// WithLevelString parses and sets the minimum log level by name. Any parse
// error is returned by New / NewWithCloser.
func WithLevelString(level string) Option {
	return func(c *config) {
		lvl, err := ParseLevel(level)
		if err != nil {
			c.levelErr = err
			return
		}
		c.level = lvl
	}
}

// WithComponent attaches a pre-bound "component" field to every log entry.
func WithComponent(component string) Option {
	return func(c *config) {
		c.component = component
	}
}

// WithAddSource controls whether source file and line metadata are included.
func WithAddSource(add bool) Option {
	return func(c *config) {
		c.addSource = add
	}
}

// WithExtraSensitiveKeys registers additional case-insensitive key names or
// substrings whose values must always be redacted.
func WithExtraSensitiveKeys(keys ...string) Option {
	return func(c *config) {
		c.sensitiveKeys = append(c.sensitiveKeys, keys...)
	}
}

// WithClock overrides record timestamps (primarily for deterministic tests).
func WithClock(now func() time.Time) Option {
	return func(c *config) {
		c.now = now
	}
}

// New constructs a hardened JSON *slog.Logger. If WithFile is used without
// NewWithCloser, the file stays open for the lifetime of the process; prefer
// NewWithCloser when managing file lifecycle or rotation.
func New(opts ...Option) (*slog.Logger, error) {
	l, _, err := NewWithCloser(opts...)
	return l, err
}

// NewWithCloser constructs a hardened JSON *slog.Logger and returns an
// io.Closer for any file opened via WithFile (a no-op closer for writer/stdout
// targets). When WithFile is used, the returned closer is a *FileWriter that
// also supports Reopen() once a caller wires a rotation signal handler.
func NewWithCloser(opts ...Option) (*slog.Logger, io.Closer, error) {
	cfg := config{
		writer: os.Stdout,
		level:  slog.LevelInfo,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.levelErr != nil {
		return nil, nil, cfg.levelErr
	}

	var (
		out    io.Writer = cfg.writer
		closer io.Closer = nopCloser{}
	)
	if cfg.filePath != "" {
		fw, err := OpenFileWriter(cfg.filePath)
		if err != nil {
			return nil, nil, err
		}
		out = fw
		closer = fw
	}

	redactor := NewRedactor(cfg.sensitiveKeys...)
	// sanitizingHandler scrubs record messages, normalizes timestamps to UTC, and
	// scrubs every attribute under a per-record node budget before delegating to
	// slog.JSONHandler. Leaving ReplaceAttr nil here avoids redundant double-pass
	// scrubbing on every attribute; Redactor.ReplaceAttr remains available for
	// callers constructing a standalone slog.HandlerOptions.
	jsonHandler := slog.NewJSONHandler(out, &slog.HandlerOptions{
		AddSource: cfg.addSource,
		Level:     cfg.level,
	})

	var h slog.Handler = &sanitizingHandler{
		next:     jsonHandler,
		redactor: redactor,
		now:      cfg.now,
	}
	logger := slog.New(h)
	if cfg.component != "" {
		logger = logger.With(slog.String(FieldComponent, cfg.component))
	}
	return logger, closer, nil
}

// Default returns a hardened JSON logger writing INFO+ records to os.Stdout.
func Default() *slog.Logger {
	l, _ := New()
	return l
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// sanitizingHandler wraps slog.JSONHandler so record timestamps are normalized
// to UTC, record messages are scrubbed and control-char encoded, and every
// record gets a bounded node budget (maxScrubNodes) to prevent breadth/cycle
// resource exhaustion.
type sanitizingHandler struct {
	next     slog.Handler
	redactor *Redactor
	now      func() time.Time
	groups   []string
}

func (h *sanitizingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *sanitizingHandler) Handle(ctx context.Context, r slog.Record) error {
	t := r.Time
	if h.now != nil {
		t = h.now()
	}
	if !t.IsZero() {
		t = t.UTC()
	} else {
		t = time.Now().UTC()
	}

	st := newScrubState()
	clean := slog.NewRecord(t, r.Level, h.redactor.ScrubString(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		clean.AddAttrs(h.redactor.scrubAttr(st, h.groups, a, 0))
		return true
	})
	return h.next.Handle(ctx, clean)
}

func (h *sanitizingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	st := newScrubState()
	scrubbed := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		scrubbed[i] = h.redactor.scrubAttr(st, h.groups, a, 0)
	}
	return &sanitizingHandler{
		next:     h.next.WithAttrs(scrubbed),
		redactor: h.redactor,
		now:      h.now,
		groups:   h.groups,
	}
}

func (h *sanitizingHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	cleanName := h.redactor.ScrubString(name)
	nextGroups := make([]string, len(h.groups)+1)
	copy(nextGroups, h.groups)
	nextGroups[len(h.groups)] = cleanName
	return &sanitizingHandler{
		next:     h.next.WithGroup(cleanName),
		redactor: h.redactor,
		now:      h.now,
		groups:   nextGroups,
	}
}

// FileWriter is a concurrency-safe append-only log file writer that enforces
// 0600 file permissions (in a 0700 directory, refusing symlinks via O_NOFOLLOW
// on POSIX) and supports atomic Reopen for external log rotation once wired.
type FileWriter struct {
	path   string
	mu     sync.Mutex
	file   *os.File
	closed bool
}

// OpenFileWriter opens or creates path for append-only logging.
func OpenFileWriter(path string) (*FileWriter, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return nil, errors.New("logging: empty log file path")
	}
	clean := filepath.Clean(trimmed)
	f, err := openLogFileOS(clean)
	if err != nil {
		return nil, err
	}
	return &FileWriter{path: clean, file: f}, nil
}

// Path returns the configured file path.
func (fw *FileWriter) Path() string { return fw.path }

// Write appends p to the underlying file under a mutex.
func (fw *FileWriter) Write(p []byte) (int, error) {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	if fw.closed || fw.file == nil {
		return 0, os.ErrClosed
	}
	return fw.file.Write(p)
}

// Reopen opens a fresh file handle at Path and closes the previous descriptor.
func (fw *FileWriter) Reopen() error {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	if fw.closed {
		return os.ErrClosed
	}
	next, err := openLogFileOS(fw.path)
	if err != nil {
		return err
	}
	old := fw.file
	fw.file = next
	if old != nil {
		_ = old.Close()
	}
	return nil
}

// Close closes the underlying log file. Subsequent writes return os.ErrClosed.
func (fw *FileWriter) Close() error {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	if fw.closed {
		return nil
	}
	fw.closed = true
	if fw.file == nil {
		return nil
	}
	err := fw.file.Close()
	fw.file = nil
	return err
}
