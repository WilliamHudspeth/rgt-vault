package tui

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"
)

// fakeClient is an in-memory Client for testing.
type fakeClient struct {
	rotateCalls int
}

func (f *fakeClient) Health() bool { return true }

func (f *fakeClient) VerifyAudit() bool { return true }

func (f *fakeClient) ListSecrets(namespace string) ([]SecretInfo, error) {
	return []SecretInfo{
		{Name: "api-key", Fingerprint: "abc12345"},
		{Name: "db-pass", Fingerprint: "def67890"},
	}, nil
}

func (f *fakeClient) Rotate(target string) error {
	f.rotateCalls++
	return nil
}

// readOutput drains all currently available bytes from the reader.
func readOutput(r io.Reader) string {
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

// waitForOutput keeps reading from r until condition is true or timeout elapses.
func waitForOutput(t *testing.T, r io.Reader, condition func(string) bool, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var accumulated strings.Builder
	for time.Now().Before(deadline) {
		chunk := readOutput(r)
		if chunk != "" {
			accumulated.WriteString(chunk)
		}
		if condition(accumulated.String()) {
			return accumulated.String()
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("condition not met after %s. Last output:\n%s", timeout, accumulated.String())
	return accumulated.String()
}

// TestDashboardRenders verifies that after startup the dashboard shows
// server health and secret names.
func TestDashboardRenders(t *testing.T) {
	fake := &fakeClient{}
	tm := teatest.NewTestModel(
		t,
		New(fake, "default"),
		teatest.WithInitialTermSize(80, 24),
	)

	// The model fires loadCmd on Init; wait for the loaded state.
	teatest.WaitFor(
		t,
		tm.Output(),
		func(bts []byte) bool {
			out := string(bts)
			return strings.Contains(out, "online") && strings.Contains(out, "api-key")
		},
		teatest.WithDuration(3*time.Second),
		teatest.WithCheckInterval(50*time.Millisecond),
	)

	// Quit cleanly.
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	tm.WaitFinished(t, teatest.WithFinalTimeout(2*time.Second))
}

// TestSearchFilter verifies that typing "/" then "db" filters to db-pass only.
func TestSearchFilter(t *testing.T) {
	fake := &fakeClient{}
	tm := teatest.NewTestModel(
		t,
		New(fake, "default"),
		teatest.WithInitialTermSize(80, 24),
	)

	// Wait for initial load.
	teatest.WaitFor(
		t,
		tm.Output(),
		func(bts []byte) bool {
			return strings.Contains(string(bts), "api-key")
		},
		teatest.WithDuration(3*time.Second),
		teatest.WithCheckInterval(50*time.Millisecond),
	)

	// Enter search mode and type "db".
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("/")})
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("b")})

	// Wait for the filter to render: db-pass visible, api-key gone.
	teatest.WaitFor(
		t,
		tm.Output(),
		func(bts []byte) bool {
			out := string(bts)
			return strings.Contains(out, "db-pass") && !strings.Contains(out, "api-key")
		},
		teatest.WithDuration(3*time.Second),
		teatest.WithCheckInterval(50*time.Millisecond),
	)

	// Quit cleanly.
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	tm.WaitFinished(t, teatest.WithFinalTimeout(2*time.Second))
}

// TestHelp verifies that "?" opens the help screen.
func TestHelp(t *testing.T) {
	fake := &fakeClient{}
	tm := teatest.NewTestModel(
		t,
		New(fake, "default"),
		teatest.WithInitialTermSize(80, 24),
	)

	// Wait for initial load.
	teatest.WaitFor(
		t,
		tm.Output(),
		func(bts []byte) bool {
			return strings.Contains(string(bts), "online")
		},
		teatest.WithDuration(3*time.Second),
		teatest.WithCheckInterval(50*time.Millisecond),
	)

	// Open help.
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("?")})

	teatest.WaitFor(
		t,
		tm.Output(),
		func(bts []byte) bool {
			out := string(bts)
			return strings.Contains(out, "Search secrets") &&
				strings.Contains(out, "Press any key to return")
		},
		teatest.WithDuration(3*time.Second),
		teatest.WithCheckInterval(50*time.Millisecond),
	)

	// Dismiss help, then quit.
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	tm.WaitFinished(t, teatest.WithFinalTimeout(2*time.Second))
}

// TestQuit verifies that pressing "q" terminates the program.
func TestQuit(t *testing.T) {
	fake := &fakeClient{}
	tm := teatest.NewTestModel(
		t,
		New(fake, "default"),
		teatest.WithInitialTermSize(80, 24),
	)

	// Wait for load so the model is in dashboard mode.
	teatest.WaitFor(
		t,
		tm.Output(),
		func(bts []byte) bool {
			return strings.Contains(string(bts), "online")
		},
		teatest.WithDuration(3*time.Second),
		teatest.WithCheckInterval(50*time.Millisecond),
	)

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	tm.WaitFinished(t, teatest.WithFinalTimeout(2*time.Second))
}
