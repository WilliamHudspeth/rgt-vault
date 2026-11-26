package providers

import (
	"context"
	"strings"
	"sync"
)

// call records one fake external invocation.
type call struct {
	Name  string
	Args  []string
	Stdin string
}

func (c call) String() string { return c.Name + " " + strings.Join(c.Args, " ") }

// fakeRunner is a programmable Runner. handle may inspect/mutate the file
// system (to simulate tpm2 tools) and return stdout/err; a nil handle returns
// success.
type fakeRunner struct {
	mu     sync.Mutex
	calls  []call
	handle func(c call) ([]byte, error)
}

func (f *fakeRunner) Run(_ context.Context, name string, args []string, stdin []byte) ([]byte, error) {
	f.mu.Lock()
	c := call{Name: name, Args: append([]string(nil), args...), Stdin: string(stdin)}
	f.calls = append(f.calls, c)
	h := f.handle
	f.mu.Unlock()
	if h == nil {
		return nil, nil
	}
	return h(c)
}

func (f *fakeRunner) names() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	for i, c := range f.calls {
		out[i] = c.Name
	}
	return out
}
