package netguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

func mustAddr(t testing.TB, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return a
}

// fakeResolver answers from a table and counts lookups. answers[host] is a
// list of answer sets returned on successive lookups (the last repeats), so a
// test can model a DNS-rebinding server that changes its answer.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][][]string
	calls   map[string]int
}

func newFakeResolver(answers map[string][][]string) *fakeResolver {
	return &fakeResolver{answers: answers, calls: map[string]int{}}
}

func (f *fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	sets, ok := f.answers[host]
	if !ok {
		f.calls[host]++
		return nil, errors.New("no such host (secret-resolver-detail)")
	}
	i := f.calls[host]
	f.calls[host]++
	if i >= len(sets) {
		i = len(sets) - 1
	}
	var out []net.IPAddr
	for _, s := range sets[i] {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

func (f *fakeResolver) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		n += c
	}
	return n
}
