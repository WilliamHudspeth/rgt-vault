package gateway

import "testing"

func TestIsLoopbackAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		DefaultListenAddr: true,
		"localhost:8088":  true,
		"[::1]:8088":      true,
		"127.1.2.3:1":     true,
		":8088":           false,
		"0.0.0.0:8088":    false,
		"[::]:8088":       false,
		"10.0.0.5:8088":   false,
		"example.com:80":  false,
		"no-port":         false,
	} {
		if got := IsLoopbackAddr(addr); got != want {
			t.Errorf("IsLoopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}
