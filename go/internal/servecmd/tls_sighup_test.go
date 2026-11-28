//go:build unix

package servecmd

import (
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"rgt-vault-server/internal/tlstest"
)

// SIGHUP reloads the certificate immediately, with file polling off.
func TestServeReloadsOnSIGHUP(t *testing.T) {
	ca := tlstest.NewCA(t)
	f := ca.Localhost(t, t.TempDir())
	r := startTLS(t, tlsArgs(f, "--tls-reload-interval", "0")...)
	first := serial(t, r.addr, ca)
	want := replaceCert(t, ca, f)
	if first == want {
		t.Fatal("test setup: same serial")
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	waitSerial(t, r.addr, ca, want)
}

// Without TLS a SIGHUP (`systemctl reload`) must not kill the server.
func TestSIGHUPWithoutTLSIsIgnored(t *testing.T) {
	r := startTLS(t, "--port", "0")
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(r.logs.String(), "SIGHUP ignored") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(r.logs.String(), "SIGHUP ignored") {
		t.Errorf("SIGHUP not handled:\n%s", r.logs)
	}
	resp, err := http.Get("http://" + r.addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}
