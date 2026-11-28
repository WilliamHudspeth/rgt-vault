package tlstest

import (
	"crypto/x509"
	"net"
	"os"
	"runtime"
	"testing"
	"time"
)

func TestIssueVerifiesAgainstCA(t *testing.T) {
	ca := NewCA(t)
	f := ca.Localhost(t, "")
	if _, err := f.Leaf.Verify(x509.VerifyOptions{Roots: ca.Pool(), DNSName: "localhost"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ca.PEMFile); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(f.Key); fi.Mode().Perm() != 0o600 {
			t.Errorf("key mode %v", fi.Mode().Perm())
		}
	}
}

func TestIssueOptions(t *testing.T) {
	ca := NewCA(t)
	dir := t.TempDir()
	c := ca.Issue(t, dir, Leaf{Name: "cl", Client: true, NoSAN: true, KeyMode: 0o644,
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour),
		IPs: []net.IP{net.ParseIP("10.0.0.1")}})
	if len(c.Leaf.IPAddresses) != 0 || len(c.Leaf.DNSNames) != 0 {
		t.Error("NoSAN ignored")
	}
	if len(c.Leaf.ExtKeyUsage) != 1 || c.Leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("EKU %v", c.Leaf.ExtKeyUsage)
	}
	if c.Leaf.Subject.CommonName != "cl" || c.Leaf.NotAfter.After(time.Now()) {
		t.Errorf("leaf %+v", c.Leaf.Subject)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(c.Key); fi.Mode().Perm() != 0o644 {
			t.Errorf("key mode %v", fi.Mode().Perm())
		}
	}
}
