// Package tlstest generates throw-away certificate authorities and
// certificates for tests (batch H6). It is test support only: nothing outside
// _test.go files may import it.
package tlstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CA is a self-signed certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	// PEMFile is the CA certificate as a PEM file (a --cacert / client CA).
	PEMFile string
	dir     string
	serial  int64
}

// Leaf selects the properties of an issued certificate.
type Leaf struct {
	Name      string // file name stem; default "leaf"
	CN        string
	DNSNames  []string
	IPs       []net.IP
	NotBefore time.Time // default: one hour ago
	NotAfter  time.Time // default: 90 days ahead
	Client    bool      // client-auth EKU instead of server-auth
	NoSAN     bool      // leave the SAN empty
	KeyMode   os.FileMode
}

// Files are the PEM files of an issued certificate.
type Files struct {
	Cert, Key string
	Leaf      *x509.Certificate
	PrivKey   *ecdsa.PrivateKey
}

// NewCA creates a CA whose files live in a fresh temp dir.
func NewCA(tb testing.TB) *CA {
	tb.Helper()
	dir := tb.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(tb, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "rgt-vault test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	must(tb, err)
	cert, err := x509.ParseCertificate(der)
	must(tb, err)
	ca := &CA{Cert: cert, Key: key, dir: dir, serial: 1}
	ca.PEMFile = filepath.Join(dir, "ca.pem")
	writePEM(tb, ca.PEMFile, "CERTIFICATE", der, 0o644)
	return ca
}

// Pool returns a pool trusting only this CA.
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.Cert)
	return p
}

// Issue signs a leaf certificate and writes cert and key (mode 0600 unless
// l.KeyMode is set) into dir (default: the CA's directory).
func (c *CA) Issue(tb testing.TB, dir string, l Leaf) Files {
	tb.Helper()
	if dir == "" {
		dir = c.dir
	}
	if l.Name == "" {
		l.Name = "leaf"
	}
	if l.NotBefore.IsZero() {
		l.NotBefore = time.Now().Add(-time.Hour)
	}
	if l.NotAfter.IsZero() {
		l.NotAfter = time.Now().Add(90 * 24 * time.Hour)
	}
	if l.KeyMode == 0 {
		l.KeyMode = 0o600
	}
	if l.CN == "" {
		l.CN = l.Name
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(tb, err)
	c.serial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(c.serial + time.Now().UnixNano()%1_000_000),
		Subject:      pkix.Name{CommonName: l.CN},
		NotBefore:    l.NotBefore,
		NotAfter:     l.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if !l.NoSAN {
		tmpl.DNSNames, tmpl.IPAddresses = l.DNSNames, l.IPs
	}
	if l.Client {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, &key.PublicKey, c.Key)
	must(tb, err)
	leaf, err := x509.ParseCertificate(der)
	must(tb, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	must(tb, err)
	f := Files{
		Cert:    filepath.Join(dir, l.Name+".crt"),
		Key:     filepath.Join(dir, l.Name+".key"),
		Leaf:    leaf,
		PrivKey: key,
	}
	writePEM(tb, f.Cert, "CERTIFICATE", der, 0o644)
	writePEM(tb, f.Key, "PRIVATE KEY", keyDER, l.KeyMode)
	return f
}

// Localhost issues a server certificate for localhost, 127.0.0.1 and ::1.
func (c *CA) Localhost(tb testing.TB, dir string) Files {
	tb.Helper()
	return c.Issue(tb, dir, Leaf{
		Name:     "server",
		DNSNames: []string{"localhost"},
		IPs:      []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	})
}

func writePEM(tb testing.TB, path, typ string, der []byte, mode os.FileMode) {
	tb.Helper()
	b := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	if err := os.WriteFile(path, b, mode); err != nil {
		tb.Fatal(err)
	}
	// WriteFile's mode is subject to the umask and ignored for an existing
	// file; set it exactly.
	if err := os.Chmod(path, mode); err != nil {
		tb.Fatal(err)
	}
}

func must(tb testing.TB, err error) {
	tb.Helper()
	if err != nil {
		tb.Fatal(err)
	}
}
