package transport

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"
)

// ExpiryWarning is how long before NotAfter a certificate is reported as
// "expires soon".
const ExpiryWarning = 14 * 24 * time.Hour

// CertInfo describes the loaded leaf certificate (for logs; never the key).
type CertInfo struct {
	Subject  string
	Serial   string
	NotAfter time.Time
	DNSNames []string
	IPs      []string
	Warnings []string
}

// LoadCertificate loads and validates a server certificate/key pair:
//
//   - the key file must not be readable by group/other (CheckKeyFile);
//   - the pair must match (a mismatch fails here, not at the first client);
//   - the leaf must be inside its validity window (expired or not yet valid
//     is an error), must carry at least one Subject Alternative Name (Go and
//     every browser ignore the CN), must be usable for server
//     authentication, must not be signed with MD5/SHA-1 (RGT-456) and an RSA
//     key must be at least 2048 bits.
//
// A certificate that expires within ExpiryWarning is accepted with a warning
// in CertInfo.Warnings.
func LoadCertificate(certFile, keyFile string, now time.Time) (*tls.Certificate, CertInfo, error) {
	if certFile == "" || keyFile == "" {
		return nil, CertInfo{}, errors.New("both a certificate file and a private key file are required")
	}
	// The key is opened, checked and read through one descriptor (no
	// check-then-read race).
	keyPEM, err := ReadKeyFile(keyFile)
	if err != nil {
		return nil, CertInfo{}, err
	}
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, CertInfo{}, fmt.Errorf("certificate: %w", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, CertInfo{}, fmt.Errorf("certificate %s and key %s: %w", certFile, keyFile, err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, CertInfo{}, fmt.Errorf("certificate %s: %w", certFile, err)
	}
	warns, err := checkLeaf(leaf, now)
	if err != nil {
		return nil, CertInfo{}, fmt.Errorf("certificate %s: %w", certFile, err)
	}
	pair.Leaf = leaf
	info := CertInfo{
		Subject:  leaf.Subject.String(),
		Serial:   leaf.SerialNumber.Text(16),
		NotAfter: leaf.NotAfter,
		DNSNames: append([]string(nil), leaf.DNSNames...),
		Warnings: warns,
	}
	for _, ip := range leaf.IPAddresses {
		info.IPs = append(info.IPs, ip.String())
	}
	return &pair, info, nil
}

// timeWindowError is a validity-window failure: unlike a corrupt file it
// fixes itself as the clock advances, so a reload that hit it is retried.
type timeWindowError struct{ msg string }

func (e *timeWindowError) Error() string { return e.msg }

// checkLeaf applies the certificate policy to leaf at time now.
func checkLeaf(leaf *x509.Certificate, now time.Time) (warnings []string, err error) {
	if now.Before(leaf.NotBefore) {
		return nil, &timeWindowError{fmt.Sprintf("not valid before %s", leaf.NotBefore.UTC().Format(time.RFC3339))}
	}
	if now.After(leaf.NotAfter) {
		return nil, &timeWindowError{fmt.Sprintf("expired on %s", leaf.NotAfter.UTC().Format(time.RFC3339))}
	}
	if left := leaf.NotAfter.Sub(now); left < ExpiryWarning {
		warnings = append(warnings, fmt.Sprintf("expires in %s (%s): renew it and reload with SIGHUP",
			left.Round(time.Hour), leaf.NotAfter.UTC().Format(time.RFC3339)))
	}
	if len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 {
		return nil, errors.New("no Subject Alternative Name: clients match the host name against the SAN only, " +
			"never the CN; reissue it with the server's DNS name or IP address")
	}
	if leaf.IsCA {
		return nil, errors.New("this is a CA certificate, not a server certificate")
	}
	if len(leaf.ExtKeyUsage) > 0 && !hasServerAuth(leaf.ExtKeyUsage) {
		return nil, errors.New("extended key usage lacks serverAuth")
	}
	switch leaf.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return nil, fmt.Errorf("weak signature algorithm %s: reissue it with SHA-256 or better", leaf.SignatureAlgorithm)
	}
	if pub, ok := leaf.PublicKey.(*rsa.PublicKey); ok && pub.N.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA key of %d bits is too weak: use at least 2048 (or an ECDSA P-256 key)", pub.N.BitLen())
	}
	return warnings, nil
}

func hasServerAuth(usages []x509.ExtKeyUsage) bool {
	for _, u := range usages {
		if u == x509.ExtKeyUsageServerAuth || u == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

// LoadCAPool reads a PEM bundle of CA certificates. An empty or
// unparsable bundle is an error: an empty pool would silently trust nothing
// (or, for a nil pool, everything the OS trusts).
func LoadCAPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA file %s contains no valid PEM certificate", path)
	}
	return pool, nil
}
