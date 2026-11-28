// Command gateway is the RGT-162 cutover proxy.
//
// It fronts the Python rgt-vault server and routes a configurable percentage
// of traffic to the Go server. It starts at 0% Go (full Python) and an operator
// ramps it up. Rollback is instant:
//
//	curl -X PUT -H "Authorization: Bearer $(cat ~/.config/rgt-vault/gateway-operator.token)" \
//	     'http://127.0.0.1:8088/__cutover?go=0'
//
// The admin API (/__cutover, /__cutover/stats) requires the operator token,
// which is created (0600) on first start. The gateway binds to loopback by
// default; a non-loopback -addr is refused unless it serves TLS (-tls-cert and
// -tls-key; -tls-client-ca adds mutual TLS) or -allow-non-loopback is set.
// Backends must be https:// (verified, optionally against -backend-cacert
// only) or loopback http:// unless -allow-insecure-backends is set. TLS policy:
// internal/transport (TLS 1.2+, AEAD suites; SIGHUP reloads the certificate).
//
// Python is always the safe backend; Go-backend transport failures fall back
// to Python transparently.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/auth"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/gateway"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/transport"
)

func defaultTokenPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "gateway-operator.token"
	}
	return filepath.Join(home, ".config", "rgt-vault", "gateway-operator.token")
}

func main() {
	var (
		addr             = flag.String("addr", gateway.DefaultListenAddr, "gateway listen address (loopback by default)")
		allowNonLoopback = flag.Bool("allow-non-loopback", false, "permit binding -addr to a non-loopback interface WITHOUT TLS (insecure)")
		tlsCert          = flag.String("tls-cert", "", "PEM certificate: serve HTTPS")
		tlsKey           = flag.String("tls-key", "", "PEM private key for -tls-cert (refused if group/other can read it)")
		tlsClientCA      = flag.String("tls-client-ca", "", "PEM CA bundle for client certificates (mutual TLS)")
		tlsClientAuth    = flag.String("tls-client-auth", "", "require (default with -tls-client-ca) or verify-if-given")
		tlsReload        = flag.Duration("tls-reload-interval", time.Minute, "poll the TLS files for changes (0 = SIGHUP only)")
		backendCACert    = flag.String("backend-cacert", "", "PEM CA bundle to verify https backends (replaces the system trust store)")
		insecureBackends = flag.Bool("allow-insecure-backends", false, "allow plain http:// backends on non-loopback hosts (tokens cross the network unencrypted)")
		pythonURL        = flag.String("python-url", "http://localhost:8080", "Python backend base URL")
		goURL            = flag.String("go-url", "http://localhost:8099", "Go backend base URL")
		goPercent        = flag.Int("go-percent", 0, "initial percent of traffic to route to Go (0-100)")
		tokenFile        = flag.String("operator-token-file", defaultTokenPath(), "operator bearer token for the /__cutover admin API (created 0600 if missing)")
	)
	flag.Parse()

	tlsOpts := gateway.TLSOptions{CertFile: *tlsCert, KeyFile: *tlsKey, ClientCAFile: *tlsClientCA,
		ClientAuth: *tlsClientAuth, ReloadInterval: *tlsReload}
	if err := gateway.CheckListen(*addr, tlsOpts.Enabled(), *allowNonLoopback); err != nil {
		log.Fatal(err)
	}
	if !gateway.IsLoopbackAddr(*addr) && !tlsOpts.Enabled() {
		log.Printf("WARNING: INSECURE: serving PLAIN HTTP on non-loopback %s (-allow-non-loopback)", *addr)
	}
	for name, u := range map[string]string{"python": *pythonURL, "go": *goURL} {
		if err := gateway.ValidateBackendURL(name, u, *insecureBackends); err != nil {
			log.Fatal(err)
		}
	}

	path, _, err := auth.LoadOrCreateToken(*tokenFile)
	if err != nil {
		log.Fatalf("operator token: %v", err)
	}
	// LoadOrCreateToken reuses an existing file as-is; never serve with a
	// token file others can read.
	if err := os.Chmod(path, 0o600); err != nil {
		log.Fatalf("operator token: restricting %s: %v", path, err)
	}

	gw, err := gateway.NewGateway(*pythonURL, *goURL, *goPercent)
	if err != nil {
		log.Fatalf("gateway init failed: %v", err)
	}
	gw.SetOperatorTokenStore(auth.NewTokenStore(path))
	backendTransport, err := transport.NewTransport(transport.ClientOptions{CACertFile: *backendCACert})
	if err != nil {
		log.Fatalf("backend TLS: %v", err)
	}
	gw.SetBackendTransport(backendTransport)

	fmt.Println("===============================================")
	fmt.Println("  rgt-vault cutover gateway (RGT-162)")
	fmt.Printf("  Listening:  %s\n", *addr)
	fmt.Printf("  Python:     %s (safe backend)\n", *pythonURL)
	fmt.Printf("  Go:         %s\n", *goURL)
	fmt.Printf("  Go traffic: %d%%\n", gw.GoPercent())
	fmt.Printf("  Admin token file: %s\n", path)
	fmt.Println("  Ramp:     curl -X PUT -H 'Authorization: Bearer <token>' 'http://" + *addr + "/__cutover?go=N'")
	fmt.Println("  Rollback: curl -X PUT -H 'Authorization: Bearer <token>' 'http://" + *addr + "/__cutover?go=0'")
	fmt.Println("  Stats:    GET /__cutover/stats (same header)")
	fmt.Println("===============================================")

	srv, tlsState, err := gateway.NewHTTPServer(*addr, gw, tlsOpts, log.Printf)
	if err != nil {
		log.Fatalf("TLS: %v", err)
	}
	if tlsState == nil {
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("gateway server failed: %v", err)
		}
		return
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	trigger := make(chan struct{}, 1)
	go func() {
		for range hup {
			select {
			case trigger <- struct{}{}:
			default:
			}
		}
	}()
	go tlsState.Watch(context.Background(), trigger, tlsOpts.ReloadInterval)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("gateway server failed: %v", err)
	}
}
