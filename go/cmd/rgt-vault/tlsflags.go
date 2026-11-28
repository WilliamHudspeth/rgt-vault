package main

import (
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/transport"
)

// clientTLSFlags are the transport options of every command that talks to a
// server (batch H6, RGT-251/422/455/458): https:// URLs are verified against
// the system trust store, or against --cacert alone; TLS 1.2 is the floor and
// only AEAD suites are offered. There is deliberately no flag that turns
// certificate verification off.
type clientTLSFlags struct {
	cacert            string
	clientCert        string
	clientKey         string
	allowInsecureHTTP bool
}

func (f *clientTLSFlags) register(cmd *cobra.Command) {
	pf := cmd.PersistentFlags()
	pf.StringVar(&f.cacert, "cacert", "", "PEM file of the CA(s) that signed the server certificate; replaces the system trust store (env "+transport.EnvCACert+")")
	pf.StringVar(&f.clientCert, "client-cert", "", "PEM client certificate for a server that requires mutual TLS (env "+transport.EnvClientCert+")")
	pf.StringVar(&f.clientKey, "client-key", "", "PEM private key of --client-cert; must not be readable by group/other (env "+transport.EnvClientKey+")")
	pf.BoolVar(&f.allowInsecureHTTP, "allow-insecure-http", false, "allow sending the token over plain http:// to a NON-loopback host (a trusted network only; https is the default way)")
}

func (f *clientTLSFlags) options() transport.ClientOptions {
	return transport.ClientOptionsFromEnv(transport.ClientOptions{
		CACertFile: f.cacert, ClientCertFile: f.clientCert, ClientKeyFile: f.clientKey,
	}, os.Getenv)
}

// prepare validates the server URL (https, or http to loopback) and builds
// the transport. It returns the URL without a trailing slash.
func (f *clientTLSFlags) prepare(host string) (string, http.RoundTripper, error) {
	base := strings.TrimSuffix(host, "/")
	if _, err := transport.CheckBaseURL(base, f.allowInsecureHTTP); err != nil {
		return base, nil, err
	}
	tr, err := transport.NewTransport(f.options())
	if err != nil {
		return base, nil, err
	}
	return base, tr, nil
}
