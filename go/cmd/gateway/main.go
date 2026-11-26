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
// default; a non-loopback -addr is refused unless -allow-non-loopback is set.
//
// Python is always the safe backend; Go-backend transport failures fall back
// to Python transparently.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/gateway"
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
		allowNonLoopback = flag.Bool("allow-non-loopback", false, "permit binding -addr to a non-loopback interface")
		pythonURL        = flag.String("python-url", "http://localhost:8080", "Python backend base URL")
		goURL            = flag.String("go-url", "http://localhost:8099", "Go backend base URL")
		goPercent        = flag.Int("go-percent", 0, "initial percent of traffic to route to Go (0-100)")
		tokenFile        = flag.String("operator-token-file", defaultTokenPath(), "operator bearer token for the /__cutover admin API (created 0600 if missing)")
	)
	flag.Parse()

	if !gateway.IsLoopbackAddr(*addr) && !*allowNonLoopback {
		log.Fatalf("refusing to bind %s: not a loopback address (pass -allow-non-loopback to override)", *addr)
	}

	path, _, err := auth.LoadOrCreateToken(*tokenFile)
	if err != nil {
		log.Fatalf("operator token: %v", err)
	}

	gw, err := gateway.NewGateway(*pythonURL, *goURL, *goPercent)
	if err != nil {
		log.Fatalf("gateway init failed: %v", err)
	}
	gw.SetOperatorTokenStore(auth.NewTokenStore(path))

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

	srv := &http.Server{Addr: *addr, Handler: gw, ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("gateway server failed: %v", err)
	}
}
