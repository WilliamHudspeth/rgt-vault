// Command gateway is the RGT-162 cutover proxy.
//
// It fronts the Python rgt-vault server and routes a configurable percentage
// of traffic to the Go server. It starts at 0% Go (full Python) and an operator
// ramps it up. Rollback is instant:
//
//	curl -X PUT 'http://localhost:8088/__cutover?go=0'
//
// Python is always the safe backend; Go-backend transport failures fall back
// to Python transparently.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"rgt-vault-server/internal/gateway"
)

func main() {
	var (
		addr       = flag.String("addr", ":8088", "gateway listen address")
		pythonURL  = flag.String("python-url", "http://localhost:8080", "Python backend base URL")
		goURL      = flag.String("go-url", "http://localhost:8099", "Go backend base URL")
		goPercent  = flag.Int("go-percent", 0, "initial percent of traffic to route to Go (0-100)")
	)
	flag.Parse()

	gw, err := gateway.NewGateway(*pythonURL, *goURL, *goPercent)
	if err != nil {
		log.Fatalf("gateway init failed: %v", err)
	}

	fmt.Println("===============================================")
	fmt.Println("  rgt-vault cutover gateway (RGT-162)")
	fmt.Printf("  Listening:  %s\n", *addr)
	fmt.Printf("  Python:     %s (safe backend)\n", *pythonURL)
	fmt.Printf("  Go:         %s\n", *goURL)
	fmt.Printf("  Go traffic: %d%%\n", gw.GoPercent())
	fmt.Println("  Ramp:    curl -X PUT 'http://HOST" + *addr + "/__cutover?go=N'")
	fmt.Println("  Rollback: curl -X PUT 'http://HOST" + *addr + "/__cutover?go=0'")
	fmt.Println("  Stats:      GET /__cutover/stats")
	fmt.Println("===============================================")

	if err := http.ListenAndServe(*addr, gw); err != nil {
		log.Fatalf("gateway server failed: %v", err)
	}
}
