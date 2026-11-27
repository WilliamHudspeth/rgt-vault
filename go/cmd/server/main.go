// Command server is the DEPRECATED alias of `rgt-vault serve`.
//
// It is kept so existing deployments (deploy/rgt-vault-go.service runs it as
// rgt-vault-server) keep working. It runs exactly the same code as
// `rgt-vault serve` (internal/servecmd): the real vault on --db with the ABAC
// --policy, the hash-chained audit log and, optionally, the live approval
// broker with TOTP. New installs should run `rgt-vault serve`.
//
// Usage:
//
//	rgt-vault-server [--db PATH] [--policy FILE] [--provider keyring|platform]
//	                 [--host 127.0.0.1] [--port 8765] [--token-file PATH]
//	                 [--operator-token-file PATH] [--require-approval
//	                 [--totp-secret-file PATH] [--approval-timeout 120s]]
//	                 [--harness-key-file PATH] [--allow-private-network]
//	                 [--allow-non-loopback]
//
// See `go doc rgt-vault-server/internal/servecmd` for every flag and
// environment variable. Differences from the pre-G10 binary: flags need two
// dashes (--port, not -port), and a non-loopback --host needs
// --allow-non-loopback (it used to be accepted with a warning).
package main

import (
	"fmt"
	"os"

	"rgt-vault-server/internal/servecmd"
)

func main() {
	os.Exit(run(os.Args[1:], servecmd.Env{}))
}

// run executes the alias with env (tests inject providers and streams) and
// returns the process exit code.
func run(args []string, env servecmd.Env) int {
	cmd := servecmd.NewCommand(env, nil)
	cmd.Use = "rgt-vault-server"
	cmd.Short = "DEPRECATED: use `rgt-vault serve`"
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetOut(os.Stderr)
	cmd.SetErr(os.Stderr)
	fmt.Fprintln(os.Stderr, "rgt-vault-server is deprecated: use `rgt-vault serve` (same flags).")
	return servecmd.Main(cmd, args)
}
