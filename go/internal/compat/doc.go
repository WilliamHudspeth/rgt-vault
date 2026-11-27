// Package compat is the Python <-> Go compatibility suite (batch G12). It has
// no production code: every test drives the FULL Go stack (providers ->
// keychain -> store -> vault -> server / CLI) against vaults that the frozen
// Python implementation wrote, and, where a Python interpreter is available,
// the other way round.
//
// Layers (each skips cleanly when its prerequisite is missing, so a plain
// `go test ./...` stays hermetic):
//
//   - fixtures_test.go, edge_test.go: always run. Open every G0 fixture
//     (go/testdata/pyvault: small, default, epoch1, edge/*.db) through
//     server.OpenStack and the HTTP handler, decrypt every secret against
//     manifest.json, compare chain verdicts with Python's, then write,
//     RotateDEK and RotateMaster through the HTTP API and re-verify.
//   - cli_test.go: always run. Builds the real rgt-vault binary and runs the
//     read-only migration commands (migrate check, verify-audit, status)
//     against the same fixtures, with Python's exit codes pinned.
//   - python_test.go: needs RGT_VAULT_PYTHON (a Python with rgt_vault
//     installed). Python opens the vault Go modified and rotated, reads every
//     version, verifies the chain, imports Go's export and writes; Go reads
//     Python's write and imports Python's export.
//   - keyring_test.go: needs RGT_VAULT_PYTHON and RGT_COMPAT_KEYRING=1 and a
//     working Secret Service (see the compat CI job). Python creates a real
//     vault whose master secret lives in the OS keyring, the real rgt-vault
//     binary migrates it in place (serve, set, rotate, export), and Python
//     opens it again.
//
// Run all of it:
//
//	python3 -m venv .venv && .venv/bin/pip install -e '.[server,dev]'
//	RGT_VAULT_PYTHON=$PWD/.venv/bin/python go test ./internal/compat
package compat
