# rgt-vault

> ## ⚠️ MAINTENANCE MODE — This is the Python (v0.2.x) line.
>
> The Python implementation is in **maintenance mode** as of 2026-06-22.
> It receives **bugfixes and security patches only**; **all new feature work
> lands in the [Go rewrite](go/)** (`rgt-vault-server`, v0.3.0).
>
> - **New users:** install the Go binary — see [`go/cmd/server/`](go/cmd/server/)
>   and `go/README.md`. The Go line is the primary, supported release.
> - **Existing Python users:** stay on the latest `v0.2.x` tag for security
>   fixes. The Python line will be **archived 6 months after v0.3.0 ships**.
> - **Why:** the [v0.3 capability-based execution layer](go/) (RGT-128,
>   RGT-166) is fundamentally a Go architecture; reimplementing it in Python
>   would lock in tech debt. See [`eol.md`](docs/program/eol.md) for the full migration
>   plan and the 2026-12-22 EOL date.
>
> Tracked by RGT-164 (maintenance mode notice) → RGT-165 (EOL archive notice; see [`eol.md`](docs/program/eol.md) for the full migration plan and 2026-12-22 EOL date).

A local-first secrets manager designed for autonomous AI systems. It combines
AES-256-GCM encryption, Argon2id key derivation, ABAC authorization, secret
leasing, audit logging, and agent-aware access controls to reduce secret
exposure in LLM-powered applications.

> **Status: `v0.2.0` — Security Preview.** Suitable for evaluation and
> feedback, not yet for protecting production secrets. APIs and on-disk formats
> may change before `v1.0.0`. Read the [threat model](docs/security/threat-model.md) and
> [SECURITY.md](SECURITY.md) before relying on it.

## 📖 Documentation

The documentation has been thoroughly reorganized. Please start here:

👉 **[Read the Full Documentation](docs/README.md)** 👈

**Quick Links:**
- [Usage Guide (CLI, Python API, Policies)](docs/guides/usage.md)
- [Architecture & Design](docs/architecture/core-architecture.md)
- [Threat Model](docs/security/threat-model.md)
- [Installation Guide](docs/guides/install.md)

## Installation

```bash
pip install -e .            # editable / development install
# or, once published:
# pip install rgt-vault
```

Requires Python ≥ 3.9 and `cryptography >= 44` (for Argon2id). On Windows, the
DPAPI provider additionally needs `pywin32` (`pip install -e ".[windows]"`).

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

The test suite uses an in-memory master-secret provider and temporary
directories; it does not require a real TPM/DPAPI/Keychain.

## License

[Apache-2.0](LICENSE).
