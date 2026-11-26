## Summary

<!-- What does this PR change and why? -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Security hardening
- [ ] Documentation
- [ ] Refactor / chore

## Security checklist

- [ ] No secret plaintext is logged, returned, or placed in exceptions/audit records
- [ ] Crypto/authorization/audit/storage changes include tests
- [ ] All salts/nonces/keys use a CSPRNG (`crypto/rand` in Go; `os.urandom`/`secrets` in Python)
- [ ] Docs do not overstate guarantees (partial/best-effort protections are labeled)
- [ ] **Threat-model impact:** this PR does not add or change a component, trust
      boundary, authentication, authorization, audit, crypto, storage or
      outbound-network behavior, **or** I updated
      `docs/security/threat-model.md` in this PR (delete the one that does not apply)
- [ ] New or changed input handling validates and bounds its input and has a denial-path test

## Validation

- [ ] `cd go && go vet ./... && go test ./...` passes (CI does not run these on PRs)
- [ ] `pytest -q` passes (if the legacy Python code is touched)
- [ ] `CHANGELOG.md` updated under "Unreleased"
- [ ] Relevant docs updated (README / ARCHITECTURE / SECURITY / llm_guide)

## Related issues

<!-- Every PR links the issue or change ticket it addresses (source-control traceability).
     Use one line per issue: `Closes RGT-123` (tracker) and/or `Closes #123` (GitHub).
     Use `Refs RGT-123` when the PR only partly addresses it. -->

Closes RGT-
