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
- [ ] All salts/nonces/keys use `os.urandom`
- [ ] Docs do not overstate guarantees (partial/best-effort protections are labeled)

## Validation

- [ ] `pytest -q` passes
- [ ] `CHANGELOG.md` updated under "Unreleased"
- [ ] Relevant docs updated (README / ARCHITECTURE / SECURITY / llm_guide)

## Related issues

<!-- e.g. Closes #123 -->
