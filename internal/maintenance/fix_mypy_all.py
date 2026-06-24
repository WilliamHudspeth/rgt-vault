# 1. scripts/llm/providers/_http.py:41: error: Incompatible types in assignment (expression has type "str", variable has type "dict[Any, Any]")  [assignment]
with open("scripts/llm/providers/_http.py", "r") as f:
    http = f.read()
http = http.replace('        body = e.read()[:500].decode("utf-8", errors="replace")\n        raise HTTPStatusError(e.code, body) from e', 
                    '        err_body = e.read()[:500].decode("utf-8", errors="replace")\n        raise HTTPStatusError(e.code, err_body) from e')
with open("scripts/llm/providers/_http.py", "w") as f:
    f.write(http)

# 2. scripts/llm/tests/test_cli_providers.py:25: error: Function "builtins.callable" is not valid as a type
with open("scripts/llm/tests/test_cli_providers.py", "r") as f:
    cli = f.read()
cli = cli.replace('def _force_which(name: str, body: str) -> "callable":', 'def _force_which(name: str, body: str) -> "typing.Callable":')
cli = cli.replace('import tempfile', 'import tempfile\n    import typing')
with open("scripts/llm/tests/test_cli_providers.py", "w") as f:
    f.write(cli)

# 3. tests/test_token.py: remove type ignores
with open("tests/test_token.py", "r") as f:
    tok = f.read()
tok = tok.replace('  # type: ignore[arg-type]', '')
tok = tok.replace('  # type: ignore[attr-defined]', '')
with open("tests/test_token.py", "w") as f:
    f.write(tok)

# 4. tests/test_shadow.py: type annotations
with open("tests/test_shadow.py", "r") as f:
    shad = f.read()
shad = shad.replace('self.sets = []', 'self.sets: list = []')
shad = shad.replace('self.revokes = []', 'self.revokes: list = []')
with open("tests/test_shadow.py", "w") as f:
    f.write(shad)

# 5. tests/test_capabilities.py: remove type ignore
with open("tests/test_capabilities.py", "r") as f:
    cap = f.read()
cap = cap.replace('  # type: ignore[attr-defined]', '')
cap = cap.replace('  # type: ignore[arg-type]', '')
with open("tests/test_capabilities.py", "w") as f:
    f.write(cap)

# 6. review-gate.yml: add explicit-package-bases
with open(".github/workflows/review-gate.yml", "r") as f:
    rg = f.read()
rg = rg.replace('run: mypy rgt_vault/ tests/ scripts/', 'run: mypy --explicit-package-bases rgt_vault/ tests/ scripts/')
with open(".github/workflows/review-gate.yml", "w") as f:
    f.write(rg)

