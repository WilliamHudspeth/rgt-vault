#!/usr/bin/env python3
import re
import sys
from pathlib import Path

SENSITIVE_PATTERNS = [
    re.compile(r"TODO|FIXME|BUG", re.IGNORECASE),
    re.compile(r"password|credential|token|secret|key", re.IGNORECASE),
    re.compile(r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}"),  # Private IPs
]
HTML_COMMENT_RE = re.compile(r"<!--[\s\S]*?-->")
JS_COMMENT_RE = re.compile(r"\/\/.*|\/\*[\s\S]*?\*\/")

def check_file(path: Path) -> bool:
    content = path.read_text(errors="ignore")
    has_leak = False

    # Extract comments
    comments = []
    if path.suffix in (".html", ".tmpl", ".tpl"):
        comments.extend(HTML_COMMENT_RE.findall(content))
    if path.suffix == ".js":
        comments.extend(JS_COMMENT_RE.findall(content))

    for comment in comments:
        for pattern in SENSITIVE_PATTERNS:
            if pattern.search(comment):
                print(f"[LEAK] Sensitive comment found in {path}: {comment.strip()}")
                has_leak = True
    return has_leak

def main():
    has_errors = False
    for p in Path(".").rglob("*"):
        if p.suffix in (".html", ".js", ".tmpl", ".tpl") and ".venv" not in p.parts and "node_modules" not in p.parts:
            if check_file(p):
                has_errors = True
    if has_errors:
        sys.exit(1)
    print("All template comment scans passed.")

if __name__ == "__main__":
    main()
