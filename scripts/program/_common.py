"""Shared helpers for the rgt-vault program management scripts.

Imports the Multica API and exposes high-level queries:
  - list_issues(workspace_id) → all tickets
  - get_issue(tid) → single ticket with full detail
  - list_labels(workspace_id) → all labels
  - list_projects(workspace_id) → all projects (milestones)

Tokens read from ~/.multica/config.json (the standard Multica PAT).
"""

import json
import urllib.error
import urllib.request
from pathlib import Path

WORKSPACE_ID = "8a622480-5997-4491-9ff5-17e4a602aab5"
MULTICA_API = "http://10.10.88.88:8080"


def _token() -> str:
    """Read the Multica PAT from the controller's config.

    Uses a context manager so the file handle doesn't leak (OPUS-100).
    Raises FileNotFoundError if the file is missing and KeyError if the
    'token' key isn't present.
    """
    cfg_path = Path.home() / ".multica" / "config.json"
    with open(cfg_path) as f:
        data = json.load(f)
    if "token" not in data:
        raise KeyError(f"'token' key missing from {cfg_path}; expected Multica PAT config")
    return data["token"]


def _hdr() -> str:
    # OPUS-92: was chr(66)+chr(101)+chr(97)+chr(114)+chr(101)+chr(114)
    # = "Bearer", exactly the banned secret-redaction pattern.
    return "Bearer " + _token()


def _get(path):
    req = urllib.request.Request(
        f"{MULTICA_API}{path}",
        headers={"Authorization": _hdr(), "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def _put(path, body):
    req = urllib.request.Request(
        f"{MULTICA_API}{path}",
        method="PUT",
        headers={"Authorization": _hdr(), "Accept": "application/json", "Content-Type": "application/json"},
        data=json.dumps(body).encode(),
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode()[:300]}


def list_issues(workspace_id=WORKSPACE_ID, limit=200):
    """Return all tickets in the workspace."""
    data = _get(f"/api/issues?workspace_id={workspace_id}&limit={limit}")
    return data.get("issues", [])


def get_issue(tid, workspace_id=WORKSPACE_ID):
    """Fetch full ticket detail by identifier (RGT-N) or UUID.

    Resolves identifier -> uuid with a single list call, then hits the
    direct /api/issues/{uuid} endpoint.

    Note: the *list* call still has a server-side limit, so if you have
    more than `limit` (default 200) issues in the workspace, an
    identifier that sorts after the first 200 will return None. This
    is a server-side pagination concern; pass a higher `limit` if
    you need to resolve old tickets. Callers like release_gate and
    dashboard should pass a generous limit.
    """
    issues = list_issues(workspace_id, limit=1000)
    for i in issues:
        if i.get("identifier") == tid or i.get("id") == tid:
            tid_uuid = i["id"]
            break
    else:
        return None
    return _get(f"/api/issues/{tid_uuid}?workspace_id={workspace_id}")


def list_labels(workspace_id=WORKSPACE_ID):
    """Return all labels in the workspace as {name: uuid, ...}."""
    data = _get(f"/api/labels?workspace_id={workspace_id}")
    labels = data if isinstance(data, list) else data.get("labels", [])
    return {l["name"]: l["id"] for l in labels}


def list_projects(workspace_id=WORKSPACE_ID):
    """Return all milestone projects."""
    data = _get(f"/api/projects?workspace_id={workspace_id}")
    return data if isinstance(data, list) else data.get("projects", [])


def milestone_lookup(workspace_id=WORKSPACE_ID):
    """Return {short_name: uuid} for milestones — short name is the part before the first ' - '."""
    projects = list_projects(workspace_id)
    return {p["title"].split(" - ")[0]: p["id"] for p in projects}


def label_set(issue):
    """Return {name} set from a full ticket dict."""
    return {l["name"] for l in issue.get("labels", [])}


def effort_size(issue):
    """Return effort label or 'unknown'."""
    for l in label_set(issue):
        if l.startswith("effort:"):
            return l.split(":", 1)[1]
    return "unknown"


def priority_label(issue):
    """Return pri:* label or 'none'."""
    for l in label_set(issue):
        if l.startswith("pri:"):
            return l.split(":", 1)[1]
    return "none"


def is_active(issue):
    return issue.get("status") in ("todo", "in_progress", "in_review", "backlog", "blocked")
