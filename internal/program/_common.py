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


def list_issues(workspace_id=WORKSPACE_ID, limit=200, max_pages=100):
    """Return all tickets in the workspace, paginated (RGT-89).

    The API caps each response to `limit` (page_size) and reports `total`.
    We loop on `offset` until we've fetched `total` issues or hit a short
    page. `max_pages` is a safety cap so a misbehaving server can't spin
    this forever.
    """
    issues = []
    offset = 0
    for _ in range(max_pages):
        data = _get(f"/api/issues?workspace_id={workspace_id}&limit={limit}&offset={offset}")
        batch = data.get("issues") or []
        issues.extend(batch)
        total = data.get("total")
        offset += len(batch)
        if len(batch) < limit or (total is not None and offset >= total):
            break
    return issues


def get_issue(tid, workspace_id=WORKSPACE_ID):
    """Fetch full ticket detail by identifier (RGT-N) or UUID.

    Resolves identifier -> uuid with a single (now-paginated) list call,
    then hits the direct /api/issues/{uuid} endpoint. list_issues() fetches
    every ticket in the workspace, so no `limit` kludge is needed here
    (RGT-89 — previously identifiers sorting past a capped page returned
    None).
    """
    issues = list_issues(workspace_id)
    for i in issues:
        if i.get("identifier") == tid or i.get("id") == tid:
            tid_uuid = i["id"]
            break
    else:
        return None
    return _get(f"/api/issues/{tid_uuid}?workspace_id={workspace_id}")


def list_members(workspace_id=WORKSPACE_ID):
    """Return {member_id: display_name} for the workspace.

    Multica exposes this at /api/workspaces/{id}/members (not /api/members —
    confirmed by probing the live API 2026-07-27; that path 404s). There is
    no status-transition history endpoint (/history, /activity both 404),
    which is why wip_audit's staleness checks fall back to updated_at
    (see RGT-99).
    """
    data = _get(f"/api/workspaces/{workspace_id}/members")
    members = data if isinstance(data, list) else data.get("members", [])
    return {m["id"]: m.get("name") or m.get("email") or m["id"] for m in members}


def list_labels(workspace_id=WORKSPACE_ID):
    """Return all labels in the workspace as {name: uuid, ...}."""
    data = _get(f"/api/labels?workspace_id={workspace_id}")
    labels = data if isinstance(data, list) else data.get("labels", [])
    return {lbl["name"]: lbl["id"] for lbl in labels}


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
    return {lbl["name"] for lbl in issue.get("labels", [])}


def effort_size(issue):
    """Return effort label or 'unknown'."""
    for lbl in label_set(issue):
        if lbl.startswith("effort:"):
            return lbl.split(":", 1)[1]
    return "unknown"


def priority_label(issue):
    """Return pri:* label or 'none'."""
    for lbl in label_set(issue):
        if lbl.startswith("pri:"):
            return lbl.split(":", 1)[1]
    return "none"


def is_active(issue):
    return issue.get("status") in ("todo", "in_progress", "in_review", "backlog", "blocked")
