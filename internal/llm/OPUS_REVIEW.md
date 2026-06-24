# Opus Code Review — 2026-06-17

Opus (`claude -p --model opus`) reviewed 4 files in the multi-LLM router project.
Findings grouped by severity and file. Each finding has a tracking number (OPUS-N)
for reference from Multica issues.

## Summary

| File | Critical | Major | Minor |
|------|----------|-------|-------|
| router.py | 3 | 3 | 1 |
| providers/cli.py | 3 | 2 | 1 |
| kanban_loop.py | 4 | 2 | 1 |
| routes.yaml | 2 | 0 | 1 |
| **Total** | **12** | **7** | **4** |

---

## router.py (the multi-LLM Router core)

### Critical

- **OPUS-1**: An exception inside `call()` (not just an `ok=False` reply) aborts the whole chain instead of falling through. Same in `call_parallel._one`: a single provider exception makes `f.result()` re-raise and kills the entire fan-out. Only `build`/`is_available` are guarded.
- **OPUS-2**: `env_path` is parsed from yaml but never loaded. If it's meant to populate provider API keys, keys silently won't be set. Either load it (e.g. dotenv) or drop the field.
- **OPUS-3**: Timeouts aren't enforced at the executor. `f.result()` has no timeout, so the whole call hangs as long as the slowest provider does. Use `future.result(timeout=...)`.

### Major

- **OPUS-4**: `review_pair` collapses duplicate specs. `reply_by_spec = dict(results)` keys by spec; if `primary == secondary` (misconfig), both keys point at the same Reply. Key by role/index instead.
- **OPUS-5**: `_quick_agreement` substring matching is unreliable. `"fine"` matches "define/refined"; `"but "` is brittle; `"however"` in either reply forces "partial" even when both clearly agree. Use word-boundary regex and weigh both sides.
- **OPUS-6**: TOCTOU + double latency. `is_available()` then `complete()` are separate round-trips; provider can go away between them, and you pay two network calls per attempt. Let `complete()` fail-fast and treat that as unavailable.

### Minor

- **OPUS-7**: `os` import is unused; `writer_for` is dead within this module. `writers`/`writer_for` are wired up and never called by any code path here — confirm an external caller uses them or they're cruft.

---

## providers/cli.py (subprocess wrappers for Claude/Gemini)

### Critical

- **OPUS-8**: Timeout doesn't reap grandchildren. `subprocess.run(timeout=...)` kills the direct child on `TimeoutExpired`, but `claude`/`gemini` are Node wrappers that fork helper processes. Orphans keep running and keep consuming quota. Start child in its own process group (`start_new_session=True`) and `os.killpg` on timeout.
- **OPUS-9**: Gemini stderr/stdout filtering is wrong and lossy. The comment says the warning lands on stderr, but the code filters it out of stdout — so the filter never matches the real warning, yet *will* silently delete any legitimate answer line starting with `"Warning:"`. Drop the stdout filter; suppress the banner from `proc.stderr` if needed.
- **OPUS-10**: `env=os.environ` hands the full parent environment to the child, leaking secrets/API keys unnecessarily. Pass a curated copy.

### Major

- **OPUS-11**: stderr is embedded raw into `Reply.error` (truncated to 300 chars). If these Replies get logged or surfaced to a UI, CLI stderr can contain paths, tokens, or auth hints. Scrub before crossing a trust boundary.

### Minor

- **OPUS-12**: Empty-output success is indistinguishable from failure. A `returncode == 0` with empty stdout returns `text=""` and `ok=True`. Treat empty output on 0 exit as a soft error.

---

## kanban_loop.py (the AFK Multica processor)

### Critical

- **OPUS-13**: `post_comment` has no try/except. One raised exception propagates out of `main()`, kills the process, and discards state for everything already posted this pass → those get re-posted next run. Wrap each ticket iteration in try/except.
- **OPUS-14**: Retry storm on failures — no backoff, no failure cap. A persistent failure (auth 401, 500, provider outage) causes expensive LLM + POST attempts every 60s forever. Track failure count + apply exponential backoff or max-retries-then-skip.
- **OPUS-15**: `--reset-state` + `--loop` re-posts duplicates every pass. `--reset-state` only `unlink`s the file once at startup, but the skip check is `... and not args.reset_state and ...`. In loop mode that condition stays false forever. Reset should be one-shot, not a permanent flag.
- **OPUS-16**: `updated_at` in the signature can cause an infinite re-review loop. Posting a comment may bump `updated_at`, `ticket_changed` sees a new signature next pass and reprocesses → another comment → another bump. Use content-only hash (description + labels), drop `updated_at`.

### Major

- **OPUS-17**: Pagination gap and unsafe tid key. `list_issues(limit=300)` is filtered *after* fetch, so >300 issues silently drops the tail. `tid = i.get("identifier", i.get("id"))` can be `None` if both are absent, then `processed[None]` becomes a key.

### Minor

- **OPUS-18**: `/tmp/<fixed-name>` is a predictable path — a symlink/pre-create by another local user is a (low-severity) tampering vector. Prefer a mode-0600 file under a user-owned dir.

---

## routes.yaml (the routing config)

### Critical

- **OPUS-19**: Silent trust-class fallback in security-review chain. `security-review: [claude-cli, gemini-cli, groq]` means if Claude + Gemini both fail (or are rate-limited), the chain silently falls through to Groq — a different trust class — and the downgrade is only recorded in `reply.raw["_router_skipped"]`, invisible at `reply.ok`. Security-tier chains should not auto-fall-through to a different trust class without surfacing it.
- **OPUS-20**: `RouteConfig.default()` diverges from `routes.yaml` for `security-review` chain. Default has `gemini-cli` first; YAML has `claude-cli` first. So a missing or malformed config silently reorders the most sensitive chain instead of erroring. Either remove the divergent default or make a missing config fatal for security tasks.

### Minor

- **OPUS-21**: Gemini argv injection / missing `--` guard. `GeminiCLIProvider` passes the prompt as an argv element `["gemini", "-p", full]`. No `shell=True`, so no shell injection — but no `--` guard, so a prompt or system string starting with `-` is parsed as a CLI flag. Claude is safe because it pipes via stdin; Gemini is the outlier.

(OPUS-22 to OPUS-27 are subset detail of the above; some were in CLI / kanban_loop output, see raw transcripts.)
