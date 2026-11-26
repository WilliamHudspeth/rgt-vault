"""Headless tests for the Textual operator console (RGT-261 coverage gate).

Drives ``VaultTUI`` with Textual's test pilot against a fake HTTP client, so no
daemon or terminal is needed. Skipped when the optional ``textual`` extra is
not installed.
"""

import asyncio
from typing import Any, List, Optional

import pytest

pytest.importorskip("textual")

from textual.widgets import Checkbox, DataTable, Input, Static  # noqa: E402

from rgt_vault import tui  # noqa: E402
from rgt_vault.tui_client import PendingRequest  # noqa: E402


def _req(rid="r1", *, secret="API_KEY", require_2fa=False) -> PendingRequest:
    return PendingRequest(
        request_id=rid,
        agent="agent-1",
        namespace="default",
        secret_name=secret,
        purpose="deploy",
        action="use",
        require_2fa=require_2fa,
        created_at=0.0,
    )


class FakeClient:
    def __init__(self, requests: Optional[List[PendingRequest]] = None):
        self.requests = requests or []
        self.calls: List[Any] = []
        self.fail = False
        self.approve_result = True
        self.closed = False

    def list_requests(self):
        if self.fail:
            raise ConnectionError("daemon down")
        return list(self.requests)

    def approve(self, request_id, *, totp_code=None, operator="operator"):
        self.calls.append(("approve", request_id, totp_code, operator))
        if self.fail:
            raise RuntimeError("boom")
        return self.approve_result

    def deny(self, request_id, *, reason="", operator="operator"):
        self.calls.append(("deny", request_id, operator))
        if self.fail:
            raise RuntimeError("boom")
        return True

    def set_secret(self, name, value, **kw):
        self.calls.append(("set", name, value, kw))
        if self.fail:
            raise RuntimeError("store exploded")
        return {}

    def close(self):
        self.closed = True


def _record_statuses(app):
    msgs: List[str] = []
    orig = app._set_status

    def _rec(msg):
        msgs.append(msg)
        orig(msg)

    app._set_status = _rec
    return msgs


def _status(app) -> str:
    return str(app.query_one("#status", Static).render())


async def _settle(app, pilot):
    await pilot.pause()
    # Exclusive workers (the poll/refresh) are cancelled when a newer one starts, which
    # makes wait_for_complete() raise WorkerCancelled on some platforms; just keep waiting.
    for _ in range(5):
        try:
            await app.workers.wait_for_complete()
            break
        except Exception:
            await pilot.pause()
    await pilot.pause()


def _run(coro):
    return asyncio.run(coro)


def test_note_word_limit():
    assert not tui._note_too_long("one two three")
    assert tui._note_too_long(" ".join(["w"] * (tui.NOTE_WORD_LIMIT + 1)))
    assert not tui._note_too_long(" ".join(["w"] * tui.NOTE_WORD_LIMIT))


def test_requests_table_populates_and_status_reports_count():
    client = FakeClient([_req("r1"), _req("r2", secret="DB_PASS", require_2fa=True)])
    app = tui.VaultTUI(client, poll_interval=60)

    async def go():
        async with app.run_test() as pilot:
            await _settle(app, pilot)
            table = app.query_one("#requests-table", DataTable)
            assert table.row_count == 2
            assert set(app._req_index) == {"r1", "r2"}
            assert "2 pending request(s)" in _status(app)

    _run(go())


def test_refresh_failure_is_shown_not_raised():
    client = FakeClient()
    client.fail = True
    app = tui.VaultTUI(client, poll_interval=60)

    async def go():
        async with app.run_test() as pilot:
            await _settle(app, pilot)
            assert "Could not reach daemon" in _status(app)

    _run(go())


def test_approve_and_deny_without_selection_report_it():
    app = tui.VaultTUI(FakeClient(), poll_interval=60)

    async def go():
        async with app.run_test() as pilot:
            await _settle(app, pilot)
            assert app._selected_request() is None
            await app._approve()
            assert "No request selected" in _status(app)
            app._deny()
            assert "No request selected" in _status(app)

    _run(go())


def test_approve_without_2fa_calls_client():
    client = FakeClient([_req("r1")])
    app = tui.VaultTUI(client, poll_interval=60)

    async def go():
        async with app.run_test() as pilot:
            await _settle(app, pilot)
            msgs = _record_statuses(app)
            assert app._selected_request() is not None
            await app._approve()
            await _settle(app, pilot)
            assert ("approve", "r1", None, "tui") in client.calls
            assert "Approved." in msgs

    _run(go())


def test_approve_rejected_and_failure_messages():
    client = FakeClient([_req("r1")])
    client.approve_result = False
    app = tui.VaultTUI(client, poll_interval=60)

    async def go():
        async with app.run_test() as pilot:
            await _settle(app, pilot)
            msgs = _record_statuses(app)
            await app._approve()
            await _settle(app, pilot)
            assert any("Rejected" in m for m in msgs)
            client.approve_result = True
            app._do_decision("r1", approve=True, totp_code=None)
            await _settle(app, pilot)
            assert "Approved." in msgs

    _run(go())


def test_deny_calls_client_and_failure_is_reported():
    client = FakeClient([_req("r1")])
    app = tui.VaultTUI(client, poll_interval=60)

    async def go():
        async with app.run_test() as pilot:
            await _settle(app, pilot)
            msgs = _record_statuses(app)
            app._deny()
            await _settle(app, pilot)
            assert ("deny", "r1", "tui") in client.calls
            assert "Denied." in msgs
            client.fail = True
            app._do_decision("r1", approve=False, totp_code=None)
            await _settle(app, pilot)
            assert any("Decision failed" in m for m in msgs)

    _run(go())


def test_approve_with_2fa_prompts_for_code_and_cancel_aborts():
    client = FakeClient([_req("r1", require_2fa=True)])
    app = tui.VaultTUI(client, poll_interval=60)

    async def go():
        async with app.run_test() as pilot:
            await _settle(app, pilot)
            task = asyncio.ensure_future(_worker_call(app))
            await pilot.pause()
            assert isinstance(app.screen, tui.TotpPrompt)
            app.screen._cancel()
            await task
            await _settle(app, pilot)
            assert "cancelled" in _status(app)
            assert not any(c[0] == "approve" for c in client.calls)

    async def _worker_call(app):
        # push_screen_wait must run inside a worker, as Textual's @on handlers do
        w = app.run_worker(app._approve(), exclusive=False)
        await w.wait()

    _run(go())


def test_approve_with_2fa_submits_code():
    client = FakeClient([_req("r1", require_2fa=True)])
    app = tui.VaultTUI(client, poll_interval=60)

    async def go():
        async with app.run_test() as pilot:
            await _settle(app, pilot)
            w = app.run_worker(app._approve(), exclusive=False)
            await pilot.pause()
            assert isinstance(app.screen, tui.TotpPrompt)
            app.screen.query_one("#totp-input", Input).value = " 123456 "
            app.screen._ok()
            await w.wait()
            await _settle(app, pilot)
            assert ("approve", "r1", "123456", "tui") in client.calls

    _run(go())


def test_totp_prompt_submit_via_enter_key():
    client = FakeClient([_req("r1", require_2fa=True)])
    app = tui.VaultTUI(client, poll_interval=60)

    async def go():
        async with app.run_test() as pilot:
            await _settle(app, pilot)
            w = app.run_worker(app._approve(), exclusive=False)
            await pilot.pause()
            app.screen.query_one("#totp-input", Input).value = "654321"
            app.screen._submit()
            await w.wait()
            await _settle(app, pilot)
            assert ("approve", "r1", "654321", "tui") in client.calls

    _run(go())


def test_store_validates_then_stores_and_clears_form():
    client = FakeClient()
    app = tui.VaultTUI(client, namespace="ns1", poll_interval=60)

    async def go():
        async with app.run_test() as pilot:
            await _settle(app, pilot)
            app._store()
            assert "required" in _status(app)

            app.query_one("#f-title", Input).value = "OPENAI_KEY"
            app.query_one("#f-secret", Input).value = "sk-123"
            app.query_one("#f-note", Input).value = " ".join(["w"] * (tui.NOTE_WORD_LIMIT + 1))
            app._store()
            assert "over" in _status(app)
            assert not client.calls

            app.query_one("#f-note", Input).value = "for tests"
            app.query_one("#f-2fa", Checkbox).value = True
            app._store()
            await _settle(app, pilot)
            kind, name, value, kw = client.calls[0]
            assert (kind, name, value) == ("set", "OPENAI_KEY", "sk-123")
            assert kw == {"namespace": "ns1", "agent": "operator", "note": "for tests", "require_2fa": True}
            assert "Stored 'OPENAI_KEY'" in _status(app)
            assert "2FA required" in _status(app)
            assert app.query_one("#f-title", Input).value == ""
            assert app.query_one("#f-secret", Input).value == ""
            assert app.query_one("#f-2fa", Checkbox).value is False

    _run(go())


def test_store_failure_is_reported():
    client = FakeClient()
    client.fail = True
    app = tui.VaultTUI(client, poll_interval=60)

    async def go():
        async with app.run_test() as pilot:
            await _settle(app, pilot)
            app.query_one("#f-title", Input).value = "T"
            app.query_one("#f-secret", Input).value = "S"
            app._store()
            await _settle(app, pilot)
            assert "Store failed" in _status(app)

    _run(go())


def test_run_tui_builds_client_runs_app_and_closes(monkeypatch):
    seen = {}

    class _Client(FakeClient):
        def __init__(self, base_url, token):
            super().__init__()
            seen["args"] = (base_url, token)
            seen["client"] = self

    class _App:
        def __init__(self, client, namespace="default"):
            seen["namespace"] = namespace

        def run(self):
            seen["ran"] = True

    monkeypatch.setattr(tui, "VaultHTTPClient", _Client)
    monkeypatch.setattr(tui, "VaultTUI", _App)
    assert tui.run_tui("http://127.0.0.1:1", "tok", namespace="n") == 0
    assert seen["args"] == ("http://127.0.0.1:1", "tok")
    assert seen["namespace"] == "n" and seen["ran"] and seen["client"].closed


def test_run_tui_requires_textual_extra(monkeypatch):
    monkeypatch.setattr(tui, "_TEXTUAL_AVAILABLE", False)
    with pytest.raises(RuntimeError, match="tui"):
        tui.run_tui("http://x", "t")
