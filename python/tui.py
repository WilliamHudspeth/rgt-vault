"""Textual TUI for rgt-vault operators.

Two jobs, both over the daemon's HTTP API (so the human runs this in their
own terminal; the LLM/agent never has the I/O handle):

  1. Store secrets — title, masked value, a short note (<=25 words), and a
     "require 2FA" toggle.
  2. Approve or deny live agent requests — with a TOTP prompt when the
     secret was flagged for a second factor.

The operator only ever sees titles and request metadata; secret values go
straight into the vault and never come back out through this UI.

Run via:  rgt-vault tui --url http://127.0.0.1:8765 --token <operator-token>
"""

from __future__ import annotations

from typing import Optional

try:
    from textual import on, work
    from textual.app import App, ComposeResult
    from textual.containers import Horizontal, Vertical
    from textual.screen import ModalScreen
    from textual.widgets import (
        Button,
        Checkbox,
        DataTable,
        Footer,
        Header,
        Input,
        Label,
        Static,
        TabbedContent,
        TabPane,
    )

    _TEXTUAL_AVAILABLE = True
except ModuleNotFoundError:  # pragma: no cover - exercised only without the extra
    _TEXTUAL_AVAILABLE = False

from rgt_vault.tui_client import PendingRequest, VaultHTTPClient

NOTE_WORD_LIMIT = 25


def _note_too_long(note: str) -> bool:
    return len(note.split()) > NOTE_WORD_LIMIT


if _TEXTUAL_AVAILABLE:

    class TotpPrompt(ModalScreen[Optional[str]]):
        """Modal that collects a TOTP code (or cancels) for a 2FA approval."""

        def __init__(self, secret_name: str):
            super().__init__()
            self._secret_name = secret_name

        def compose(self) -> ComposeResult:
            with Vertical(id="totp-box"):
                yield Label(f"2FA required to approve '{self._secret_name}'")
                yield Input(placeholder="6-digit code", id="totp-input", max_length=8)
                with Horizontal():
                    yield Button("Approve", variant="success", id="totp-ok")
                    yield Button("Cancel", variant="error", id="totp-cancel")

        @on(Button.Pressed, "#totp-ok")
        def _ok(self) -> None:
            self.dismiss(self.query_one("#totp-input", Input).value.strip())

        @on(Button.Pressed, "#totp-cancel")
        def _cancel(self) -> None:
            self.dismiss(None)

        @on(Input.Submitted, "#totp-input")
        def _submit(self) -> None:
            self.dismiss(self.query_one("#totp-input", Input).value.strip())

    class VaultTUI(App):
        """Operator console: store secrets and approve/deny agent requests."""

        CSS = """
        #totp-box { width: 60; height: auto; padding: 1 2; border: thick $accent; background: $surface; }
        #status { height: 1; color: $text-muted; }
        DataTable { height: 1fr; }
        """
        BINDINGS = [
            ("r", "refresh", "Refresh requests"),
            ("q", "quit", "Quit"),
        ]

        def __init__(self, client: VaultHTTPClient, *, namespace: str = "default", poll_interval: float = 2.0):
            super().__init__()
            self._client = client
            self._namespace = namespace
            self._poll_interval = poll_interval
            self._req_index: dict[str, PendingRequest] = {}

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            with TabbedContent():
                with TabPane("Requests", id="tab-requests"):
                    yield DataTable(id="requests-table")
                    with Horizontal():
                        yield Button("Approve", variant="success", id="approve")
                        yield Button("Deny", variant="error", id="deny")
                with TabPane("Store secret", id="tab-store"):
                    with Vertical():
                        yield Label("Title")
                        yield Input(placeholder="e.g. OPENAI_KEY", id="f-title")
                        yield Label("Secret (hidden)")
                        yield Input(placeholder="the secret value", password=True, id="f-secret")
                        yield Label("Note (<= 25 words)")
                        yield Input(placeholder="what this is for", id="f-note")
                        yield Checkbox("Require 2FA to use", id="f-2fa")
                        yield Button("Store", variant="primary", id="store")
            yield Static("", id="status")
            yield Footer()

        def on_mount(self) -> None:
            table = self.query_one("#requests-table", DataTable)
            table.add_columns("Agent", "Secret", "Namespace", "Purpose", "2FA")
            table.cursor_type = "row"
            self.set_interval(self._poll_interval, self.action_refresh)
            self.action_refresh()

        def _set_status(self, msg: str) -> None:
            self.query_one("#status", Static).update(msg)

        # ---- requests tab --------------------------------------------- #

        @work(exclusive=True, thread=True)
        def action_refresh(self) -> None:
            try:
                requests = self._client.list_requests()
            except Exception as e:  # network/daemon hiccup — show, don't crash
                self.call_from_thread(self._set_status, f"Could not reach daemon: {e}")
                return
            self.call_from_thread(self._render_requests, requests)

        def _render_requests(self, requests: list[PendingRequest]) -> None:
            table = self.query_one("#requests-table", DataTable)
            table.clear()
            self._req_index = {}
            for r in requests:
                table.add_row(r.agent, r.secret_name, r.namespace, r.purpose,
                              "yes" if r.require_2fa else "no", key=r.request_id)
                self._req_index[r.request_id] = r
            self._set_status(f"{len(requests)} pending request(s)")

        def _selected_request(self) -> Optional[PendingRequest]:
            table = self.query_one("#requests-table", DataTable)
            if not table.row_count:
                return None
            row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
            return self._req_index.get(row_key.value)

        @on(Button.Pressed, "#approve")
        async def _approve(self) -> None:
            req = self._selected_request()
            if req is None:
                self._set_status("No request selected.")
                return
            if req.require_2fa:
                code = await self.push_screen_wait(TotpPrompt(req.secret_name))
                if not code:
                    self._set_status("Approval cancelled (no 2FA code).")
                    return
            else:
                code = None
            self._do_decision(req.request_id, approve=True, totp_code=code)

        @on(Button.Pressed, "#deny")
        def _deny(self) -> None:
            req = self._selected_request()
            if req is None:
                self._set_status("No request selected.")
                return
            self._do_decision(req.request_id, approve=False, totp_code=None)

        @work(exclusive=False, thread=True)
        def _do_decision(self, request_id: str, *, approve: bool, totp_code: Optional[str]) -> None:
            try:
                if approve:
                    ok = self._client.approve(request_id, totp_code=totp_code, operator="tui")
                    msg = "Approved." if ok else "Rejected (bad/missing 2FA or request gone)."
                else:
                    self._client.deny(request_id, operator="tui")
                    msg = "Denied."
            except Exception as e:
                msg = f"Decision failed: {e}"
            self.call_from_thread(self._set_status, msg)
            self.call_from_thread(self.action_refresh)

        # ---- store tab ------------------------------------------------ #

        @on(Button.Pressed, "#store")
        def _store(self) -> None:
            title = self.query_one("#f-title", Input).value.strip()
            secret = self.query_one("#f-secret", Input).value
            note = self.query_one("#f-note", Input).value.strip()
            require_2fa = self.query_one("#f-2fa", Checkbox).value
            if not title or not secret:
                self._set_status("Title and secret are required.")
                return
            if _note_too_long(note):
                self._set_status(f"Note is over {NOTE_WORD_LIMIT} words — please shorten it.")
                return
            self._store_worker(title, secret, note, require_2fa)

        @work(exclusive=False, thread=True)
        def _store_worker(self, title: str, secret: str, note: str, require_2fa: bool) -> None:
            try:
                self._client.set_secret(
                    title, secret, namespace=self._namespace, agent="operator",
                    note=note, require_2fa=require_2fa,
                )
                msg = f"Stored '{title}'." + (" (2FA required to use)" if require_2fa else "")
            except Exception as e:
                msg = f"Store failed: {e}"
            self.call_from_thread(self._clear_store_form)
            self.call_from_thread(self._set_status, msg)

        def _clear_store_form(self) -> None:
            for wid in ("#f-title", "#f-secret", "#f-note"):
                self.query_one(wid, Input).value = ""
            self.query_one("#f-2fa", Checkbox).value = False


def run_tui(base_url: str, token: str, *, namespace: str = "default") -> int:
    """Entry point used by ``rgt-vault tui``."""
    if not _TEXTUAL_AVAILABLE:
        raise RuntimeError(
            "The TUI requires the 'tui' extra. Install it with:\n"
            "    pip install 'rgt-vault[tui]'"
        )
    client = VaultHTTPClient(base_url, token)
    try:
        VaultTUI(client, namespace=namespace).run()
    finally:
        client.close()
    return 0
