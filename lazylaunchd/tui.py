"""lazygit-style Textual terminal UI for macOS LaunchAgents and LaunchDaemons."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from rich.console import Group
from rich.markup import escape
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Input,
    Label,
    Static,
    TextArea,
)

from lazylaunchd import __version__
from lazylaunchd.actions import (
    ActionResult,
    copy_to_clipboard,
    generate_agent_plist,
    load_service,
    restart_service,
    save_plist_content,
    toggle_enable_service,
    unload_service,
    validate_plist_content,
)
from lazylaunchd.core import (
    build_demo_services,
    discover_services,
    load_runtime_details,
)
from lazylaunchd.logs import format_log_line_rich, read_service_logs
from lazylaunchd.models import (
    ServiceInfo,
    ServiceScope,
    ServiceState,
    Severity,
)

INSPECTOR_TABS: tuple[tuple[str, str], ...] = (
    ("diagnostics", "1:Why / Diagnostics"),
    ("logs", "2:Logs"),
    ("plist", "3:Plist XML"),
    ("runtime", "4:Runtime"),
)

FILTER_MODES: tuple[tuple[str, str], ...] = (
    ("all", "All"),
    ("user", "User Agents"),
    ("global_agent", "Global Agents"),
    ("daemon", "Global Daemons"),
    ("failed", "Failed / Errors"),
    ("running", "Running"),
)


def _service_uid(svc: ServiceInfo, idx: int) -> str:
    path_part = str(svc.plist_path) if svc.plist_path else "runtime"
    return f"{svc.domain_target}|{svc.scope.value}|{svc.label}|{path_part}|{idx}"


def _state_cell(state: ServiceState) -> Text:
    styles = {
        ServiceState.RUNNING: ("● RUN ", "bold green"),
        ServiceState.LOADED: ("○ LOAD", "cyan"),
        ServiceState.FAILED: ("✖ FAIL", "bold red"),
        ServiceState.DISABLED: ("⊘ DIS ", "yellow"),
        ServiceState.UNLOADED: ("· UNLD", "dim white"),
        ServiceState.INVALID: ("! INV ", "bold magenta"),
    }
    label, style = styles[state]
    return Text(label, style=style)


def _exit_cell(svc: ServiceInfo) -> Text:
    code = svc.last_exit_status
    summary = svc.short_exit_summary
    if code is None:
        return Text(summary, style="dim")
    if code == 0:
        return Text(summary, style="green")
    if code < 0:
        return Text(summary, style="bold yellow")
    return Text(summary, style="bold red")


def _primary_fix_or_path(svc: ServiceInfo) -> tuple[str, str] | None:
    """Return `(description, text_to_copy)` for the `[y]` copy shortcut."""
    for diag in svc.diagnostics:
        if diag.severity in (Severity.ERROR, Severity.WARNING) and diag.fix_hint:
            return ("fix hint", diag.fix_hint)
    if svc.plist_path is not None:
        return ("plist path", str(svc.plist_path))
    return ("service target", svc.service_target)


class PlistEditorModal(ModalScreen[tuple[bool, bool]]):
    """Modal XML editor for inspecting, validating, and saving plist files.

    Returns `(saved, should_reload)`.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("ctrl+s", "save_only", "Save"),
        Binding("ctrl+r", "save_and_reload", "Save & Reload"),
        Binding("ctrl+t", "validate_only", "Validate"),
    ]

    CSS = """
    PlistEditorModal {
        align: center middle;
    }
    #editor-dialog {
        width: 90%;
        height: 88%;
        background: #141820;
        border: tall #4c78a8;
        padding: 1 2;
    }
    #editor-title {
        text-style: bold;
        color: #79c0ff;
        height: 1;
        margin-bottom: 1;
    }
    #editor-status {
        height: 2;
        margin-bottom: 1;
        color: #c9d1d9;
    }
    #plist-textarea {
        height: 1fr;
        border: solid #30363d;
        margin-bottom: 1;
    }
    #editor-buttons {
        height: 3;
        align: right middle;
    }
    #editor-buttons Button {
        margin-left: 1;
    }
    """

    def __init__(self, service: ServiceInfo, *, demo: bool = False) -> None:
        super().__init__()
        self.service = service
        self.demo = demo
        self._initial_text = service.raw_plist_text or ""

    def compose(self) -> ComposeResult:
        path_display = str(self.service.plist_path or "(no file on disk)")
        lang = "xml" if "xml" in TextArea().available_languages else None
        with Vertical(id="editor-dialog"):
            yield Static(
                f"Edit Plist — {self.service.label} ({path_display})",
                id="editor-title",
            )
            status_msg = (
                "Root-owned plist: direct save may require sudo; you can still validate XML."
                if self.service.requires_sudo and not self.demo
                else "Ctrl+T Validate  |  Ctrl+S Save  |  Ctrl+R Save & Reload  |  Esc Cancel"
            )
            yield Static(status_msg, id="editor-status")
            yield TextArea.code_editor(
                self._initial_text,
                language=lang,
                theme="monokai",
                id="plist-textarea",
            )
            with Horizontal(id="editor-buttons"):
                yield Button("Validate (Ctrl+T)", id="btn-validate", variant="default")
                yield Button("Save (Ctrl+S)", id="btn-save", variant="primary")
                yield Button("Save & Reload (Ctrl+R)", id="btn-save-reload", variant="success")
                yield Button("Cancel (Esc)", id="btn-cancel", variant="error")

    def on_mount(self) -> None:
        self.query_one("#plist-textarea", TextArea).focus()

    def _set_status(self, message: str, *, error: bool = False) -> None:
        status = self.query_one("#editor-status", Static)
        color = "bold red" if error else "bold green"
        status.update(Text(message, style=color))

    def _validate(self) -> bool:
        text = self.query_one("#plist-textarea", TextArea).text
        ok, msg, _ = validate_plist_content(text, require_label=True)
        self._set_status(msg, error=not ok)
        return ok

    def _perform_save(self, *, reload_after: bool) -> None:
        text = self.query_one("#plist-textarea", TextArea).text
        ok, msg, parsed = validate_plist_content(text, require_label=True)
        if not ok:
            self._set_status(msg, error=True)
            return

        if self.demo:
            self.service.raw_plist_text = text
            self.service.plist_error = None
            if parsed is not None:
                self.service.plist_data = parsed
            self.dismiss((True, reload_after))
            return

        if self.service.plist_path is None:
            self._set_status("Cannot save: service has no plist path on disk.", error=True)
            return

        res = save_plist_content(self.service.plist_path, text, require_label=True)
        if not res.ok:
            self._set_status(res.message, error=True)
            return
        self.dismiss((True, reload_after))

    def action_validate_only(self) -> None:
        self._validate()

    def action_save_only(self) -> None:
        self._perform_save(reload_after=False)

    def action_save_and_reload(self) -> None:
        self._perform_save(reload_after=True)

    def action_cancel(self) -> None:
        self.dismiss((False, False))

    @on(Button.Pressed, "#btn-validate")
    def _on_validate(self) -> None:
        self._validate()

    @on(Button.Pressed, "#btn-save")
    def _on_save(self) -> None:
        self._perform_save(reload_after=False)

    @on(Button.Pressed, "#btn-save-reload")
    def _on_save_reload(self) -> None:
        self._perform_save(reload_after=True)

    @on(Button.Pressed, "#btn-cancel")
    def _on_cancel(self) -> None:
        self.dismiss((False, False))


class NewAgentModal(ModalScreen[tuple[Path | None, bool, str | None]]):
    """Wizard modal to create a new User LaunchAgent plist.

    Returns `(created_path, load_after_save, demo_xml_if_demo)`.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    CSS = """
    NewAgentModal {
        align: center middle;
    }
    #new-agent-dialog {
        width: 78;
        height: auto;
        max-height: 92%;
        background: #141820;
        border: tall #3fb950;
        padding: 1 2;
    }
    #new-agent-title {
        text-style: bold;
        color: #3fb950;
        margin-bottom: 1;
    }
    .field-label {
        margin-top: 0;
        color: #8b949e;
    }
    #new-agent-dialog Input {
        height: 1;
        border: none;
        background: #0d1117;
        color: #e6edf3;
        padding: 0 1;
        margin-bottom: 1;
    }
    #new-agent-error {
        color: #f85149;
        height: auto;
    }
    #new-agent-checks {
        height: auto;
    }
    #new-agent-buttons {
        margin-top: 1;
        height: 3;
        align: right middle;
    }
    #new-agent-buttons Button {
        margin-left: 1;
    }
    """

    def __init__(self, target_dir: Path | None = None, *, demo: bool = False) -> None:
        super().__init__()
        self.target_dir = target_dir or (Path.home() / "Library" / "LaunchAgents")
        self.demo = demo

    def compose(self) -> ComposeResult:
        default_logs = str(Path.home() / "Library" / "Logs" / "lazylaunchd-agent.log")
        with VerticalScroll(id="new-agent-dialog"):
            yield Static("Create New User LaunchAgent", id="new-agent-title")
            yield Label("Service Label (e.g. com.dev.my-worker):", classes="field-label")
            yield Input(placeholder="com.dev.my-worker", id="new-label")
            yield Label("Command (executable and arguments):", classes="field-label")
            yield Input(placeholder="/usr/bin/python3 /path/to/worker.py", id="new-command")
            yield Label("Working Directory (optional):", classes="field-label")
            yield Input(placeholder=str(Path.home()), id="new-workdir")
            yield Label("Stdout / Stderr Log Path (optional):", classes="field-label")
            yield Input(value=default_logs, id="new-logpath")
            yield Label("Start Interval in seconds (optional, e.g. 300):", classes="field-label")
            yield Input(placeholder="", id="new-interval")
            with Horizontal(id="new-agent-checks"):
                yield Checkbox("RunAtLoad", value=True, id="chk-runatload")
                yield Checkbox("KeepAlive", value=False, id="chk-keepalive")
                yield Checkbox("Load immediately", value=True, id="chk-loadnow")
            yield Static("", id="new-agent-error")
            with Horizontal(id="new-agent-buttons"):
                yield Button("Create Plist", id="btn-create", variant="success")
                yield Button("Cancel (Esc)", id="btn-new-cancel", variant="error")

    def on_mount(self) -> None:
        self.query_one("#new-label", Input).focus()

    def action_cancel(self) -> None:
        self.dismiss((None, False, None))

    @on(Button.Pressed, "#btn-new-cancel")
    def _on_cancel(self) -> None:
        self.dismiss((None, False, None))

    @on(Button.Pressed, "#btn-create")
    def _on_create(self) -> None:
        err_widget = self.query_one("#new-agent-error", Static)
        label = self.query_one("#new-label", Input).value.strip()
        cmd_raw = self.query_one("#new-command", Input).value.strip()
        workdir = self.query_one("#new-workdir", Input).value.strip() or None
        logpath = self.query_one("#new-logpath", Input).value.strip() or None
        interval_raw = self.query_one("#new-interval", Input).value.strip()
        run_at_load = self.query_one("#chk-runatload", Checkbox).value
        keep_alive = self.query_one("#chk-keepalive", Checkbox).value
        load_now = self.query_one("#chk-loadnow", Checkbox).value

        if not label:
            err_widget.update("Service Label is required.")
            return
        if not cmd_raw:
            err_widget.update("Command is required.")
            return

        import shlex

        try:
            cmd_args = shlex.split(cmd_raw)
        except ValueError as exc:
            err_widget.update(f"Invalid command quoting: {exc}")
            return

        start_interval: int | None = None
        if interval_raw:
            if not interval_raw.isdigit() or int(interval_raw) <= 0:
                err_widget.update("Start Interval must be a positive integer (seconds).")
                return
            start_interval = int(interval_raw)

        xml_text = generate_agent_plist(
            label=label,
            program_args=cmd_args,
            run_at_load=run_at_load,
            keep_alive=keep_alive,
            working_directory=workdir,
            stdout_path=logpath,
            stderr_path=logpath,
            start_interval=start_interval,
            env_path="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        )

        plist_path = self.target_dir / f"{label}.plist"
        if self.demo:
            self.dismiss((plist_path, load_now, xml_text))
            return

        if plist_path.exists():
            err_widget.update(f"Plist already exists: {plist_path}")
            return

        if logpath:
            try:
                Path(logpath).parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                err_widget.update(f"Could not create log directory: {exc}")
                return

        res = save_plist_content(plist_path, xml_text, require_label=True)
        if not res.ok:
            err_widget.update(res.message)
            return

        self.dismiss((plist_path, load_now, None))


class HelpModal(ModalScreen[None]):
    """Keyboard shortcuts and launchd exit-code reference modal."""

    BINDINGS = [
        Binding("escape", "close", "Close"),
        Binding("?", "close", "Close"),
        Binding("q", "close", "Close"),
    ]

    CSS = """
    HelpModal {
        align: center middle;
    }
    #help-dialog {
        width: 84;
        height: auto;
        max-height: 88%;
        background: #141820;
        border: tall #58a6ff;
        padding: 1 2;
    }
    #help-title {
        text-style: bold;
        color: #79c0ff;
        margin-bottom: 1;
    }
    #help-close {
        margin-top: 1;
        align: right middle;
        height: 3;
    }
    """

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="help-dialog"):
            yield Static(f"lazylaunchd v{__version__} — Shortcuts & Reference", id="help-title")
            table = Table(show_header=True, header_style="bold cyan", expand=True, box=None)
            table.add_column("Key", style="bold yellow", width=14)
            table.add_column("Action", style="white")
            shortcuts = [
                ("j / k / ↑ / ↓", "Move selection up / down"),
                ("/ or f", "Focus live search filter (Esc returns to list)"),
                ("1 2 3 4 / Tab", "Switch inspector: Why/Diagnostics, Logs, Plist XML, Runtime"),
                ("d", "Cycle scope/status filter (All / User / Global / Daemons / Failed / Running)"),
                ("a", "Toggle Apple /System/Library services"),
                ("s", "Start / Kickstart selected service (`launchctl kickstart -k`)"),
                ("l / u", "Load (bootstrap) / Unload (bootout) selected service"),
                ("e", "Toggle Enable / Disable (`launchctl enable` / `disable`)"),
                ("E", "Open built-in XML Plist Editor (with plutil/plistlib validation)"),
                ("Ctrl+E", "Open plist file in external $EDITOR"),
                ("n", "Create new User LaunchAgent wizard"),
                ("L", "Fetch macOS Unified Logs (`log show --last 15m`) for selected service"),
                ("y", "Copy recommended fix command or plist path to clipboard"),
                ("r", "Refresh services and live launchctl state"),
                ("? / q", "Show this help / Quit lazylaunchd"),
            ]
            for key, desc in shortcuts:
                table.add_row(key, desc)

            exit_notes = Text.from_markup(
                "\n[bold cyan]Common launchd Exit Codes[/bold cyan]\n"
                "  [green]0[/green]    Clean exit\n"
                "  [red]2[/red]    ENOENT — Missing file or argument\n"
                "  [red]78[/red]   EX_CONFIG — Missing WorkingDirectory, missing log parent dir, or bad permissions\n"
                "  [red]126[/red]  Command found but not executable (`chmod +x` needed)\n"
                "  [red]127[/red]  Command not found (remember launchd does not load shell `$PATH`!)\n"
                "  [yellow]-9[/yellow]   Killed by SIGKILL (reaped or force-killed)\n"
                "  [yellow]-15[/yellow]  Terminated by SIGTERM (graceful stop)\n"
            )
            yield Static(Group(table, exit_notes))
            with Horizontal(id="help-close"):
                yield Button("Close (Esc)", id="btn-help-close", variant="primary")

    def action_close(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#btn-help-close")
    def _on_close(self) -> None:
        self.dismiss(None)


class LazyLaunchdApp(App[None]):
    """lazygit-inspired Textual TUI for managing and debugging macOS launchd services."""

    TITLE = "lazylaunchd"

    BINDINGS = [
        Binding("q", "quit", "Quit", show=False),
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("/", "focus_search", "Search", show=False),
        Binding("f", "focus_search", "Filter", show=False),
        Binding("1", "tab_diagnostics", "Why", show=False),
        Binding("2", "tab_logs", "Logs", show=False),
        Binding("3", "tab_plist", "Plist", show=False),
        Binding("4", "tab_runtime", "Runtime", show=False),
        Binding("tab", "next_tab", "Next Tab", show=False),
        Binding("d", "cycle_filter", "Scope Filter", show=False),
        Binding("a", "toggle_apple", "Toggle Apple", show=False),
        Binding("s", "start_service", "Start/Kickstart", show=False),
        Binding("l", "load_service", "Load", show=False),
        Binding("u", "unload_service", "Unload", show=False),
        Binding("e", "toggle_enable", "Enable/Disable", show=False),
        Binding("E", "edit_plist", "Edit Plist", show=False),
        Binding("ctrl+e", "external_edit", "$EDITOR", show=False),
        Binding("n", "new_agent", "New Agent", show=False),
        Binding("L", "load_unified_logs", "Unified Logs", show=False),
        Binding("y", "copy_fix", "Copy Fix/Path", show=False),
        Binding("r", "refresh_services", "Refresh", show=False),
        Binding("?", "show_help", "Help", show=False),
    ]

    CSS = """
    Screen {
        background: #0d1117;
        color: #c9d1d9;
    }
    #top-bar {
        height: 2;
        background: #161b22;
        border-bottom: solid #30363d;
        padding: 0 1;
        content-align: left middle;
    }
    #main-split {
        height: 1fr;
    }
    #left-pane {
        width: 48%;
        min-width: 48;
        border-right: solid #30363d;
        background: #0d1117;
    }
    #filter-bar {
        height: 3;
        padding: 0 1;
        background: #161b22;
        border-bottom: solid #30363d;
        align: left middle;
    }
    #search-input {
        width: 1fr;
        border: none;
        background: #0d1117;
        color: #e6edf3;
    }
    #scope-pill {
        width: auto;
        padding: 0 1;
        margin-left: 1;
        background: #21262d;
        color: #79c0ff;
        text-style: bold;
        height: 1;
        content-align: center middle;
    }
    #service-table {
        height: 1fr;
        background: #0d1117;
    }
    #right-pane {
        width: 52%;
        background: #0d1117;
    }
    #service-banner {
        height: auto;
        min-height: 3;
        max-height: 5;
        padding: 0 1;
        background: #161b22;
        border-bottom: solid #30363d;
    }
    #inspector-tabs {
        height: 2;
        padding: 0 1;
        background: #161b22;
        border-bottom: solid #30363d;
        align: left middle;
    }
    .tab-btn {
        width: auto;
        height: 1;
        min-width: 10;
        padding: 0 1;
        margin-right: 1;
        background: #21262d;
        color: #8b949e;
        border: none;
    }
    .tab-btn.active-tab {
        background: #1f6feb;
        color: #ffffff;
        text-style: bold;
    }
    #inspector-scroll {
        height: 1fr;
        padding: 1;
    }
    #inspector-content {
        width: 100%;
    }
    #status-line {
        height: 1;
        padding: 0 1;
        background: #161b22;
        border-top: solid #30363d;
        color: #8b949e;
    }
    #key-bar {
        height: 1;
        padding: 0 1;
        background: #0d1117;
        color: #8b949e;
    }
    """

    def __init__(
        self,
        *,
        demo: bool = False,
        include_apple: bool = False,
        extra_dirs: list[tuple[Path, ServiceScope]] | None = None,
        initial_query: str = "",
        initial_services: list[ServiceInfo] | None = None,
    ) -> None:
        super().__init__()
        self.demo = demo
        self.include_apple = include_apple
        self.extra_dirs = extra_dirs
        self.search_query = initial_query
        self.filter_idx = 0
        self.active_tab = "diagnostics"
        self.show_unified_logs = False

        self.all_services: list[ServiceInfo] = initial_services or []
        self.filtered_services: list[ServiceInfo] = []
        self._row_service_map: dict[str, ServiceInfo] = {}
        self._selected_label: str | None = None
        self._last_feedback: tuple[str, str] = ("Ready.", "#8b949e")

    def compose(self) -> ComposeResult:
        yield Static("", id="top-bar")
        with Horizontal(id="main-split"):
            with Vertical(id="left-pane"):
                with Horizontal(id="filter-bar"):
                    yield Input(
                        value=self.search_query,
                        placeholder="Filter services... (/ to search, Esc for list)",
                        id="search-input",
                    )
                    yield Static("[d] All", id="scope-pill")
                yield DataTable(id="service-table", cursor_type="row", zebra_stripes=True)
            with Vertical(id="right-pane"):
                yield Static("", id="service-banner")
                with Horizontal(id="inspector-tabs"):
                    for tab_id, label in INSPECTOR_TABS:
                        classes = "tab-btn active-tab" if tab_id == self.active_tab else "tab-btn"
                        yield Button(label, id=f"tab-{tab_id}", classes=classes)
                with VerticalScroll(id="inspector-scroll"):
                    yield Static("", id="inspector-content")
        yield Static("", id="status-line")
        yield Static(
            "[b]s[/b] Start  [b]l[/b] Load  [b]u[/b] Unload  [b]e[/b] Enable/Disable  "
            "[b]E[/b] Edit Plist  [b]n[/b] New  [b]L[/b] Unified Logs  "
            "[b]d[/b] Scope  [b]a[/b] Apple  [b]y[/b] Copy Fix  [b]?[/b] Help  [b]q[/b] Quit",
            id="key-bar",
        )

    def on_mount(self) -> None:
        table = self.query_one("#service-table", DataTable)
        table.add_column("State", width=7)
        table.add_column("Scope", width=7)
        table.add_column("PID", width=6)
        table.add_column("Exit", width=13)
        table.add_column("Label")

        if not self.all_services:
            self._reload_services()
        else:
            self._apply_filters_and_populate()
        table.focus()

    def _reload_services(self) -> None:
        if self.demo:
            if not self.all_services:
                self.all_services = build_demo_services()
        else:
            self.all_services = discover_services(
                include_apple=self.include_apple,
                extra_dirs=self.extra_dirs,
            )
        self._apply_filters_and_populate()

    def _matches_filter(self, svc: ServiceInfo) -> bool:
        mode = FILTER_MODES[self.filter_idx][0]
        if mode == "user" and svc.scope != ServiceScope.USER_AGENT:
            return False
        if mode == "global_agent" and svc.scope != ServiceScope.GLOBAL_AGENT:
            return False
        if mode == "daemon" and svc.scope not in (
            ServiceScope.GLOBAL_DAEMON,
            ServiceScope.SYSTEM_DAEMON,
        ):
            return False
        if mode == "failed" and svc.state not in (ServiceState.FAILED, ServiceState.INVALID):
            return False
        if mode == "running" and svc.state != ServiceState.RUNNING:
            return False

        if self.search_query:
            q = self.search_query.lower()
            haystack = " ".join(
                [
                    svc.label,
                    str(svc.plist_path or ""),
                    " ".join(svc.program_command),
                    svc.scope.label,
                    svc.short_exit_summary,
                    svc.exit_summary,
                ]
            ).lower()
            if q not in haystack:
                return False
        return True

    def _apply_filters_and_populate(self) -> None:
        self.filtered_services = [s for s in self.all_services if self._matches_filter(s)]

        table = self.query_one("#service-table", DataTable)
        table.clear()
        self._row_service_map.clear()

        target_row_index = 0
        for idx, svc in enumerate(self.filtered_services):
            key = _service_uid(svc, idx)
            self._row_service_map[key] = svc
            pid_text = Text(str(svc.pid), style="bold white") if svc.pid else Text("-", style="dim")
            label_style = "bold red" if svc.state in (ServiceState.FAILED, ServiceState.INVALID) else "white"
            table.add_row(
                _state_cell(svc.state),
                Text(svc.scope.short_label, style="cyan"),
                pid_text,
                _exit_cell(svc),
                Text(svc.label, style=label_style),
                key=key,
            )
            if self._selected_label and svc.label == self._selected_label:
                target_row_index = idx

        if self.filtered_services:
            table.move_cursor(row=target_row_index)
            self._selected_label = self.filtered_services[target_row_index].label

        self._update_top_bar()
        self._update_scope_pill()
        self._update_inspector()
        self._update_status_line()

    def _current_service(self) -> ServiceInfo | None:
        table = self.query_one("#service-table", DataTable)
        if not self.filtered_services or table.cursor_row is None:
            return None
        row_idx = table.cursor_row
        if 0 <= row_idx < len(self.filtered_services):
            return self.filtered_services[row_idx]
        return None

    def _update_top_bar(self) -> None:
        counts = {state: 0 for state in ServiceState}
        for svc in self.all_services:
            counts[svc.state] += 1
        demo_tag = " [black on yellow] DEMO [/]" if self.demo else ""
        apple_tag = "[green]Apple:Shown[/]" if self.include_apple else "[dim]Apple:Hidden[/]"
        summary = (
            f"[bold cyan]lazylaunchd[/]{demo_tag}  "
            f"[white]Total: {len(self.all_services)}[/]  "
            f"[bold green]● {counts[ServiceState.RUNNING]} Run[/]  "
            f"[bold red]✖ {counts[ServiceState.FAILED] + counts[ServiceState.INVALID]} Fail[/]  "
            f"[cyan]○ {counts[ServiceState.LOADED]} Load[/]  "
            f"[yellow]⊘ {counts[ServiceState.DISABLED]} Dis[/]  "
            f"[dim]· {counts[ServiceState.UNLOADED]} Unld[/]  "
            f"│ {apple_tag}"
        )
        self.query_one("#top-bar", Static).update(summary)

    def _update_scope_pill(self) -> None:
        _, label = FILTER_MODES[self.filter_idx]
        self.query_one("#scope-pill", Static).update(f"[d] {label}")

    def _update_status_line(self) -> None:
        msg, color = self._last_feedback
        showing = f"Showing {len(self.filtered_services)}/{len(self.all_services)}"
        self.query_one("#status-line", Static).update(
            f"[{color}]{escape(msg)}[/]  [dim]│  {showing}[/]"
        )

    def _set_feedback(self, message: str, *, style: str = "#7ee787") -> None:
        self._last_feedback = (message, style)
        self._update_status_line()

    def _update_tab_buttons(self) -> None:
        for tab_id, _ in INSPECTOR_TABS:
            btn = self.query_one(f"#tab-{tab_id}", Button)
            if tab_id == self.active_tab:
                btn.add_class("active-tab")
            else:
                btn.remove_class("active-tab")

    def _update_inspector(self) -> None:
        self._update_tab_buttons()
        svc = self._current_service()
        banner = self.query_one("#service-banner", Static)
        content = self.query_one("#inspector-content", Static)

        if svc is None:
            banner.update("[dim]No service matches the current filter.[/dim]")
            content.update(
                "[dim]Press [b]Esc[/b] or clear the filter, or press [b]n[/b] to create a new LaunchAgent.[/dim]"
            )
            return

        pid_str = str(svc.pid) if svc.pid else "-"
        plist_str = str(svc.plist_path) if svc.plist_path else "(runtime-only, no plist on disk)"
        sudo_badge = " [yellow](sudo)[/yellow]" if svc.requires_sudo else ""
        banner.update(
            f"[bold white]{escape(svc.label)}[/]  {svc.status_badge}  "
            f"[cyan]{escape(svc.scope.label)}[/]{sudo_badge}\n"
            f"[dim]Domain:[/] {escape(svc.domain_target)}  "
            f"[dim]PID:[/] {pid_str}  "
            f"[dim]Exit:[/] {escape(svc.exit_summary)}  "
            f"[dim]Schedule:[/] {escape(svc.schedule_summary)}\n"
            f"[dim]Plist:[/] {escape(plist_str)}"
        )

        if self.active_tab == "diagnostics":
            content.update(self._render_diagnostics(svc))
        elif self.active_tab == "logs":
            content.update(self._render_logs(svc))
        elif self.active_tab == "plist":
            content.update(self._render_plist(svc))
        elif self.active_tab == "runtime":
            content.update(self._render_runtime(svc))

    def _render_diagnostics(self, svc: ServiceInfo) -> Group:
        blocks: list[Any] = []
        for diag in svc.diagnostics:
            style_map = {
                Severity.ERROR: ("bold red", "red", "✖ ERROR"),
                Severity.WARNING: ("bold yellow", "yellow", "▲ WARN"),
                Severity.INFO: ("bold cyan", "cyan", "ℹ INFO"),
                Severity.OK: ("bold green", "green", "✔ OK"),
            }
            title_style, border_style, badge = style_map[diag.severity]
            lines = [Text(diag.detail, style="white")]
            if diag.fix_hint:
                lines.append(Text(""))
                lines.append(Text.assemble(("Fix: ", "bold green"), (diag.fix_hint, "green")))
            blocks.append(
                Panel(
                    Group(*lines),
                    title=f"[{title_style}]{badge}: {escape(diag.title)}[/{title_style}]",
                    subtitle=f"[dim]{diag.code}[/dim]",
                    border_style=border_style,
                    padding=(0, 1),
                )
            )

        meta = Table(show_header=False, box=None, expand=True, padding=(0, 1))
        meta.add_column("Key", style="bold cyan", width=18)
        meta.add_column("Value", style="white")
        cmd_str = " ".join(svc.program_command) if svc.program_command else "(none)"
        meta.add_row("Command", cmd_str)
        meta.add_row("WorkingDir", svc.working_directory or "(default)")
        meta.add_row("Stdout", svc.stdout_path or "(not configured)")
        meta.add_row("Stderr", svc.stderr_path or "(not configured)")
        meta.add_row("Schedule", svc.schedule_summary)
        meta.add_row("Disabled", "Yes" if svc.is_disabled else "No")
        blocks.append(Panel(meta, title="[bold]Configuration Summary[/bold]", border_style="#30363d"))
        return Group(*blocks)

    def _render_logs(self, svc: ServiceInfo) -> Group:
        bundle = read_service_logs(
            svc,
            max_lines=120,
            include_unified=self.show_unified_logs,
        )
        sections: list[Any] = []

        def _make_log_panel(title: str, path_str: str | None, lines: list[str], err: str | None, border: str) -> Panel:
            if not path_str and not lines and not err:
                body: Any = Text("Not configured in plist.", style="dim")
            elif err:
                body = Text(err, style="yellow")
            elif not lines:
                body = Text("(log file is empty)", style="dim")
            else:
                body = Group(*(format_log_line_rich(ln) for ln in lines))
            subtitle = escape(path_str) if path_str else ""
            return Panel(body, title=title, subtitle=subtitle, border_style=border, padding=(0, 1))

        sections.append(
            _make_log_panel(
                "[bold red]StandardErrorPath[/bold red]",
                bundle.stderr_path,
                bundle.stderr_lines,
                bundle.stderr_error,
                "red" if bundle.stderr_lines else "#30363d",
            )
        )
        sections.append(
            _make_log_panel(
                "[bold cyan]StandardOutPath[/bold cyan]",
                bundle.stdout_path,
                bundle.stdout_lines,
                bundle.stdout_error,
                "#30363d",
            )
        )

        if self.show_unified_logs:
            if bundle.unified_error:
                u_body: Any = Text(bundle.unified_error, style="yellow")
            elif not bundle.unified_lines:
                u_body = Text("No matching Unified Log entries in the last 15 minutes.", style="dim")
            else:
                u_body = Group(*(format_log_line_rich(ln) for ln in bundle.unified_lines))
            sections.append(
                Panel(
                    u_body,
                    title="[bold magenta]macOS Unified Logs (`log show --last 15m`)[/bold magenta]",
                    border_style="magenta",
                    padding=(0, 1),
                )
            )
        else:
            sections.append(
                Text("Tip: Press [L] to query macOS Unified Logs (`log show --last 15m`).", style="dim")
            )
        return Group(*sections)

    def _render_plist(self, svc: ServiceInfo) -> Any:
        if not svc.raw_plist_text:
            return Panel(
                Text("This service is active in launchd memory without a scanned plist file on disk.", style="dim"),
                title="Plist XML",
                border_style="#30363d",
            )
        if svc.plist_error:
            err_panel = Panel(
                Text(f"Parse error: {svc.plist_error}\nPress [E] to repair in the built-in XML editor.", style="bold red"),
                title="[bold red]Invalid Plist[/bold red]",
                border_style="red",
            )
            syntax = Syntax(svc.raw_plist_text, "xml", theme="monokai", line_numbers=True, word_wrap=True)
            return Group(err_panel, syntax)
        return Syntax(svc.raw_plist_text, "xml", theme="monokai", line_numbers=True, word_wrap=True)

    def _render_runtime(self, svc: ServiceInfo) -> Any:
        details = load_runtime_details(svc)
        if not details:
            return Panel(
                Text(
                    "No active runtime record from `launchctl print` (service is likely unloaded).",
                    style="dim",
                ),
                title="Runtime Details",
                border_style="#30363d",
            )
        tbl = Table(show_header=True, header_style="bold cyan", expand=True, box=None)
        tbl.add_column("Property", style="bold cyan", width=24)
        tbl.add_column("Value", style="white")
        for key, val in details.items():
            if isinstance(val, dict):
                formatted = "\n".join(f"{k} => {v}" for k, v in val.items()) or "{}"
            elif isinstance(val, list):
                formatted = "\n".join(str(x) for x in val) or "[]"
            else:
                formatted = str(val)
            tbl.add_row(str(key), formatted)
        return Panel(tbl, title=f"[bold]launchctl print {escape(svc.service_target)}[/bold]", border_style="#30363d")

    @on(Input.Changed, "#search-input")
    def _on_search_changed(self, event: Input.Changed) -> None:
        self.search_query = event.value
        self._apply_filters_and_populate()

    @on(Input.Submitted, "#search-input")
    def _on_search_submitted(self) -> None:
        self.query_one("#service-table", DataTable).focus()

    def on_key(self, event: Any) -> None:
        search = self.query_one("#search-input", Input)
        if event.key == "escape" and search.has_focus:
            if search.value:
                search.value = ""
                self.search_query = ""
                self._apply_filters_and_populate()
            self.query_one("#service-table", DataTable).focus()
            event.stop()

    @on(DataTable.RowHighlighted, "#service-table")
    def _on_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key and event.row_key.value in self._row_service_map:
            self._selected_label = self._row_service_map[event.row_key.value].label
        self._update_inspector()

    @on(Button.Pressed, ".tab-btn")
    def _on_tab_button(self, event: Button.Pressed) -> None:
        btn_id = event.button.id or ""
        if btn_id.startswith("tab-"):
            self.active_tab = btn_id[4:]
            self._update_inspector()

    def action_cursor_down(self) -> None:
        self.query_one("#service-table", DataTable).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#service-table", DataTable).action_cursor_up()

    def action_focus_search(self) -> None:
        self.query_one("#search-input", Input).focus()

    def action_tab_diagnostics(self) -> None:
        self.active_tab = "diagnostics"
        self._update_inspector()

    def action_tab_logs(self) -> None:
        self.active_tab = "logs"
        self._update_inspector()

    def action_tab_plist(self) -> None:
        self.active_tab = "plist"
        self._update_inspector()

    def action_tab_runtime(self) -> None:
        self.active_tab = "runtime"
        self._update_inspector()

    def action_next_tab(self) -> None:
        ids = [t[0] for t in INSPECTOR_TABS]
        idx = (ids.index(self.active_tab) + 1) % len(ids)
        self.active_tab = ids[idx]
        self._update_inspector()

    def action_cycle_filter(self) -> None:
        self.filter_idx = (self.filter_idx + 1) % len(FILTER_MODES)
        self._apply_filters_and_populate()
        self._set_feedback(f"Filter: {FILTER_MODES[self.filter_idx][1]}", style="#79c0ff")

    def action_toggle_apple(self) -> None:
        self.include_apple = not self.include_apple
        if self.demo:
            self._set_feedback("Apple /System/Library toggle applies to live scan mode.", style="yellow")
            return
        self._reload_services()
        state_lbl = "shown" if self.include_apple else "hidden"
        self._set_feedback(f"Apple system services {state_lbl}.", style="#79c0ff")

    def action_refresh_services(self) -> None:
        self._reload_services()
        self._set_feedback("Refreshed services and launchctl state.", style="#7ee787")

    def _apply_action_result(self, res: ActionResult) -> None:
        if res.ok:
            self._set_feedback(res.message, style="#7ee787")
            if res.needs_refresh:
                self._reload_services()
            else:
                self._update_inspector()
        else:
            if res.requires_sudo and res.command:
                copy_to_clipboard(res.command)
                self._set_feedback(f"{res.message} (copied command)", style="yellow")
            else:
                self._set_feedback(res.message, style="bold red")

    def action_start_service(self) -> None:
        svc = self._current_service()
        if not svc:
            return
        self._apply_action_result(restart_service(svc, demo=self.demo))

    def action_load_service(self) -> None:
        svc = self._current_service()
        if not svc:
            return
        self._apply_action_result(load_service(svc, demo=self.demo))

    def action_unload_service(self) -> None:
        svc = self._current_service()
        if not svc:
            return
        self._apply_action_result(unload_service(svc, demo=self.demo))

    def action_toggle_enable(self) -> None:
        svc = self._current_service()
        if not svc:
            return
        self._apply_action_result(toggle_enable_service(svc, demo=self.demo))

    def action_load_unified_logs(self) -> None:
        self.show_unified_logs = not self.show_unified_logs
        self.active_tab = "logs"
        self._update_inspector()
        state = "enabled" if self.show_unified_logs else "hidden"
        self._set_feedback(f"Unified Logs (`log show`) {state}.", style="#d2a8ff")

    def action_copy_fix(self) -> None:
        svc = self._current_service()
        if not svc:
            return
        choice = _primary_fix_or_path(svc)
        if not choice:
            return
        kind, payload = choice
        ok, msg = copy_to_clipboard(payload)
        if ok:
            self._set_feedback(f"Copied {kind} to clipboard: {payload}", style="#7ee787")
        else:
            self._set_feedback(f"Clipboard unavailable ({msg}): {payload}", style="yellow")

    def action_edit_plist(self) -> None:
        svc = self._current_service()
        if not svc:
            return
        if svc.plist_path is None and not self.demo:
            self._set_feedback("Selected service has no plist file on disk.", style="yellow")
            return

        def _after_edit(result: tuple[bool, bool] | None) -> None:
            if not result:
                return
            saved, reload_after = result
            if not saved:
                return
            if reload_after:
                if svc.loaded:
                    unload_service(svc, demo=self.demo)
                res = load_service(svc, demo=self.demo)
                self._apply_action_result(res)
            else:
                self._reload_services()
                self._set_feedback(f"Saved plist for {svc.label}.", style="#7ee787")

        self.push_screen(PlistEditorModal(svc, demo=self.demo), _after_edit)

    def action_external_edit(self) -> None:
        svc = self._current_service()
        if not svc or svc.plist_path is None:
            self._set_feedback("No plist file on disk to open in $EDITOR.", style="yellow")
            return
        if self.demo:
            self._set_feedback("External $EDITOR disabled in demo mode; press [E] for built-in editor.", style="yellow")
            return

        editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "nano"
        target_path = svc.plist_path
        cmd = ["sudo", editor, str(target_path)] if svc.requires_sudo else [editor, str(target_path)]

        with self.suspend():
            try:
                subprocess.run(cmd, check=False)
            except OSError as exc:
                self._set_feedback(f"Failed to launch editor '{editor}': {exc}", style="bold red")
                return
        self._reload_services()
        self._set_feedback(f"Returned from {editor}; refreshed {svc.label}.", style="#7ee787")

    def action_new_agent(self) -> None:
        target_dir: Path | None = None
        if self.extra_dirs:
            target_dir = self.extra_dirs[0][0]
        elif self.demo:
            target_dir = Path(tempfile.gettempdir()) / "lazylaunchd-demo"

        def _after_create(result: tuple[Path | None, bool, str | None] | None) -> None:
            if not result:
                return
            created_path, load_now, demo_xml = result
            if created_path is None:
                return
            if self.demo and demo_xml is not None:
                import plistlib

                pdata = plistlib.loads(demo_xml.encode("utf-8"))
                new_svc = ServiceInfo(
                    label=pdata["Label"],
                    scope=ServiceScope.USER_AGENT,
                    domain_target=f"gui/{os.getuid()}",
                    plist_path=created_path,
                    loaded=load_now,
                    last_exit_status=0 if load_now else None,
                    plist_data=pdata,
                    raw_plist_text=demo_xml,
                )
                self.all_services.insert(0, new_svc)
                self._selected_label = new_svc.label
                self._apply_filters_and_populate()
                self._set_feedback(f"[Demo] Created {new_svc.label}", style="#7ee787")
                return

            self._selected_label = created_path.stem
            self._reload_services()
            if load_now:
                match = next((s for s in self.all_services if s.plist_path == created_path), None)
                if match is not None:
                    self._apply_action_result(load_service(match, demo=False))
                    return
            self._set_feedback(f"Created {created_path}", style="#7ee787")

        self.push_screen(NewAgentModal(target_dir=target_dir, demo=self.demo), _after_create)

    def action_show_help(self) -> None:
        self.push_screen(HelpModal())
