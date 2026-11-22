"""Data models and exit-status decoding for lazylaunchd."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any


class ServiceScope(str, Enum):
    """Filesystem/domain origin of a launchd service."""

    USER_AGENT = "user_agent"
    GLOBAL_AGENT = "global_agent"
    GLOBAL_DAEMON = "global_daemon"
    SYSTEM_AGENT = "system_agent"
    SYSTEM_DAEMON = "system_daemon"
    RUNTIME_ONLY = "runtime_only"

    @property
    def label(self) -> str:
        labels = {
            ServiceScope.USER_AGENT: "User Agent",
            ServiceScope.GLOBAL_AGENT: "Global Agent",
            ServiceScope.GLOBAL_DAEMON: "Global Daemon",
            ServiceScope.SYSTEM_AGENT: "System Agent",
            ServiceScope.SYSTEM_DAEMON: "System Daemon",
            ServiceScope.RUNTIME_ONLY: "Runtime Only",
        }
        return labels[self]

    @property
    def short_label(self) -> str:
        labels = {
            ServiceScope.USER_AGENT: "User",
            ServiceScope.GLOBAL_AGENT: "GlobalA",
            ServiceScope.GLOBAL_DAEMON: "Daemon",
            ServiceScope.SYSTEM_AGENT: "SysA",
            ServiceScope.SYSTEM_DAEMON: "SysD",
            ServiceScope.RUNTIME_ONLY: "Runtime",
        }
        return labels[self]


class ServiceState(str, Enum):
    """Effective runtime/health state of a launchd service."""

    RUNNING = "running"
    LOADED = "loaded"
    FAILED = "failed"
    DISABLED = "disabled"
    UNLOADED = "unloaded"
    INVALID = "invalid"


class Severity(str, Enum):
    """Severity level for diagnostic findings."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    OK = "ok"


@dataclass(slots=True)
class DiagnosticItem:
    """Single diagnostic finding explaining service health or failure."""

    severity: Severity
    code: str
    title: str
    detail: str
    fix_hint: str | None = None


_COMMON_EXIT_CODES: dict[int, str] = {
    1: "General error (exit 1)",
    2: "Misuse of shell builtins or missing file (ENOENT)",
    13: "Permission denied (EACCES)",
    64: "Command line usage error (EX_USAGE)",
    65: "Data format error (EX_DATAERR)",
    66: "Cannot open input (EX_NOINPUT)",
    69: "Service unavailable (EX_UNAVAILABLE)",
    70: "Internal software error (EX_SOFTWARE)",
    71: "System error (EX_OSERR)",
    72: "Critical OS file missing (EX_OSFILE)",
    73: "Can't create output file (EX_CANTCREAT)",
    74: "Input/output error (EX_IOERR)",
    75: "Temporary failure (EX_TEMPFAIL)",
    77: "Permission denied (EX_NOPERM)",
    78: "Configuration or spawn error (EX_CONFIG: bad path, missing log dir, or non-executable)",
    126: "Command invoked cannot execute (permission or format error)",
    127: "Command not found (check executable path and launchd PATH)",
    130: "Terminated by Ctrl-C / SIGINT",
    137: "Killed by SIGKILL (128 + 9)",
    143: "Terminated by SIGTERM (128 + 15)",
}


@lru_cache(maxsize=128)
def _lookup_launchctl_error(code: int) -> str | None:
    """Query `launchctl error <code>` on macOS for lesser-known error codes."""
    if sys.platform != "darwin":
        return None
    try:
        proc = subprocess.run(
            ["launchctl", "error", str(code)],
            capture_output=True,
            text=True,
            timeout=1.5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    out = (proc.stdout or "").strip()
    if proc.returncode == 0 and ":" in out:
        _, _, msg = out.partition(":")
        msg = msg.strip()
        if msg and "unknown error" not in msg.lower():
            return msg
    return None


def explain_exit_status(code: int | None, *, query_launchctl: bool = False) -> str:
    """Return a human-readable explanation for a launchd exit status or signal."""
    if code is None:
        return "-"
    if code == 0:
        return "0 (OK)"
    if code < 0:
        sig_num = abs(code)
        try:
            sig_name = signal.Signals(sig_num).name
            return f"{code} ({sig_name})"
        except ValueError:
            return f"{code} (Signal {sig_num})"

    if code in _COMMON_EXIT_CODES:
        return f"{code} ({_COMMON_EXIT_CODES[code]})"

    if query_launchctl:
        desc = _lookup_launchctl_error(code)
        if desc:
            return f"{code} ({desc})"

    if 128 < code < 192:
        sig_num = code - 128
        try:
            sig_name = signal.Signals(sig_num).name
            return f"{code} (Exited via {sig_name})"
        except ValueError:
            pass

    return f"{code} (Non-zero exit)"


@dataclass
class ServiceInfo:
    """Normalized representation of a macOS LaunchAgent or LaunchDaemon."""

    label: str
    scope: ServiceScope
    domain_target: str
    plist_path: Path | None = None
    pid: int | None = None
    last_exit_status: int | None = None
    loaded: bool = False
    disabled_in_db: bool | None = None
    plist_data: dict[str, Any] = field(default_factory=dict)
    plist_error: str | None = None
    raw_plist_text: str = ""
    runtime_details: dict[str, Any] = field(default_factory=dict)
    diagnostics: list[DiagnosticItem] = field(default_factory=list)
    demo_stdout: str | None = None
    demo_stderr: str | None = None
    demo_unified_logs: str | None = None

    @property
    def is_disabled(self) -> bool:
        if self.disabled_in_db is True:
            return True
        if self.disabled_in_db is False:
            return False
        return bool(self.plist_data.get("Disabled", False))

    @property
    def state(self) -> ServiceState:
        if self.plist_error:
            return ServiceState.INVALID
        if self.loaded and self.pid is not None and self.pid > 0:
            return ServiceState.RUNNING
        if self.is_disabled:
            return ServiceState.DISABLED
        has_error = any(d.severity == Severity.ERROR for d in self.diagnostics)
        if (
            self.loaded
            and self.last_exit_status is not None
            and self.last_exit_status != 0
        ) or has_error:
            return ServiceState.FAILED
        if self.loaded:
            return ServiceState.LOADED
        return ServiceState.UNLOADED

    @property
    def program_command(self) -> list[str]:
        prog_args = self.plist_data.get("ProgramArguments")
        if isinstance(prog_args, list) and prog_args:
            return [str(item) for item in prog_args]
        prog = self.plist_data.get("Program")
        if isinstance(prog, str) and prog.strip():
            return [prog.strip()]
        runtime_args = self.runtime_details.get("arguments")
        if isinstance(runtime_args, list) and runtime_args:
            return [str(item) for item in runtime_args]
        runtime_prog = self.runtime_details.get("program")
        if isinstance(runtime_prog, str) and runtime_prog.strip():
            return [runtime_prog.strip()]
        return []

    @property
    def stdout_path(self) -> str | None:
        val = self.plist_data.get("StandardOutPath") or self.runtime_details.get(
            "stdout path"
        )
        return str(val) if val else None

    @property
    def stderr_path(self) -> str | None:
        val = self.plist_data.get("StandardErrorPath") or self.runtime_details.get(
            "stderr path"
        )
        return str(val) if val else None

    @property
    def working_directory(self) -> str | None:
        val = self.plist_data.get("WorkingDirectory") or self.runtime_details.get(
            "working directory"
        )
        return str(val) if val else None

    @property
    def run_at_load(self) -> bool:
        return bool(self.plist_data.get("RunAtLoad", False))

    @property
    def keep_alive(self) -> Any:
        return self.plist_data.get("KeepAlive", False)

    @property
    def schedule_summary(self) -> str:
        triggers: list[str] = []
        if self.run_at_load:
            triggers.append("RunAtLoad")
        ka = self.keep_alive
        if ka is True:
            triggers.append("KeepAlive")
        elif isinstance(ka, dict) and ka:
            triggers.append("KeepAlive(cond)")
        if "StartInterval" in self.plist_data:
            triggers.append(f"Every {self.plist_data['StartInterval']}s")
        if "StartCalendarInterval" in self.plist_data:
            triggers.append("Calendar")
        if self.plist_data.get("WatchPaths"):
            triggers.append("WatchPaths")
        if self.plist_data.get("QueueDirectories"):
            triggers.append("QueueDirs")
        if self.plist_data.get("Sockets"):
            triggers.append("Sockets")
        if self.plist_data.get("MachServices"):
            triggers.append("MachServices")
        return ", ".join(triggers) if triggers else "On demand / manual"

    @property
    def is_apple(self) -> bool:
        return (
            self.label.startswith("com.apple.")
            or self.scope in (ServiceScope.SYSTEM_AGENT, ServiceScope.SYSTEM_DAEMON)
        )

    @property
    def requires_sudo(self) -> bool:
        if os.geteuid() == 0:
            return False
        if self.scope in (
            ServiceScope.GLOBAL_AGENT,
            ServiceScope.GLOBAL_DAEMON,
            ServiceScope.SYSTEM_AGENT,
            ServiceScope.SYSTEM_DAEMON,
        ):
            return True
        return self.domain_target == "system"

    @property
    def status_badge(self) -> str:
        badges = {
            ServiceState.RUNNING: "● RUNNING",
            ServiceState.LOADED: "○ LOADED",
            ServiceState.FAILED: "✖ FAILED",
            ServiceState.DISABLED: "⊘ DISABLED",
            ServiceState.UNLOADED: "· UNLOADED",
            ServiceState.INVALID: "! INVALID",
        }
        return badges[self.state]

    @property
    def exit_summary(self) -> str:
        return explain_exit_status(self.last_exit_status)

    @property
    def service_target(self) -> str:
        return f"{self.domain_target}/{self.label}"

    @property
    def error_count(self) -> int:
        return sum(1 for d in self.diagnostics if d.severity == Severity.ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for d in self.diagnostics if d.severity == Severity.WARNING)

    def to_dict(self) -> dict[str, Any]:
        """Serialize service metadata and diagnostics for JSON CLI output."""
        return {
            "label": self.label,
            "scope": self.scope.value,
            "domain_target": self.domain_target,
            "state": self.state.value,
            "loaded": self.loaded,
            "pid": self.pid,
            "last_exit_status": self.last_exit_status,
            "exit_summary": self.exit_summary,
            "disabled": self.is_disabled,
            "plist_path": str(self.plist_path) if self.plist_path else None,
            "program_command": self.program_command,
            "working_directory": self.working_directory,
            "stdout_path": self.stdout_path,
            "stderr_path": self.stderr_path,
            "schedule_summary": self.schedule_summary,
            "requires_sudo": self.requires_sudo,
            "plist_error": self.plist_error,
            "diagnostics": [
                {
                    "severity": d.severity.value,
                    "code": d.code,
                    "title": d.title,
                    "detail": d.detail,
                    "fix_hint": d.fix_hint,
                }
                for d in self.diagnostics
            ],
        }
