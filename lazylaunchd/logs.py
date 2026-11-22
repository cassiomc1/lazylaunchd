"""Log reading (stdout, stderr, and macOS Unified Logging) for launchd services."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from rich.text import Text

from lazylaunchd.models import ServiceInfo

_ERROR_LINE_RE = re.compile(
    r"\b(error|err|fatal|critical|panic|exception|traceback|failed|denied)\b",
    re.IGNORECASE,
)
_WARN_LINE_RE = re.compile(r"\b(warn|warning|deprecated|retry|timeout)\b", re.IGNORECASE)
_INFO_LINE_RE = re.compile(r"\b(info|ready|started|listening|healthy)\b", re.IGNORECASE)


@dataclass(slots=True)
class ServiceLogBundle:
    """Collected stdout, stderr, and optional macOS Unified Log output."""

    stdout_path: str | None = None
    stdout_lines: list[str] = field(default_factory=list)
    stdout_error: str | None = None
    stderr_path: str | None = None
    stderr_lines: list[str] = field(default_factory=list)
    stderr_error: str | None = None
    unified_lines: list[str] = field(default_factory=list)
    unified_error: str | None = None


def tail_file(path: Path, max_lines: int = 200, chunk_size: int = 8192) -> tuple[list[str], str | None]:
    """Read the last `max_lines` lines from `path` in bounded memory."""
    if max_lines <= 0:
        return [], None
    if not path.exists():
        return [], f"File does not exist: {path}"
    if path.is_dir():
        return [], f"Path is a directory, not a log file: {path}"

    try:
        file_size = path.stat().st_size
    except OSError as exc:
        return [], str(exc)

    if file_size == 0:
        return [], None

    try:
        with path.open("rb") as fh:
            pos = file_size
            blocks: list[bytes] = []
            newline_count = 0
            while pos > 0 and newline_count <= max_lines:
                read_len = min(chunk_size, pos)
                pos -= read_len
                fh.seek(pos, os.SEEK_SET)
                chunk = fh.read(read_len)
                blocks.append(chunk)
                newline_count += chunk.count(b"\n")
    except OSError as exc:
        return [], str(exc)

    raw = b"".join(reversed(blocks))
    lines = raw.decode("utf-8", errors="replace").splitlines()
    return lines[-max_lines:], None


def fetch_unified_logs(
    service: ServiceInfo,
    *,
    last: str = "15m",
    max_lines: int = 120,
) -> tuple[list[str], str | None]:
    """Query macOS Unified Logging (`log show`) for messages matching `service`."""
    if service.demo_unified_logs is not None:
        return service.demo_unified_logs.splitlines()[-max_lines:], None
    if service.demo_stdout is not None or service.demo_stderr is not None:
        return [
            f"2026-11-22 09:50:00.100 Df launchd[1]: ({service.service_target}) demo unified log stream active"
        ], None

    if sys.platform != "darwin":
        return [], "Unified logging (`log show`) is only available on macOS."

    safe_label = service.label.replace('"', "")
    cmd_parts = [f'subsystem CONTAINS "{safe_label}"', f'eventMessage CONTAINS "{safe_label}"']
    cmd = service.program_command
    if cmd:
        proc_name = Path(cmd[0]).name.replace('"', "")
        if proc_name and proc_name not in ("python", "python3", "bash", "sh", "zsh", "env", "node"):
            cmd_parts.append(f'process == "{proc_name}"')

    predicate = " OR ".join(cmd_parts)
    try:
        proc = subprocess.run(
            ["log", "show", "--predicate", predicate, "--last", last, "--style", "compact"],
            capture_output=True,
            text=True,
            timeout=6.0,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return [], "Timed out querying macOS Unified Log (`log show`)."
    except (OSError, subprocess.SubprocessError) as exc:
        return [], str(exc)

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or f"log show exited {proc.returncode}").strip()
        return [], err

    lines = [ln for ln in (proc.stdout or "").splitlines() if ln.strip()]
    if lines and lines[0].startswith("Filtering the log data"):
        lines = lines[1:]
    if lines and lines[0].startswith("Timestamp"):
        lines = lines[1:]
    return lines[-max_lines:], None


def read_service_logs(
    service: ServiceInfo,
    *,
    max_lines: int = 200,
    include_unified: bool = False,
) -> ServiceLogBundle:
    """Collect stdout, stderr, and optionally Unified Logs for `service`."""
    bundle = ServiceLogBundle(
        stdout_path=service.stdout_path,
        stderr_path=service.stderr_path,
    )

    if service.demo_stdout is not None or service.demo_stderr is not None:
        bundle.stdout_lines = (service.demo_stdout or "").splitlines()[-max_lines:]
        bundle.stderr_lines = (service.demo_stderr or "").splitlines()[-max_lines:]
        if include_unified:
            u_lines, u_err = fetch_unified_logs(service, max_lines=max_lines)
            bundle.unified_lines = u_lines
            bundle.unified_error = u_err
        return bundle

    if service.stdout_path:
        lines, err = tail_file(Path(service.stdout_path), max_lines=max_lines)
        bundle.stdout_lines = lines
        bundle.stdout_error = err

    if service.stderr_path:
        if service.stderr_path == service.stdout_path:
            bundle.stderr_lines = list(bundle.stdout_lines)
            bundle.stderr_error = bundle.stdout_error
        else:
            lines, err = tail_file(Path(service.stderr_path), max_lines=max_lines)
            bundle.stderr_lines = lines
            bundle.stderr_error = err

    if include_unified:
        u_lines, u_err = fetch_unified_logs(service, max_lines=max_lines)
        bundle.unified_lines = u_lines
        bundle.unified_error = u_err

    return bundle


def format_log_line_rich(line: str) -> Text:
    """Format a log line with severity-aware Rich styling."""
    if _ERROR_LINE_RE.search(line):
        return Text(line, style="bold red")
    if _WARN_LINE_RE.search(line):
        return Text(line, style="yellow")
    if _INFO_LINE_RE.search(line):
        return Text(line, style="cyan")
    return Text(line, style="white")
