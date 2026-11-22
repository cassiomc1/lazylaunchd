"""Core service discovery, plist loading, and launchctl output parsing."""

from __future__ import annotations

import os
import plistlib
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from lazylaunchd.diagnostics import diagnose_service
from lazylaunchd.models import (
    DiagnosticItem,
    ServiceInfo,
    ServiceScope,
    Severity,
    explain_exit_status,
)

__all__ = [
    "build_demo_services",
    "default_plist_dirs",
    "discover_services",
    "explain_exit_status",
    "load_runtime_details",
    "parse_launchctl_disabled",
    "parse_launchctl_domain_services",
    "parse_launchctl_list",
    "parse_launchctl_print",
]

_DISABLED_LINE_RE = re.compile(r'^\s*"(?P<label>[^"]+)"\s*=>\s*(?P<state>disabled|enabled)\s*$')
_DOMAIN_SERVICE_RE = re.compile(
    r"^\s*(?P<pid>\d+)\s+(?P<status>-|\d+|\([^)]+\))\s+(?P<label>\S+)\s*$"
)


def default_plist_dirs(*, include_apple: bool = False) -> list[tuple[Path, ServiceScope]]:
    """Return standard macOS LaunchAgent and LaunchDaemon directories."""
    dirs: list[tuple[Path, ServiceScope]] = [
        (Path.home() / "Library" / "LaunchAgents", ServiceScope.USER_AGENT),
        (Path("/Library/LaunchAgents"), ServiceScope.GLOBAL_AGENT),
        (Path("/Library/LaunchDaemons"), ServiceScope.GLOBAL_DAEMON),
    ]
    if include_apple:
        dirs.extend(
            [
                (Path("/System/Library/LaunchAgents"), ServiceScope.SYSTEM_AGENT),
                (Path("/System/Library/LaunchDaemons"), ServiceScope.SYSTEM_DAEMON),
            ]
        )
    return dirs


def parse_launchctl_list(output: str) -> dict[str, tuple[int | None, int | None]]:
    """Parse `launchctl list` TSV output into `{label: (pid, last_exit_status)}`."""
    results: dict[str, tuple[int | None, int | None]] = {}
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        pid_raw, status_raw, label = parts[0].strip(), parts[1].strip(), parts[2].strip()
        if pid_raw.upper() == "PID" and label.lower() == "label":
            continue
        pid = int(pid_raw) if pid_raw.isdigit() else None
        status: int | None
        if status_raw == "-":
            status = None
        else:
            try:
                status = int(status_raw)
            except ValueError:
                status = None
        if label:
            results[label] = (pid, status)
    return results


def parse_launchctl_disabled(output: str) -> dict[str, bool]:
    """Parse `launchctl print-disabled <domain>` output into `{label: is_disabled}`."""
    disabled: dict[str, bool] = {}
    for line in output.splitlines():
        match = _DISABLED_LINE_RE.match(line)
        if match:
            disabled[match.group("label")] = match.group("state") == "disabled"
    return disabled


def parse_launchctl_domain_services(output: str) -> dict[str, tuple[int | None, int | None]]:
    """Parse the `services = { ... }` table inside `launchctl print <domain>` output."""
    services: dict[str, tuple[int | None, int | None]] = {}
    in_services_block = False
    for line in output.splitlines():
        stripped = line.strip()
        if not in_services_block:
            if stripped == "services = {":
                in_services_block = True
            continue
        if stripped == "}":
            break
        match = _DOMAIN_SERVICE_RE.match(line)
        if not match:
            continue
        pid_val = int(match.group("pid"))
        pid = pid_val if pid_val > 0 else None
        status_raw = match.group("status")
        status: int | None = None
        if status_raw.lstrip("-").isdigit():
            status = int(status_raw)
        label = match.group("label")
        services[label] = (pid, status)
    return services


def parse_launchctl_print(output: str) -> dict[str, Any]:
    """Extract key runtime attributes from `launchctl print <domain>/<label>`."""
    details: dict[str, Any] = {}
    lines = output.splitlines()
    idx = 0

    def _parse_block(start_idx: int, key: str) -> tuple[Any, int]:
        items: list[str] = []
        kv_map: dict[str, str] = {}
        i = start_idx
        depth = 1
        while i < len(lines) and depth > 0:
            raw = lines[i].strip()
            i += 1
            if raw == "}":
                depth -= 1
                break
            if raw.endswith("{"):
                depth += 1
                continue
            if not raw:
                continue
            if "=>" in raw:
                k, _, v = raw.partition("=>")
                kv_map[k.strip()] = v.strip()
            else:
                items.append(raw)
        if kv_map and not items:
            return kv_map, i
        return (kv_map if key in ("environment", "inherited environment", "default environment") else items), i

    # Skip leading empty lines and outer header line (`domain/label = {`) if present.
    while idx < len(lines) and not lines[idx].strip():
        idx += 1
    if idx < len(lines) and lines[idx].strip().endswith("= {"):
        idx += 1

    brace_depth = 0
    while idx < len(lines):
        raw = lines[idx]
        stripped = raw.strip()
        idx += 1

        if not stripped:
            continue
        if stripped == "}":
            if brace_depth > 0:
                brace_depth -= 1
            continue

        if brace_depth > 0:
            if stripped.endswith("{"):
                brace_depth += 1
            continue

        if stripped.endswith("= {"):
            key = stripped[:-3].strip()
            block_val, idx = _parse_block(idx, key)
            if key in (
                "arguments",
                "environment",
                "inherited environment",
                "default environment",
                "endpoints",
                "disabled services",
            ):
                details[key] = block_val
            continue

        if stripped.endswith("{"):
            brace_depth += 1
            continue

        if "=" in stripped:
            key, _, val = stripped.partition("=")
            key = key.strip()
            val = val.strip()
            if key in ("pid", "active count", "runs", "forks", "execs", "minimum runtime", "exit timeout"):
                if val.isdigit():
                    details[key] = int(val)
                else:
                    details[key] = val
            elif key == "last exit code":
                if val.lstrip("-").isdigit():
                    details[key] = int(val)
                else:
                    details[key] = val
            else:
                details[key] = val

    return details


def _run_launchctl(args: list[str], *, timeout: float = 4.0) -> str:
    """Run a read-only `launchctl` subcommand, returning stdout or empty string."""
    if sys.platform != "darwin":
        return ""
    try:
        proc = subprocess.run(
            ["launchctl", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


def load_runtime_details(service: ServiceInfo) -> dict[str, Any]:
    """Fetch and cache `launchctl print <domain>/<label>` details for a service."""
    if service.demo_stdout is not None or service.demo_stderr is not None or service.demo_unified_logs is not None:
        return service.runtime_details
    if not service.loaded and not service.runtime_details:
        out = _run_launchctl(["print", service.service_target], timeout=3.0)
        if not out:
            return {}
        parsed = parse_launchctl_print(out)
        service.runtime_details = parsed
        return parsed
    out = _run_launchctl(["print", service.service_target], timeout=3.0)
    if out:
        parsed = parse_launchctl_print(out)
        service.runtime_details = parsed
    return service.runtime_details


def _read_plist_file(path: Path) -> tuple[dict[str, Any], str | None, str]:
    """Read and parse an XML or binary plist file."""
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        return {}, str(exc), f"# Unreadable file: {exc}\n"

    try:
        loaded = plistlib.loads(raw_bytes)
    except Exception as exc:  # noqa: BLE001 - malformed user plists raise varied errors
        raw_text = raw_bytes.decode("utf-8", errors="replace")
        return {}, str(exc), raw_text

    if not isinstance(loaded, dict):
        raw_text = raw_bytes.decode("utf-8", errors="replace")
        return {}, f"Root plist object must be a dictionary, got {type(loaded).__name__}", raw_text

    if raw_bytes.startswith(b"bplist"):
        try:
            raw_text = plistlib.dumps(loaded, fmt=plistlib.FMT_XML).decode("utf-8")
        except Exception:  # noqa: BLE001
            raw_text = "<binary plist>"
    else:
        raw_text = raw_bytes.decode("utf-8", errors="replace")

    return loaded, None, raw_text


def _domain_for_scope(scope: ServiceScope, uid: int) -> str:
    if scope in (ServiceScope.GLOBAL_DAEMON, ServiceScope.SYSTEM_DAEMON):
        return "system"
    return f"gui/{uid}"


def discover_services(
    *,
    uid: int | None = None,
    include_apple: bool = False,
    include_runtime_only: bool = True,
    extra_dirs: list[tuple[Path, ServiceScope]] | None = None,
    plist_dirs: list[tuple[Path, ServiceScope]] | None = None,
    launchctl_list_output: str | None = None,
    system_print_output: str | None = None,
    gui_disabled_output: str | None = None,
    system_disabled_output: str | None = None,
) -> list[ServiceInfo]:
    """Discover launchd services from plist files and merge live launchctl status."""
    resolved_uid = os.getuid() if uid is None else uid

    if launchctl_list_output is None:
        launchctl_list_output = _run_launchctl(["list"])
    gui_runtime = parse_launchctl_list(launchctl_list_output)

    if system_print_output is None and plist_dirs is None:
        system_print_output = _run_launchctl(["print", "system"])
    system_runtime = parse_launchctl_domain_services(system_print_output or "")

    if gui_disabled_output is None and plist_dirs is None:
        gui_disabled_output = _run_launchctl(["print-disabled", f"gui/{resolved_uid}"])
    gui_disabled = parse_launchctl_disabled(gui_disabled_output or "")

    if system_disabled_output is None and plist_dirs is None:
        system_disabled_output = _run_launchctl(["print-disabled", "system"])
    system_disabled = parse_launchctl_disabled(system_disabled_output or "")

    scan_dirs = (
        list(plist_dirs)
        if plist_dirs is not None
        else default_plist_dirs(include_apple=include_apple)
    )
    if extra_dirs:
        scan_dirs.extend(extra_dirs)

    services: list[ServiceInfo] = []
    seen_gui_labels: set[str] = set()
    seen_system_labels: set[str] = set()

    for directory, scope in scan_dirs:
        if not directory.is_dir():
            continue
        try:
            entries = sorted(directory.glob("*.plist"), key=lambda p: p.name.lower())
        except OSError:
            continue

        domain_target = _domain_for_scope(scope, resolved_uid)
        is_system_domain = domain_target == "system"

        for plist_path in entries:
            plist_data, plist_error, raw_text = _read_plist_file(plist_path)
            raw_label = plist_data.get("Label")
            label = (
                raw_label.strip()
                if isinstance(raw_label, str) and raw_label.strip()
                else plist_path.stem
            )

            if is_system_domain:
                seen_system_labels.add(label)
                rt_entry = system_runtime.get(label)
                disabled_val = system_disabled.get(label)
            else:
                seen_gui_labels.add(label)
                rt_entry = gui_runtime.get(label)
                disabled_val = gui_disabled.get(label)

            loaded = rt_entry is not None
            pid = rt_entry[0] if rt_entry else None
            exit_status = rt_entry[1] if rt_entry else None

            svc = ServiceInfo(
                label=label,
                scope=scope,
                domain_target=domain_target,
                plist_path=plist_path,
                pid=pid,
                last_exit_status=exit_status,
                loaded=loaded,
                disabled_in_db=disabled_val,
                plist_data=plist_data,
                plist_error=plist_error,
                raw_plist_text=raw_text,
            )
            svc.diagnostics = diagnose_service(svc, current_uid=resolved_uid)
            services.append(svc)

    if include_runtime_only:
        for label, (pid, exit_status) in sorted(gui_runtime.items(), key=lambda kv: kv[0].lower()):
            if label in seen_gui_labels:
                continue
            if not include_apple and (
                label.startswith("com.apple.") or label.startswith("application.com.apple.")
            ):
                continue
            svc = ServiceInfo(
                label=label,
                scope=ServiceScope.RUNTIME_ONLY,
                domain_target=f"gui/{resolved_uid}",
                plist_path=None,
                pid=pid,
                last_exit_status=exit_status,
                loaded=True,
                disabled_in_db=gui_disabled.get(label),
            )
            svc.diagnostics = diagnose_service(svc, current_uid=resolved_uid)
            services.append(svc)

    scope_order = {
        ServiceScope.USER_AGENT: 0,
        ServiceScope.GLOBAL_AGENT: 1,
        ServiceScope.GLOBAL_DAEMON: 2,
        ServiceScope.RUNTIME_ONLY: 3,
        ServiceScope.SYSTEM_AGENT: 4,
        ServiceScope.SYSTEM_DAEMON: 5,
    }
    services.sort(key=lambda s: (scope_order[s.scope], s.label.lower()))
    return services


def build_demo_services(uid: int | None = None) -> list[ServiceInfo]:
    """Generate realistic demo services showcasing healthy, failed, disabled, and invalid jobs."""
    resolved_uid = os.getuid() if uid is None else uid
    gui_domain = f"gui/{resolved_uid}"
    home = Path.home()

    prtg_plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.prtg.monitor</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>{home}/.local/share/prtgmon/prtg_monitor.py</string>
        <string>{home}/.local/share/prtgmon/config.json</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>{home}/.local/share/prtgmon</string>
    <key>StandardOutPath</key>
    <string>{home}/Library/Logs/prtgmon/monitor.log</string>
    <key>StandardErrorPath</key>
    <string>{home}/Library/Logs/prtgmon/monitor_error.log</string>
</dict>
</plist>
"""

    api_plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.dev.local-api</string>
    <key>ProgramArguments</key>
    <array>
        <string>uvicorn</string>
        <string>app.main:app</string>
        <string>--port</string>
        <string>8080</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{home}/Library/Logs/local-api/out.log</string>
    <key>StandardErrorPath</key>
    <string>{home}/Library/Logs/local-api/err.log</string>
</dict>
</plist>
"""

    backup_plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.company.backup-agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/backup-sync</string>
        <string>--incremental</string>
    </array>
    <key>StartInterval</key>
    <integer>3600</integer>
    <key>StandardOutPath</key>
    <string>{home}/Library/Logs/company-backup/sync.log</string>
    <key>StandardErrorPath</key>
    <string>{home}/Library/Logs/company-backup/sync.err.log</string>
</dict>
</plist>
"""

    redis_plist = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.redis.server</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/homebrew/opt/redis/bin/redis-server</string>
        <string>/opt/homebrew/etc/redis.conf</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/opt/homebrew/var/log/redis.log</string>
    <key>StandardErrorPath</key>
    <string>/opt/homebrew/var/log/redis.log</string>
</dict>
</plist>
"""

    docker_plist = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>dev.kiri.docker-socket</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/kiri-docker-proxy</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/kiri-docker.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/kiri-docker.err.log</string>
</dict>
</plist>
"""

    broken_xml = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.broken.syntax-agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/true</string>
    <!-- Missing closing </array> and </dict> -->
</plist>
"""

    ollama_plist = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ollama.service</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/homebrew/bin/ollama</string>
        <string>serve</string>
    </array>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
"""

    services = [
        ServiceInfo(
            label="com.prtg.monitor",
            scope=ServiceScope.USER_AGENT,
            domain_target=gui_domain,
            plist_path=home / "Library/LaunchAgents/com.prtg.monitor.plist",
            pid=25688,
            last_exit_status=0,
            loaded=True,
            disabled_in_db=False,
            plist_data=plistlib.loads(prtg_plist.encode()),
            raw_plist_text=prtg_plist,
            runtime_details={
                "state": "running",
                "pid": 25688,
                "active count": 1,
                "runs": 2,
                "last exit code": 0,
                "working directory": f"{home}/.local/share/prtgmon",
                "environment": {"XPC_SERVICE_NAME": "com.prtg.monitor", "OSLogRateLimit": "64"},
            },
            diagnostics=[
                DiagnosticItem(
                    severity=Severity.OK,
                    code="SERVICE_HEALTHY",
                    title="Configuration looks healthy",
                    detail="Service is actively running under PID 25688 with exit code 0.",
                )
            ],
            demo_stdout=(
                "2026-11-22 09:50:01 [INFO] PRTG polling loop initialized (interval=30s)\n"
                "2026-11-22 09:50:31 [INFO] Checked 42 sensors: 41 UP, 1 WARNING\n"
                "2026-11-22 09:51:01 [INFO] Snapshot written to ~/.local/share/prtgmon/state.json\n"
            ),
            demo_stderr="",
        ),
        ServiceInfo(
            label="com.dev.local-api",
            scope=ServiceScope.USER_AGENT,
            domain_target=gui_domain,
            plist_path=home / "Library/LaunchAgents/com.dev.local-api.plist",
            pid=None,
            last_exit_status=127,
            loaded=True,
            disabled_in_db=False,
            plist_data=plistlib.loads(api_plist.encode()),
            raw_plist_text=api_plist,
            runtime_details={
                "state": "spawn scheduled",
                "active count": 0,
                "runs": 14,
                "last exit code": 127,
            },
            diagnostics=[
                DiagnosticItem(
                    severity=Severity.ERROR,
                    code="HOMEBREW_PATH_WARNING",
                    title="'uvicorn' is outside launchd's default PATH",
                    detail=(
                        "launchd runs with PATH='/usr/bin:/bin:/usr/sbin:/sbin' and does not load "
                        "your shell profile. 'uvicorn' lives in /opt/homebrew/bin/uvicorn."
                    ),
                    fix_hint="Use '/opt/homebrew/bin/uvicorn' or add EnvironmentVariables.PATH in the plist.",
                ),
                DiagnosticItem(
                    severity=Severity.ERROR,
                    code="NON_ZERO_EXIT",
                    title="Last run exited with 127 (Command not found)",
                    detail="launchd recorded last exit status 127 across 14 restarts.",
                    fix_hint="Press [E] to edit ProgramArguments[0] to an absolute path.",
                ),
            ],
            demo_stdout="",
            demo_stderr="launchd: spawn failed: command 'uvicorn' not found in /usr/bin:/bin:/usr/sbin:/sbin (exit 127)\n",
        ),
        ServiceInfo(
            label="com.company.backup-agent",
            scope=ServiceScope.USER_AGENT,
            domain_target=gui_domain,
            plist_path=home / "Library/LaunchAgents/com.company.backup-agent.plist",
            pid=None,
            last_exit_status=78,
            loaded=True,
            disabled_in_db=False,
            plist_data=plistlib.loads(backup_plist.encode()),
            raw_plist_text=backup_plist,
            runtime_details={
                "state": "not running",
                "runs": 1,
                "last exit code": 78,
            },
            diagnostics=[
                DiagnosticItem(
                    severity=Severity.ERROR,
                    code="MISSING_LOG_DIR",
                    title="Parent directory for StandardOutPath does not exist",
                    detail=(
                        f"'{home}/Library/Logs/company-backup' does not exist. launchd does NOT "
                        "create missing log directories and exits with code 78 before executing the program."
                    ),
                    fix_hint=f"mkdir -p {home}/Library/Logs/company-backup",
                ),
                DiagnosticItem(
                    severity=Severity.ERROR,
                    code="NON_ZERO_EXIT",
                    title="Last run exited with 78 (EX_CONFIG)",
                    detail="Exit 78 indicates launchd failed to open stdout/stderr or resolve paths.",
                    fix_hint="Create the missing log directory, then press [s] to kickstart.",
                ),
            ],
            demo_stdout="",
            demo_stderr="(No log file created yet because parent directory is missing)\n",
        ),
        ServiceInfo(
            label="dev.kiri.docker-socket",
            scope=ServiceScope.GLOBAL_DAEMON,
            domain_target="system",
            plist_path=Path("/Library/LaunchDaemons/dev.kiri.docker-socket.plist"),
            pid=None,
            last_exit_status=None,
            loaded=False,
            disabled_in_db=False,
            plist_data=plistlib.loads(docker_plist.encode()),
            raw_plist_text=docker_plist,
            diagnostics=[
                DiagnosticItem(
                    severity=Severity.ERROR,
                    code="INSECURE_PERMISSIONS",
                    title="Plist permissions (0o666) are group/world writable",
                    detail="launchd refuses to bootstrap LaunchDaemons writable by group or others.",
                    fix_hint="sudo chmod 644 /Library/LaunchDaemons/dev.kiri.docker-socket.plist",
                ),
                DiagnosticItem(
                    severity=Severity.ERROR,
                    code="WRONG_OWNER",
                    title="System plist is not owned by root (uid=501)",
                    detail="Files in /Library/LaunchDaemons must be owned by root:wheel.",
                    fix_hint="sudo chown root:wheel /Library/LaunchDaemons/dev.kiri.docker-socket.plist",
                ),
            ],
            demo_stdout="",
            demo_stderr="",
        ),
        ServiceInfo(
            label="com.redis.server",
            scope=ServiceScope.GLOBAL_AGENT,
            domain_target=gui_domain,
            plist_path=Path("/Library/LaunchAgents/com.redis.server.plist"),
            pid=None,
            last_exit_status=0,
            loaded=True,
            disabled_in_db=False,
            plist_data=plistlib.loads(redis_plist.encode()),
            raw_plist_text=redis_plist,
            runtime_details={"state": "waiting", "runs": 3, "last exit code": 0},
            diagnostics=[
                DiagnosticItem(
                    severity=Severity.OK,
                    code="SERVICE_HEALTHY",
                    title="Configuration looks healthy",
                    detail="Service is loaded in launchd and last exited cleanly (0).",
                )
            ],
            demo_stdout="1:M 22 Nov 2026 09:42:10.123 * Ready to accept connections tcp\n",
            demo_stderr="",
        ),
        ServiceInfo(
            label="com.ollama.service",
            scope=ServiceScope.USER_AGENT,
            domain_target=gui_domain,
            plist_path=home / "Library/LaunchAgents/com.ollama.service.plist",
            pid=None,
            last_exit_status=None,
            loaded=False,
            disabled_in_db=True,
            plist_data=plistlib.loads(ollama_plist.encode()),
            raw_plist_text=ollama_plist,
            diagnostics=[
                DiagnosticItem(
                    severity=Severity.WARNING,
                    code="SERVICE_DISABLED",
                    title="Service is disabled",
                    detail="Marked as disabled in launchd override database (`launchctl disable`).",
                    fix_hint=f"launchctl enable {gui_domain}/com.ollama.service",
                )
            ],
            demo_stdout="",
            demo_stderr="",
        ),
        ServiceInfo(
            label="com.broken.syntax-agent",
            scope=ServiceScope.USER_AGENT,
            domain_target=gui_domain,
            plist_path=home / "Library/LaunchAgents/com.broken.syntax-agent.plist",
            pid=None,
            last_exit_status=None,
            loaded=False,
            plist_error="not well-formed (invalid token): line 11, column 2",
            raw_plist_text=broken_xml,
            diagnostics=[
                DiagnosticItem(
                    severity=Severity.ERROR,
                    code="PLIST_PARSE_ERROR",
                    title="Malformed or unreadable plist file",
                    detail="XML syntax error at line 11, column 2: mismatched tag </plist>.",
                    fix_hint="Press [E] to fix the XML in the built-in Plist Editor.",
                )
            ],
            demo_stdout="",
            demo_stderr="",
        ),
    ]
    return services
