"""Service lifecycle actions, plist validation, safe writes, and templates."""

from __future__ import annotations

import os
import plistlib
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from lazylaunchd.models import ServiceInfo

CommandRunner = Callable[[list[str]], tuple[int, str, str]]


@dataclass(slots=True)
class ActionResult:
    """Result of a launchd lifecycle or file operation."""

    ok: bool
    message: str
    command: str | None = None
    requires_sudo: bool = False
    needs_refresh: bool = False


def default_command_runner(args: list[str], timeout: float = 8.0) -> tuple[int, str, str]:
    """Execute a subprocess command and return `(returncode, stdout, stderr)`."""
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", f"Command timed out: {' '.join(args)}"
    except OSError as exc:
        return 127, "", str(exc)


def _format_cmd(args: list[str], *, sudo: bool = False) -> str:
    prefix = "sudo " if sudo else ""
    return prefix + " ".join(shlex.quote(a) for a in args)


def _combined_output(stdout: str, stderr: str) -> str:
    parts = [p.strip() for p in (stderr, stdout) if p and p.strip()]
    return " | ".join(parts)


def load_service(
    service: ServiceInfo,
    *,
    runner: CommandRunner | None = None,
    demo: bool = False,
) -> ActionResult:
    """Load / bootstrap a service into its launchd domain."""
    if service.plist_path is None:
        return ActionResult(
            ok=False,
            message=f"'{service.label}' has no plist file on disk; cannot bootstrap.",
        )

    plist_str = str(service.plist_path)
    bootstrap_cmd = ["launchctl", "bootstrap", service.domain_target, plist_str]
    if demo:
        service.loaded = True
        service.last_exit_status = 0
        return ActionResult(
            ok=True,
            message=f"[Demo] Bootstrapped {service.service_target}",
            command=_format_cmd(bootstrap_cmd),
            needs_refresh=True,
        )

    if service.requires_sudo:
        return ActionResult(
            ok=False,
            requires_sudo=True,
            command=_format_cmd(bootstrap_cmd, sudo=True),
            message=(
                f"'{service.label}' is a {service.scope.label} and requires root privileges. "
                f"Run: {_format_cmd(bootstrap_cmd, sudo=True)}"
            ),
        )

    if not service.plist_path.exists():
        return ActionResult(ok=False, message=f"Plist file not found: {plist_str}")

    run = runner or default_command_runner
    rc, out, err = run(bootstrap_cmd)
    if rc == 0:
        return ActionResult(
            ok=True,
            message=f"Loaded {service.service_target}",
            command=_format_cmd(bootstrap_cmd),
            needs_refresh=True,
        )

    # Fallback to legacy `launchctl load -w` for compatibility with older/unusual plists.
    load_cmd = ["launchctl", "load", "-w", plist_str]
    rc2, out2, err2 = run(load_cmd)
    if rc2 == 0:
        return ActionResult(
            ok=True,
            message=f"Loaded {service.label} (via legacy load -w)",
            command=_format_cmd(load_cmd),
            needs_refresh=True,
        )

    detail = _combined_output(out, err) or _combined_output(out2, err2) or f"exit code {rc}"
    return ActionResult(
        ok=False,
        message=f"Failed to load {service.label}: {detail}",
        command=_format_cmd(bootstrap_cmd),
    )


def unload_service(
    service: ServiceInfo,
    *,
    runner: CommandRunner | None = None,
    demo: bool = False,
) -> ActionResult:
    """Unload / bootout a service from its launchd domain."""
    bootout_cmd = ["launchctl", "bootout", service.service_target]
    if demo:
        service.loaded = False
        service.pid = None
        return ActionResult(
            ok=True,
            message=f"[Demo] Booted out {service.service_target}",
            command=_format_cmd(bootout_cmd),
            needs_refresh=True,
        )

    if service.requires_sudo:
        return ActionResult(
            ok=False,
            requires_sudo=True,
            command=_format_cmd(bootout_cmd, sudo=True),
            message=(
                f"'{service.label}' requires root privileges to unload. "
                f"Run: {_format_cmd(bootout_cmd, sudo=True)}"
            ),
        )

    run = runner or default_command_runner
    rc, out, err = run(bootout_cmd)
    if rc == 0:
        return ActionResult(
            ok=True,
            message=f"Unloaded {service.service_target}",
            command=_format_cmd(bootout_cmd),
            needs_refresh=True,
        )

    if service.plist_path is not None:
        unload_cmd = ["launchctl", "unload", str(service.plist_path)]
        rc2, out2, err2 = run(unload_cmd)
        if rc2 == 0:
            return ActionResult(
                ok=True,
                message=f"Unloaded {service.label} (via legacy unload)",
                command=_format_cmd(unload_cmd),
                needs_refresh=True,
            )
        detail = _combined_output(out, err) or _combined_output(out2, err2) or f"exit code {rc}"
    else:
        detail = _combined_output(out, err) or f"exit code {rc}"

    return ActionResult(
        ok=False,
        message=f"Failed to unload {service.label}: {detail}",
        command=_format_cmd(bootout_cmd),
    )


def restart_service(
    service: ServiceInfo,
    *,
    runner: CommandRunner | None = None,
    demo: bool = False,
) -> ActionResult:
    """Start or restart a service using `launchctl kickstart -k`."""
    kickstart_cmd = ["launchctl", "kickstart", "-k", service.service_target]
    if demo:
        service.loaded = True
        service.pid = service.pid or 42100
        service.last_exit_status = 0
        return ActionResult(
            ok=True,
            message=f"[Demo] Kickstarted {service.service_target} (PID {service.pid})",
            command=_format_cmd(kickstart_cmd),
            needs_refresh=True,
        )

    if service.requires_sudo:
        return ActionResult(
            ok=False,
            requires_sudo=True,
            command=_format_cmd(kickstart_cmd, sudo=True),
            message=(
                f"'{service.label}' requires root privileges to kickstart. "
                f"Run: {_format_cmd(kickstart_cmd, sudo=True)}"
            ),
        )

    run = runner or default_command_runner
    if not service.loaded and service.plist_path is not None:
        boot_res = load_service(service, runner=run, demo=False)
        if not boot_res.ok:
            return boot_res

    rc, out, err = run(kickstart_cmd)
    if rc == 0:
        return ActionResult(
            ok=True,
            message=f"Started / kickstarted {service.service_target}",
            command=_format_cmd(kickstart_cmd),
            needs_refresh=True,
        )

    detail = _combined_output(out, err) or f"exit code {rc}"
    return ActionResult(
        ok=False,
        message=f"Failed to kickstart {service.label}: {detail}",
        command=_format_cmd(kickstart_cmd),
    )


def toggle_enable_service(
    service: ServiceInfo,
    *,
    runner: CommandRunner | None = None,
    demo: bool = False,
) -> ActionResult:
    """Enable a disabled service or disable an enabled service."""
    action = "enable" if service.is_disabled else "disable"
    cmd = ["launchctl", action, service.service_target]

    if demo:
        service.disabled_in_db = action == "disable"
        return ActionResult(
            ok=True,
            message=f"[Demo] {action.capitalize()}d {service.service_target}",
            command=_format_cmd(cmd),
            needs_refresh=True,
        )

    if service.requires_sudo:
        return ActionResult(
            ok=False,
            requires_sudo=True,
            command=_format_cmd(cmd, sudo=True),
            message=(
                f"'{service.label}' requires root privileges to {action}. "
                f"Run: {_format_cmd(cmd, sudo=True)}"
            ),
        )

    run = runner or default_command_runner
    rc, out, err = run(cmd)
    if rc == 0:
        return ActionResult(
            ok=True,
            message=f"{action.capitalize()}d {service.service_target}",
            command=_format_cmd(cmd),
            needs_refresh=True,
        )

    detail = _combined_output(out, err) or f"exit code {rc}"
    return ActionResult(
        ok=False,
        message=f"Failed to {action} {service.label}: {detail}",
        command=_format_cmd(cmd),
    )


def validate_plist_content(
    xml_text: str,
    *,
    use_plutil: bool = True,
    require_label: bool = False,
) -> tuple[bool, str, dict[str, Any] | None]:
    """Validate XML plist text with `plistlib` and optionally `plutil -lint -`."""
    if not xml_text.strip():
        return False, "Plist content is empty.", None

    try:
        parsed = plistlib.loads(xml_text.encode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        return False, f"XML/plist parse error: {exc}", None

    if not isinstance(parsed, dict):
        return False, f"Root plist object must be <dict>, got {type(parsed).__name__}.", None

    if require_label:
        lbl = parsed.get("Label")
        if not isinstance(lbl, str) or not lbl.strip():
            return False, "Plist must contain a non-empty string <key>Label</key>.", None

    if use_plutil and sys.platform == "darwin" and shutil.which("plutil"):
        try:
            proc = subprocess.run(
                ["plutil", "-lint", "-"],
                input=xml_text,
                capture_output=True,
                text=True,
                timeout=3.0,
                check=False,
            )
            if proc.returncode != 0:
                msg = (proc.stderr or proc.stdout or "plutil validation failed").strip()
                return False, msg, None
        except (OSError, subprocess.SubprocessError):
            pass

    return True, "Valid plist XML.", parsed


def save_plist_content(
    path: Path,
    xml_text: str,
    *,
    use_plutil: bool = True,
    require_label: bool = False,
) -> ActionResult:
    """Validate and atomically write XML plist content to `path`."""
    valid, msg, _ = validate_plist_content(
        xml_text,
        use_plutil=use_plutil,
        require_label=require_label,
    )
    if not valid:
        return ActionResult(ok=False, message=msg)

    existing_mode: int | None = None
    if path.exists():
        try:
            existing_mode = path.stat().st_mode & 0o777
        except OSError:
            existing_mode = None

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=str(path.parent),
        )
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(xml_text)
                if not xml_text.endswith("\n"):
                    fh.write("\n")
            os.chmod(tmp_path, existing_mode if existing_mode is not None else 0o644)
            os.replace(tmp_path, path)
        except Exception:
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            raise
    except PermissionError:
        return ActionResult(
            ok=False,
            requires_sudo=True,
            message=f"Permission denied writing {path}. System plists require root privileges.",
        )
    except OSError as exc:
        return ActionResult(ok=False, message=f"Failed to save {path}: {exc}")

    return ActionResult(
        ok=True,
        message=f"Saved valid plist to {path}",
        needs_refresh=True,
    )


def generate_agent_plist(
    label: str,
    program_args: list[str],
    *,
    run_at_load: bool = True,
    keep_alive: bool = False,
    working_directory: str | None = None,
    stdout_path: str | None = None,
    stderr_path: str | None = None,
    start_interval: int | None = None,
    env_path: str | None = None,
) -> str:
    """Generate a clean, well-formed LaunchAgent XML plist."""
    clean_label = label.strip()
    clean_args = [arg for arg in program_args if arg]
    if not clean_label:
        raise ValueError("Service label cannot be empty.")
    if not clean_args:
        raise ValueError("Program arguments cannot be empty.")

    data: dict[str, Any] = {
        "Label": clean_label,
        "ProgramArguments": clean_args,
    }
    if working_directory:
        data["WorkingDirectory"] = working_directory
    if run_at_load:
        data["RunAtLoad"] = True
    if keep_alive:
        data["KeepAlive"] = True
    if start_interval is not None and start_interval > 0:
        data["StartInterval"] = int(start_interval)
    if env_path:
        data["EnvironmentVariables"] = {"PATH": env_path}
    if stdout_path:
        data["StandardOutPath"] = stdout_path
    if stderr_path:
        data["StandardErrorPath"] = stderr_path

    return plistlib.dumps(data, fmt=plistlib.FMT_XML, sort_keys=False).decode("utf-8")


def copy_to_clipboard(text: str) -> tuple[bool, str]:
    """Copy text to the macOS clipboard via `pbcopy`."""
    pbcopy = shutil.which("pbcopy")
    if not pbcopy:
        return False, "Clipboard tool `pbcopy` is not available."
    try:
        proc = subprocess.run(
            [pbcopy],
            input=text,
            text=True,
            capture_output=True,
            timeout=3.0,
            check=False,
        )
        if proc.returncode == 0:
            return True, "Copied to clipboard."
        return False, (proc.stderr or "pbcopy failed").strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
