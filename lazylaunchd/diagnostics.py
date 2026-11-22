"""Root-cause diagnostics engine ('Why isn't it running?') for launchd services."""

from __future__ import annotations

import os
import shlex
import shutil
import stat
from collections.abc import Iterable
from pathlib import Path

from lazylaunchd.models import (
    DiagnosticItem,
    ServiceInfo,
    ServiceScope,
    ServiceState,
    Severity,
    explain_exit_status,
)

DEFAULT_LAUNCHD_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
HOMEBREW_EXTRA_PATHS = "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin"
_INTERPRETER_NAMES = {
    "python",
    "python3",
    "node",
    "ruby",
    "perl",
    "php",
    "bash",
    "sh",
    "zsh",
    "osascript",
    "pwsh",
}
_CRASH_SIGNALS = {4, 5, 6, 7, 8, 10, 11}  # SIGILL, SIGTRAP, SIGABRT, SIGEMT, SIGFPE, SIGBUS, SIGSEGV


def _is_script_interpreter(executable_name: str) -> bool:
    name = executable_name.lower()
    return name in _INTERPRETER_NAMES or name.startswith("python3.")


def _read_shebang(path: Path) -> str | None:
    """Return the shebang line (without `#!`) if `path` is a text script."""
    try:
        with path.open("rb") as fh:
            head = fh.read(256)
    except OSError:
        return None
    if not head.startswith(b"#!"):
        return None
    first_line = head.splitlines()[0][2:].decode("utf-8", errors="replace").strip()
    return first_line or None


def _get_plist_env_path(service: ServiceInfo) -> str | None:
    env = service.plist_data.get("EnvironmentVariables")
    if isinstance(env, dict):
        val = env.get("PATH")
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def _sudo_prefix(service: ServiceInfo) -> str:
    return "sudo " if service.requires_sudo else ""


def _diagnose_plist_file(
    service: ServiceInfo,
    items: list[DiagnosticItem],
    *,
    current_uid: int,
) -> None:
    plist_path = service.plist_path
    if plist_path is None:
        return

    if service.plist_error:
        items.append(
            DiagnosticItem(
                severity=Severity.ERROR,
                code="PLIST_PARSE_ERROR",
                title="Malformed or unreadable plist file",
                detail=f"Failed to parse {plist_path}: {service.plist_error}",
                fix_hint=f"Press [E] to edit XML or run: plutil -lint {shlex.quote(str(plist_path))}",
            )
        )
        return

    if not service.plist_data:
        items.append(
            DiagnosticItem(
                severity=Severity.WARNING,
                code="EMPTY_PLIST",
                title="Empty plist dictionary (<dict/>)",
                detail="Plist contains no keys (often left behind as an inactive stub by an updater or uninstaller).",
                fix_hint=f"Remove unused stub plist or populate it: rm {shlex.quote(str(plist_path))}",
            )
        )
        return

    label_val = service.plist_data.get("Label")
    if not isinstance(label_val, str) or not label_val.strip():
        items.append(
            DiagnosticItem(
                severity=Severity.ERROR,
                code="MISSING_LABEL",
                title="Missing required 'Label' key",
                detail="Every LaunchAgent/LaunchDaemon plist must define a non-empty string <key>Label</key>.",
                fix_hint="Press [E] to add <key>Label</key><string>...</string> to the plist.",
            )
        )
    elif plist_path.stem != label_val.strip():
        items.append(
            DiagnosticItem(
                severity=Severity.WARNING,
                code="LABEL_FILENAME_MISMATCH",
                title="Plist filename does not match Label",
                detail=(
                    f"File is named '{plist_path.name}', but Label is '{label_val.strip()}'. "
                    "macOS convention expects '<Label>.plist'."
                ),
                fix_hint=(
                    f"mv {shlex.quote(str(plist_path))} "
                    f"{shlex.quote(str(plist_path.with_name(label_val.strip() + '.plist')))}"
                ),
            )
        )

    if not plist_path.exists():
        return

    try:
        st = plist_path.stat()
    except OSError:
        return

    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o022 != 0:
        items.append(
            DiagnosticItem(
                severity=Severity.ERROR,
                code="INSECURE_PERMISSIONS",
                title=f"Plist permissions ({oct(mode)}) are group/world writable",
                detail=(
                    f"launchd rejects plist files writable by group or others (current mode: {oct(mode)}). "
                    "The file must be 0644 (-rw-r--r--) or 0600."
                ),
                fix_hint=f"{_sudo_prefix(service)}chmod 644 {shlex.quote(str(plist_path))}",
            )
        )

    if service.scope in (
        ServiceScope.GLOBAL_AGENT,
        ServiceScope.GLOBAL_DAEMON,
        ServiceScope.SYSTEM_AGENT,
        ServiceScope.SYSTEM_DAEMON,
    ) and st.st_uid != 0:
        items.append(
            DiagnosticItem(
                severity=Severity.ERROR,
                code="WRONG_OWNER",
                title=f"System plist is not owned by root (uid={st.st_uid})",
                detail=(
                    f"Files in {plist_path.parent} must be owned by root:wheel, "
                    f"otherwise launchd refuses to load them (current uid: {st.st_uid})."
                ),
                fix_hint=f"sudo chown root:wheel {shlex.quote(str(plist_path))}",
            )
        )
    elif (
        service.scope == ServiceScope.USER_AGENT
        and st.st_uid not in (current_uid, 0)
    ):
        items.append(
            DiagnosticItem(
                severity=Severity.WARNING,
                code="WRONG_OWNER",
                title=f"User LaunchAgent is owned by uid={st.st_uid}",
                detail=f"Expected plist {plist_path} to be owned by current user (uid={current_uid}).",
                fix_hint=f"chown $(id -un) {shlex.quote(str(plist_path))}",
            )
        )


def _diagnose_command(service: ServiceInfo, items: list[DiagnosticItem]) -> None:
    if service.plist_error or not service.plist_data:
        return

    if service.plist_data.get("BundleProgram"):
        return

    cmd = service.program_command
    if not cmd:
        items.append(
            DiagnosticItem(
                severity=Severity.ERROR,
                code="MISSING_PROGRAM_KEY",
                title="Missing 'Program' or 'ProgramArguments'",
                detail="The plist has neither <key>Program</key> nor <key>ProgramArguments</key>.",
                fix_hint="Press [E] to add ProgramArguments with the executable path.",
            )
        )
        return

    exe = cmd[0]
    plist_env_path = _get_plist_env_path(service)
    launchd_path = plist_env_path or DEFAULT_LAUNCHD_PATH

    if exe.startswith("~") or "$" in exe:
        items.append(
            DiagnosticItem(
                severity=Severity.ERROR,
                code="EXECUTABLE_NOT_FOUND",
                title="Shell tilde or variable used in executable path",
                detail=(
                    f"Executable '{exe}' uses '~' or '$VAR', which launchd does NOT expand "
                    "when spawning processes."
                ),
                fix_hint="Replace '~' or environment variables with an absolute path in the plist.",
            )
        )
        return

    resolved_exe: Path | None = None
    if "/" in exe:
        candidate = Path(exe)
        if not candidate.exists():
            alt = shutil.which(candidate.name, path=f"{launchd_path}:{HOMEBREW_EXTRA_PATHS}")
            hint = f"Found '{candidate.name}' at {alt}" if alt else f"Verify the path '{exe}' exists."
            items.append(
                DiagnosticItem(
                    severity=Severity.ERROR,
                    code="EXECUTABLE_NOT_FOUND",
                    title="Executable not found on disk",
                    detail=f"Configured executable '{exe}' does not exist.",
                    fix_hint=hint,
                )
            )
            return
        resolved_exe = candidate
    else:
        found_in_launchd = shutil.which(exe, path=launchd_path)
        if found_in_launchd:
            resolved_exe = Path(found_in_launchd)
        else:
            found_in_brew = shutil.which(exe, path=f"{HOMEBREW_EXTRA_PATHS}:{launchd_path}")
            if found_in_brew:
                items.append(
                    DiagnosticItem(
                        severity=Severity.ERROR,
                        code="HOMEBREW_PATH_WARNING",
                        title=f"'{exe}' is outside launchd's default PATH",
                        detail=(
                            f"launchd runs with PATH='{launchd_path}' and does not load your shell profile. "
                            f"'{exe}' resolves to '{found_in_brew}', which is not in launchd's PATH."
                        ),
                        fix_hint=(
                            f"Use the absolute path '{found_in_brew}' in ProgramArguments, "
                            "or set EnvironmentVariables -> PATH in the plist."
                        ),
                    )
                )
                resolved_exe = Path(found_in_brew)
            else:
                items.append(
                    DiagnosticItem(
                        severity=Severity.ERROR,
                        code="EXECUTABLE_NOT_FOUND",
                        title=f"Bare command '{exe}' could not be resolved",
                        detail=(
                            f"'{exe}' was not found in launchd PATH ('{launchd_path}') "
                            "or standard Homebrew locations."
                        ),
                        fix_hint="Specify the full absolute path to the executable.",
                    )
                )
                return

    if resolved_exe is not None:
        if resolved_exe.is_dir():
            items.append(
                DiagnosticItem(
                    severity=Severity.ERROR,
                    code="EXECUTABLE_NOT_EXECUTABLE",
                    title="Program path points to a directory, not an executable",
                    detail=f"'{resolved_exe}' is a directory (e.g., an .app bundle instead of Contents/MacOS/<binary>).",
                    fix_hint="Point ProgramArguments[0] to the binary inside Contents/MacOS/.",
                )
            )
            return

        if service.requires_sudo:
            try:
                is_exec = (resolved_exe.stat().st_mode & 0o111) != 0
            except OSError:
                is_exec = os.access(resolved_exe, os.X_OK)
        else:
            is_exec = os.access(resolved_exe, os.X_OK)

        if not is_exec:
            items.append(
                DiagnosticItem(
                    severity=Severity.ERROR,
                    code="EXECUTABLE_NOT_EXECUTABLE",
                    title="Executable lacks execute permission (+x)",
                    detail=f"'{resolved_exe}' exists but is not executable.",
                    fix_hint=f"{_sudo_prefix(service)}chmod +x {shlex.quote(str(resolved_exe))}",
                )
            )

        shebang = _read_shebang(resolved_exe)
        if shebang:
            _check_shebang(shebang, resolved_exe, launchd_path, items)

        if resolved_exe.name == "env" and len(cmd) > 1:
            target_tool = cmd[1]
            if "/" not in target_tool and not shutil.which(target_tool, path=launchd_path):
                brew_hit = shutil.which(target_tool, path=HOMEBREW_EXTRA_PATHS)
                if brew_hit:
                    items.append(
                        DiagnosticItem(
                            severity=Severity.ERROR,
                            code="HOMEBREW_PATH_WARNING",
                            title=f"'/usr/bin/env {target_tool}' cannot find '{target_tool}' in launchd PATH",
                            detail=(
                                f"'{target_tool}' lives at '{brew_hit}', which is absent from "
                                f"launchd PATH '{launchd_path}'."
                            ),
                            fix_hint=f"Replace '/usr/bin/env {target_tool}' with '{brew_hit}' or set EnvironmentVariables.PATH.",
                        )
                    )

        if _is_script_interpreter(resolved_exe.name):
            _check_interpreter_script_arg(cmd[1:], items)


def _check_shebang(
    shebang: str,
    script_path: Path,
    launchd_path: str,
    items: list[DiagnosticItem],
) -> None:
    try:
        parts = shlex.split(shebang)
    except ValueError:
        parts = shebang.split()
    if not parts:
        return
    interp = parts[0]
    if interp == "/usr/bin/env" and len(parts) > 1:
        tool = parts[1]
        if not shutil.which(tool, path=launchd_path):
            brew_hit = shutil.which(tool, path=HOMEBREW_EXTRA_PATHS)
            if brew_hit:
                items.append(
                    DiagnosticItem(
                        severity=Severity.WARNING,
                        code="HOMEBREW_PATH_WARNING",
                        title=f"Script shebang '#!/usr/bin/env {tool}' relies on shell PATH",
                        detail=(
                            f"'{script_path}' uses '#!{shebang}', but '{tool}' ({brew_hit}) is not in "
                            f"launchd PATH '{launchd_path}'."
                        ),
                        fix_hint=f"Add '{Path(brew_hit).parent}' to EnvironmentVariables.PATH in the plist.",
                    )
                )
            else:
                items.append(
                    DiagnosticItem(
                        severity=Severity.ERROR,
                        code="BAD_SHEBANG",
                        title=f"Shebang target '{tool}' not found",
                        detail=f"'{script_path}' starts with '#!{shebang}', but '{tool}' was not found.",
                        fix_hint="Install the interpreter or update the shebang line.",
                    )
                )
    elif interp.startswith("/") and not Path(interp).exists():
        items.append(
            DiagnosticItem(
                severity=Severity.ERROR,
                code="BAD_SHEBANG",
                title="Script shebang interpreter does not exist",
                detail=f"'{script_path}' has '#!{shebang}', but '{interp}' does not exist.",
                fix_hint="Fix the shebang path in the script or specify the interpreter explicitly in ProgramArguments.",
            )
        )


def _check_interpreter_script_arg(args: Iterable[str], items: list[DiagnosticItem]) -> None:
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in ("-c", "-e", "-m"):
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        if arg.startswith("~") or "$" in arg:
            items.append(
                DiagnosticItem(
                    severity=Severity.ERROR,
                    code="SCRIPT_NOT_FOUND",
                    title="Script argument uses unexpanded '~' or '$VAR'",
                    detail=f"Argument '{arg}' will not be expanded by launchd.",
                    fix_hint="Use a full absolute path in ProgramArguments.",
                )
            )
            return
        if arg.startswith("/"):
            if not Path(arg).exists():
                items.append(
                    DiagnosticItem(
                        severity=Severity.ERROR,
                        code="SCRIPT_NOT_FOUND",
                        title="Script argument file not found",
                        detail=f"Interpreter argument '{arg}' does not exist on disk.",
                        fix_hint=f"Verify '{arg}' exists or update ProgramArguments.",
                    )
                )
            return
        # Stop after the first positional argument.
        return


def _diagnose_paths(service: ServiceInfo, items: list[DiagnosticItem]) -> None:
    if service.plist_error:
        return

    wd = service.working_directory
    if wd:
        if wd.startswith("~") or "$" in wd:
            items.append(
                DiagnosticItem(
                    severity=Severity.ERROR,
                    code="MISSING_WORKING_DIR",
                    title="WorkingDirectory uses unexpanded '~' or '$VAR'",
                    detail=f"WorkingDirectory '{wd}' is not expanded by launchd and fails with exit code 78.",
                    fix_hint="Use an absolute path for WorkingDirectory.",
                )
            )
        elif not Path(wd).is_dir():
            items.append(
                DiagnosticItem(
                    severity=Severity.ERROR,
                    code="MISSING_WORKING_DIR",
                    title="WorkingDirectory does not exist",
                    detail=f"Configured WorkingDirectory '{wd}' is missing. launchd cannot spawn the job (exit 78).",
                    fix_hint=f"{_sudo_prefix(service)}mkdir -p {shlex.quote(wd)}",
                )
            )

    for key_name, log_path in (
        ("StandardOutPath", service.stdout_path),
        ("StandardErrorPath", service.stderr_path),
    ):
        if not log_path:
            continue
        if log_path.startswith("~") or "$" in log_path:
            items.append(
                DiagnosticItem(
                    severity=Severity.ERROR,
                    code="MISSING_LOG_DIR",
                    title=f"{key_name} uses unexpanded '~' or '$VAR'",
                    detail=f"{key_name}='{log_path}' is not expanded by launchd and causes exit code 78.",
                    fix_hint=f"Use a full absolute path for {key_name}.",
                )
            )
            continue

        target = Path(log_path)
        parent = target.parent
        if not parent.exists():
            items.append(
                DiagnosticItem(
                    severity=Severity.ERROR,
                    code="MISSING_LOG_DIR",
                    title=f"Parent directory for {key_name} does not exist",
                    detail=(
                        f"'{parent}' does not exist. launchd does NOT create missing log directories "
                        "and exits with code 78 before executing the program."
                    ),
                    fix_hint=f"{_sudo_prefix(service)}mkdir -p {shlex.quote(str(parent))}",
                )
            )
            continue

        if not service.requires_sudo:
            if not os.access(parent, os.W_OK) and not target.exists():
                items.append(
                    DiagnosticItem(
                        severity=Severity.ERROR,
                        code="UNWRITABLE_LOG_PATH",
                        title=f"Log directory for {key_name} is not writable",
                        detail=f"Current user cannot create log file in '{parent}'.",
                        fix_hint=f"Check permissions on {shlex.quote(str(parent))}.",
                    )
                )
            elif target.exists() and not os.access(target, os.W_OK):
                items.append(
                    DiagnosticItem(
                        severity=Severity.ERROR,
                        code="UNWRITABLE_LOG_PATH",
                        title=f"{key_name} file is not writable",
                        detail=f"Current user lacks write permission to '{target}'.",
                        fix_hint=f"chmod u+w {shlex.quote(str(target))}",
                    )
                )


def _diagnose_runtime_status(service: ServiceInfo, items: list[DiagnosticItem]) -> None:
    if service.is_disabled:
        source = (
            "launchd override database (`launchctl disable`)"
            if service.disabled_in_db is True
            else "plist `<key>Disabled</key><true/>`"
        )
        items.append(
            DiagnosticItem(
                severity=Severity.WARNING,
                code="SERVICE_DISABLED",
                title="Service is disabled",
                detail=f"Marked as disabled via {source}, so launchd will not load or start it automatically.",
                fix_hint=f"{_sudo_prefix(service)}launchctl enable {service.service_target}",
            )
        )

    code = service.last_exit_status
    if code is not None and code != 0:
        explained = explain_exit_status(code)
        if code < 0:
            sig = abs(code)
            is_running = service.pid is not None and service.pid > 0
            sev = (
                Severity.ERROR
                if (sig in _CRASH_SIGNALS and not is_running)
                else Severity.INFO
                if is_running
                else Severity.WARNING
            )
            items.append(
                DiagnosticItem(
                    severity=sev,
                    code="KILLED_BY_SIGNAL",
                    title=f"Last run terminated by signal ({explained})",
                    detail=(
                        "Process exited abnormally due to a POSIX signal. "
                        "SIGKILL (-9) or SIGTERM (-15) may come from launchd idle reaping or manual stop; "
                        "SIGSEGV/SIGABRT indicates a crash."
                    ),
                    fix_hint="Inspect StandardErrorPath and macOS Unified Logs ([2] / [L]).",
                )
            )
        else:
            is_running = service.pid is not None and service.pid > 0
            sev = Severity.WARNING if is_running else Severity.ERROR
            extra = ""
            if code == 78:
                extra = (
                    " Exit 78 (EX_CONFIG) in launchd usually means a missing WorkingDirectory, "
                    "missing StandardOutPath/StandardErrorPath directory, non-executable binary, or invalid user."
                )
            elif code == 127:
                extra = " Exit 127 means a command or shared dependency could not be found in launchd's PATH."
            items.append(
                DiagnosticItem(
                    severity=sev,
                    code="NON_ZERO_EXIT",
                    title=f"Last run exited with {explained}",
                    detail=f"launchd recorded last exit status {code}.{extra}",
                    fix_hint="Check Logs tab ([2]) or run [s] to kickstart and observe stderr.",
                )
            )

    if (
        not service.plist_error
        and service.plist_data
        and not service.is_disabled
        and service.pid is None
        and service.schedule_summary == "On demand / manual"
    ):
        items.append(
            DiagnosticItem(
                severity=Severity.WARNING,
                code="NO_START_TRIGGER",
                title="No automatic start trigger configured",
                detail=(
                    "Plist has no RunAtLoad, KeepAlive, StartInterval, StartCalendarInterval, "
                    "WatchPaths, QueueDirectories, Sockets, or MachServices."
                ),
                fix_hint="Set <key>RunAtLoad</key><true/> if it should start on login/boot, or trigger manually with [s].",
            )
        )


def diagnose_service(
    service: ServiceInfo,
    current_uid: int | None = None,
) -> list[DiagnosticItem]:
    """Analyze a ServiceInfo and return ordered diagnostic findings."""
    uid = os.getuid() if current_uid is None else current_uid
    items: list[DiagnosticItem] = []

    _diagnose_plist_file(service, items, current_uid=uid)
    _diagnose_command(service, items)
    _diagnose_paths(service, items)
    _diagnose_runtime_status(service, items)

    if not any(d.severity in (Severity.ERROR, Severity.WARNING) for d in items):
        if service.state == ServiceState.RUNNING:
            summary = f"Service is actively running under PID {service.pid}."
        elif service.state == ServiceState.LOADED:
            summary = "Service is loaded in launchd and last exited cleanly (0)."
        elif service.state == ServiceState.UNLOADED:
            summary = "Plist configuration looks valid; service is currently unloaded."
        else:
            summary = "No configuration errors detected."
        items.insert(
            0,
            DiagnosticItem(
                severity=Severity.OK,
                code="SERVICE_HEALTHY",
                title="Configuration looks healthy",
                detail=summary,
            ),
        )

    severity_rank = {
        Severity.ERROR: 0,
        Severity.WARNING: 1,
        Severity.INFO: 2,
        Severity.OK: 3,
    }
    items.sort(key=lambda d: severity_rank[d.severity])
    return items
