"""Comprehensive test suite for lazylaunchd."""

from __future__ import annotations

import asyncio
import json
import os
import plistlib
from pathlib import Path
from unittest.mock import patch

import pytest
from textual.widgets import DataTable, Input, Static

from lazylaunchd.actions import (
    generate_agent_plist,
    load_service,
    restart_service,
    save_plist_content,
    toggle_enable_service,
    unload_service,
    validate_plist_content,
)
from lazylaunchd.cli import main as cli_main
from lazylaunchd.core import (
    build_demo_services,
    discover_services,
    explain_exit_status,
    parse_launchctl_disabled,
    parse_launchctl_domain_services,
    parse_launchctl_list,
    parse_launchctl_print,
    refresh_service_diagnostics,
    short_exit_status,
)
from lazylaunchd.diagnostics import diagnose_service
from lazylaunchd.logs import read_service_logs, tail_file
from lazylaunchd.models import (
    ServiceInfo,
    ServiceScope,
    ServiceState,
    Severity,
)
from lazylaunchd.tui import HelpModal, LazyLaunchdApp, NewAgentModal, PlistEditorModal


def _write_plist(path: Path, data: dict) -> Path:
    path.write_bytes(plistlib.dumps(data, fmt=plistlib.FMT_XML))
    path.chmod(0o644)
    return path


def _make_executable(path: Path, content: str = "#!/bin/sh\nexit 0\n") -> Path:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)
    return path


# ---------------------------------------------------------------------------
# Core parsers & exit code decoding
# ---------------------------------------------------------------------------


def test_parse_launchctl_list() -> None:
    sample = (
        "PID\tStatus\tLabel\n"
        "-\t0\tcom.apple.FinderHelper\n"
        "25688\t0\tcom.prtg.monitor\n"
        "-\t-9\tcom.apple.cloudphotod\n"
        "-\t78\tcom.dev.broken\n"
        "123\t-\tcom.dev.starting\n"
    )
    parsed = parse_launchctl_list(sample)
    assert parsed["com.apple.FinderHelper"] == (None, 0)
    assert parsed["com.prtg.monitor"] == (25688, 0)
    assert parsed["com.apple.cloudphotod"] == (None, -9)
    assert parsed["com.dev.broken"] == (None, 78)
    assert parsed["com.dev.starting"] == (123, None)


def test_parse_launchctl_disabled() -> None:
    sample = """
    disabled services = {
        "com.apple.screensharing" => disabled
        "com.openssh.sshd" => enabled
    }
    """
    parsed = parse_launchctl_disabled(sample)
    assert parsed == {
        "com.apple.screensharing": True,
        "com.openssh.sshd": False,
    }


def test_parse_launchctl_domain_services() -> None:
    sample = """
    system = {
        services = {
               0      - \tcom.apple.srp-mdns-proxy
           40931      - \tnetbird
               0      1 \tcom.apple.wifiFirmwareLoader
               0   (pe) \tcom.apple.lskdd
        }
        endpoints = {
            0xcb797 M D com.ignored.endpoint
        }
    }
    """
    parsed = parse_launchctl_domain_services(sample)
    assert parsed["com.apple.srp-mdns-proxy"] == (None, None)
    assert parsed["netbird"] == (40931, None)
    assert parsed["com.apple.wifiFirmwareLoader"] == (None, 1)
    assert parsed["com.apple.lskdd"] == (None, None)
    assert "com.ignored.endpoint" not in parsed


def test_parse_launchctl_print() -> None:
    sample = """
gui/501/com.prtg.monitor = {
    active count = 1
    path = /Users/test/Library/LaunchAgents/com.prtg.monitor.plist
    type = LaunchAgent
    state = running

    program = /usr/bin/python3
    arguments = {
        /usr/bin/python3
        /Users/test/monitor.py
    }

    environment = {
        OSLogRateLimit => 64
        XPC_SERVICE_NAME => com.prtg.monitor
    }

    runs = 2
    pid = 25688
    last exit code = 0
}
"""
    parsed = parse_launchctl_print(sample)
    assert parsed["state"] == "running"
    assert parsed["pid"] == 25688
    assert parsed["runs"] == 2
    assert parsed["last exit code"] == 0
    assert parsed["arguments"] == ["/usr/bin/python3", "/Users/test/monitor.py"]
    assert parsed["environment"]["XPC_SERVICE_NAME"] == "com.prtg.monitor"


def test_explain_exit_status() -> None:
    assert explain_exit_status(None) == "-"
    assert explain_exit_status(0) == "0 (OK)"
    assert "SIGKILL" in explain_exit_status(-9)
    assert "SIGTERM" in explain_exit_status(-15)
    assert "EX_CONFIG" in explain_exit_status(78)
    assert "Command not found" in explain_exit_status(127)


def test_short_exit_status() -> None:
    assert short_exit_status(None) == "-"
    assert short_exit_status(0) == "0 OK"
    assert short_exit_status(-9) == "-9 SIGKILL"
    assert short_exit_status(-11) == "-11 SIGSEGV"
    assert short_exit_status(-15) == "-15 SIGTERM"
    assert short_exit_status(2) == "2 ENOENT"
    assert short_exit_status(13) == "13 EACCES"
    assert short_exit_status(78) == "78 EX_CONFIG"
    assert short_exit_status(126) == "126 NO_EXEC"
    assert short_exit_status(127) == "127 NOT_FOUND"
    assert short_exit_status(137) == "137 SIGKILL"
    assert short_exit_status(42) == "42"


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def test_discover_services_merges_xml_binary_invalid_and_runtime(tmp_path: Path) -> None:
    exe = _make_executable(tmp_path / "worker.sh")
    log_file = tmp_path / "worker.log"

    _write_plist(
        tmp_path / "com.test.good.plist",
        {
            "Label": "com.test.good",
            "ProgramArguments": [str(exe)],
            "RunAtLoad": True,
            "StandardOutPath": str(log_file),
        },
    )
    # Binary plist
    bin_path = tmp_path / "com.test.binary.plist"
    bin_path.write_bytes(
        plistlib.dumps(
            {
                "Label": "com.test.binary",
                "ProgramArguments": [str(exe)],
                "RunAtLoad": True,
            },
            fmt=plistlib.FMT_BINARY,
        )
    )
    bin_path.chmod(0o644)

    # Malformed plist
    bad_path = tmp_path / "com.test.bad.plist"
    bad_path.write_text("<plist><dict><broken></plist>", encoding="utf-8")
    bad_path.chmod(0o644)

    launchctl_out = (
        "PID\tStatus\tLabel\n"
        "4321\t0\tcom.test.good\n"
        "-\t78\tcom.test.binary\n"
        "-\t0\tcom.test.runtimeonly\n"
        "-\t-9\tcom.apple.ignored\n"
    )

    services = discover_services(
        uid=501,
        include_apple=False,
        plist_dirs=[(tmp_path, ServiceScope.USER_AGENT)],
        launchctl_list_output=launchctl_out,
        gui_disabled_output='"com.test.binary" => enabled\n',
        system_print_output="",
        system_disabled_output="",
    )

    by_label = {s.label: s for s in services}
    assert "com.apple.ignored" not in by_label

    assert by_label["com.test.good"].state == ServiceState.RUNNING
    assert by_label["com.test.good"].pid == 4321

    assert by_label["com.test.binary"].state == ServiceState.FAILED
    assert "<plist" in by_label["com.test.binary"].raw_plist_text

    assert by_label["com.test.bad"].state == ServiceState.INVALID
    assert any(d.code == "PLIST_PARSE_ERROR" for d in by_label["com.test.bad"].diagnostics)

    assert by_label["com.test.runtimeonly"].scope == ServiceScope.RUNTIME_ONLY
    assert by_label["com.test.runtimeonly"].state == ServiceState.LOADED


# ---------------------------------------------------------------------------
# Diagnostics engine
# ---------------------------------------------------------------------------


def test_diagnostics_detects_missing_label_and_filename_mismatch(tmp_path: Path) -> None:
    exe = _make_executable(tmp_path / "run.sh")
    empty_plist = _write_plist(tmp_path / "com.test.empty.plist", {})
    svc_empty = ServiceInfo(
        label="com.test.empty",
        scope=ServiceScope.USER_AGENT,
        domain_target="gui/501",
        plist_path=empty_plist,
        plist_data=plistlib.loads(empty_plist.read_bytes()),
    )
    empty_diags = diagnose_service(svc_empty, current_uid=os.getuid())
    assert [d.code for d in empty_diags] == ["EMPTY_PLIST"]
    assert empty_diags[0].severity == Severity.WARNING

    no_label = _write_plist(
        tmp_path / "nolabel.plist",
        {"ProgramArguments": [str(exe)], "RunAtLoad": True},
    )
    svc1 = ServiceInfo(
        label="nolabel",
        scope=ServiceScope.USER_AGENT,
        domain_target="gui/501",
        plist_path=no_label,
        plist_data=plistlib.loads(no_label.read_bytes()),
    )
    codes1 = {d.code for d in diagnose_service(svc1, current_uid=os.getuid())}
    assert "MISSING_LABEL" in codes1

    mismatch = _write_plist(
        tmp_path / "wrongname.plist",
        {"Label": "com.example.actual", "ProgramArguments": [str(exe)], "RunAtLoad": True},
    )
    svc2 = ServiceInfo(
        label="com.example.actual",
        scope=ServiceScope.USER_AGENT,
        domain_target="gui/501",
        plist_path=mismatch,
        plist_data=plistlib.loads(mismatch.read_bytes()),
    )
    codes2 = {d.code for d in diagnose_service(svc2, current_uid=os.getuid())}
    assert "LABEL_FILENAME_MISMATCH" in codes2


def test_diagnostics_detects_permissions_and_wrong_owner(tmp_path: Path) -> None:
    exe = _make_executable(tmp_path / "daemon.sh")
    plist_path = _write_plist(
        tmp_path / "com.example.daemon.plist",
        {"Label": "com.example.daemon", "ProgramArguments": [str(exe)], "RunAtLoad": True},
    )
    plist_path.chmod(0o666)

    svc = ServiceInfo(
        label="com.example.daemon",
        scope=ServiceScope.GLOBAL_DAEMON,
        domain_target="system",
        plist_path=plist_path,
        plist_data=plistlib.loads(plist_path.read_bytes()),
    )
    diags = diagnose_service(svc, current_uid=501)
    codes = {d.code for d in diags}
    assert "INSECURE_PERMISSIONS" in codes
    if os.geteuid() != 0:
        assert "WRONG_OWNER" in codes


def test_diagnostics_detects_missing_executable_nonexec_and_bad_shebang(tmp_path: Path) -> None:
    # Missing executable
    p1 = _write_plist(
        tmp_path / "com.test.missingexe.plist",
        {"Label": "com.test.missingexe", "ProgramArguments": [str(tmp_path / "nope")], "RunAtLoad": True},
    )
    s1 = ServiceInfo(
        label="com.test.missingexe",
        scope=ServiceScope.USER_AGENT,
        domain_target="gui/501",
        plist_path=p1,
        plist_data=plistlib.loads(p1.read_bytes()),
    )
    assert any(d.code == "EXECUTABLE_NOT_FOUND" for d in diagnose_service(s1, current_uid=os.getuid()))

    # Non-executable binary
    nonexec = tmp_path / "script.sh"
    nonexec.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    nonexec.chmod(0o644)
    p2 = _write_plist(
        tmp_path / "com.test.nonexec.plist",
        {"Label": "com.test.nonexec", "ProgramArguments": [str(nonexec)], "RunAtLoad": True},
    )
    s2 = ServiceInfo(
        label="com.test.nonexec",
        scope=ServiceScope.USER_AGENT,
        domain_target="gui/501",
        plist_path=p2,
        plist_data=plistlib.loads(p2.read_bytes()),
    )
    assert any(d.code == "EXECUTABLE_NOT_EXECUTABLE" for d in diagnose_service(s2, current_uid=os.getuid()))

    # Bad shebang
    bad_shebang = _make_executable(tmp_path / "bad_shebang.sh", "#!/nonexistent/interp\n")
    p3 = _write_plist(
        tmp_path / "com.test.badshebang.plist",
        {"Label": "com.test.badshebang", "ProgramArguments": [str(bad_shebang)], "RunAtLoad": True},
    )
    s3 = ServiceInfo(
        label="com.test.badshebang",
        scope=ServiceScope.USER_AGENT,
        domain_target="gui/501",
        plist_path=p3,
        plist_data=plistlib.loads(p3.read_bytes()),
    )
    assert any(d.code == "BAD_SHEBANG" for d in diagnose_service(s3, current_uid=os.getuid()))


def test_diagnostics_detects_homebrew_path_warning_and_missing_script(tmp_path: Path) -> None:
    # Bare command available only in Homebrew PATH
    p1 = _write_plist(
        tmp_path / "com.test.brew.plist",
        {"Label": "com.test.brew", "ProgramArguments": ["mybrewtool", "--serve"], "RunAtLoad": True},
    )
    s1 = ServiceInfo(
        label="com.test.brew",
        scope=ServiceScope.USER_AGENT,
        domain_target="gui/501",
        plist_path=p1,
        plist_data=plistlib.loads(p1.read_bytes()),
    )

    def fake_which(cmd: str, path: str | None = None) -> str | None:
        if cmd == "mybrewtool" and path and "/opt/homebrew/bin" in path:
            return "/opt/homebrew/bin/mybrewtool"
        return None

    with patch("lazylaunchd.diagnostics.shutil.which", side_effect=fake_which):
        codes = {d.code for d in diagnose_service(s1, current_uid=os.getuid())}
    assert "HOMEBREW_PATH_WARNING" in codes

    # Interpreter + missing script argument
    fake_py = _make_executable(tmp_path / "python3")
    p2 = _write_plist(
        tmp_path / "com.test.missingscript.plist",
        {
            "Label": "com.test.missingscript",
            "ProgramArguments": [str(fake_py), str(tmp_path / "missing_worker.py")],
            "RunAtLoad": True,
        },
    )
    s2 = ServiceInfo(
        label="com.test.missingscript",
        scope=ServiceScope.USER_AGENT,
        domain_target="gui/501",
        plist_path=p2,
        plist_data=plistlib.loads(p2.read_bytes()),
    )
    assert any(d.code == "SCRIPT_NOT_FOUND" for d in diagnose_service(s2, current_uid=os.getuid()))


def test_diagnostics_detects_missing_log_dir_working_dir_and_disabled(tmp_path: Path) -> None:
    exe = _make_executable(tmp_path / "ok.sh")
    p1 = _write_plist(
        tmp_path / "com.test.dirs.plist",
        {
            "Label": "com.test.dirs",
            "ProgramArguments": [str(exe)],
            "WorkingDirectory": str(tmp_path / "missing-wd"),
            "StandardOutPath": str(tmp_path / "missing-logs" / "out.log"),
            "Disabled": True,
        },
    )
    s1 = ServiceInfo(
        label="com.test.dirs",
        scope=ServiceScope.USER_AGENT,
        domain_target="gui/501",
        plist_path=p1,
        last_exit_status=78,
        loaded=True,
        plist_data=plistlib.loads(p1.read_bytes()),
    )
    codes = {d.code for d in diagnose_service(s1, current_uid=os.getuid())}
    assert "MISSING_WORKING_DIR" in codes
    assert "MISSING_LOG_DIR" in codes
    assert "SERVICE_DISABLED" in codes
    assert "NON_ZERO_EXIT" in codes


def test_diagnostics_healthy_and_no_trigger(tmp_path: Path) -> None:
    exe = _make_executable(tmp_path / "ok.sh")
    p1 = _write_plist(
        tmp_path / "com.test.notrigger.plist",
        {"Label": "com.test.notrigger", "ProgramArguments": [str(exe)]},
    )
    s1 = ServiceInfo(
        label="com.test.notrigger",
        scope=ServiceScope.USER_AGENT,
        domain_target="gui/501",
        plist_path=p1,
        plist_data=plistlib.loads(p1.read_bytes()),
    )
    codes = {d.code for d in diagnose_service(s1, current_uid=os.getuid())}
    assert "NO_START_TRIGGER" in codes

    p2 = _write_plist(
        tmp_path / "com.test.healthy.plist",
        {"Label": "com.test.healthy", "ProgramArguments": [str(exe)], "RunAtLoad": True},
    )
    s2 = ServiceInfo(
        label="com.test.healthy",
        scope=ServiceScope.USER_AGENT,
        domain_target="gui/501",
        plist_path=p2,
        pid=9999,
        loaded=True,
        last_exit_status=0,
        plist_data=plistlib.loads(p2.read_bytes()),
    )
    diags = diagnose_service(s2, current_uid=os.getuid())
    assert [d.code for d in diags] == ["SERVICE_HEALTHY"]
    assert diags[0].severity == Severity.OK


def test_diagnostics_distinguishes_waiting_vs_failed_no_pid(tmp_path: Path) -> None:
    exe = _make_executable(tmp_path / "job.sh")

    # 1. Loaded, no PID, scheduled via StartCalendarInterval, 0 runs -> WAITING_FOR_FIRST_TRIGGER (INFO + OK)
    p_wait = _write_plist(
        tmp_path / "com.test.waiting.plist",
        {
            "Label": "com.test.waiting",
            "ProgramArguments": [str(exe)],
            "StartCalendarInterval": {"Hour": 3, "Minute": 0},
        },
    )
    s_wait = ServiceInfo(
        label="com.test.waiting",
        scope=ServiceScope.USER_AGENT,
        domain_target="gui/501",
        plist_path=p_wait,
        pid=None,
        last_exit_status=None,
        loaded=True,
        plist_data=plistlib.loads(p_wait.read_bytes()),
        runtime_details={"state": "not running", "runs": 0, "last exit code": "(never exited)"},
    )
    s_wait.diagnostics = diagnose_service(s_wait, current_uid=os.getuid())
    assert [d.code for d in s_wait.diagnostics] == ["WAITING_FOR_FIRST_TRIGGER", "SERVICE_HEALTHY"]
    assert s_wait.diagnostics[0].severity == Severity.INFO
    assert s_wait.state == ServiceState.LOADED

    # 2. Loaded, no PID, completed 12 clean runs -> SERVICE_HEALTHY mentioning 12 run(s)
    s_idle = ServiceInfo(
        label="com.test.waiting",
        scope=ServiceScope.USER_AGENT,
        domain_target="gui/501",
        plist_path=p_wait,
        pid=None,
        last_exit_status=0,
        loaded=True,
        plist_data=plistlib.loads(p_wait.read_bytes()),
        runtime_details={"state": "not running", "runs": 12, "last exit code": 0},
    )
    s_idle.diagnostics = diagnose_service(s_idle, current_uid=os.getuid())
    assert [d.code for d in s_idle.diagnostics] == ["SERVICE_HEALTHY"]
    assert "12 run(s)" in s_idle.diagnostics[0].detail

    # 3. Loaded, no PID, state = spawn scheduled -> SPAWN_SCHEDULED (ERROR, FAILED)
    s_sched = ServiceInfo(
        label="com.test.waiting",
        scope=ServiceScope.USER_AGENT,
        domain_target="gui/501",
        plist_path=p_wait,
        pid=None,
        last_exit_status=None,
        loaded=True,
        plist_data=plistlib.loads(p_wait.read_bytes()),
        runtime_details={"state": "spawn scheduled", "runs": 5},
    )
    s_sched.diagnostics = diagnose_service(s_sched, current_uid=os.getuid())
    assert any(d.code == "SPAWN_SCHEDULED" and d.severity == Severity.ERROR for d in s_sched.diagnostics)
    assert s_sched.state == ServiceState.FAILED

    # 4. Loaded with RunAtLoad=True, runs=0, never exited -> SPAWN_FAILED_NEVER_RAN (ERROR, FAILED)
    p_runatload = _write_plist(
        tmp_path / "com.test.neverran.plist",
        {"Label": "com.test.neverran", "ProgramArguments": [str(exe)], "RunAtLoad": True},
    )
    s_never = ServiceInfo(
        label="com.test.neverran",
        scope=ServiceScope.USER_AGENT,
        domain_target="gui/501",
        plist_path=p_runatload,
        pid=None,
        last_exit_status=None,
        loaded=True,
        plist_data=plistlib.loads(p_runatload.read_bytes()),
        runtime_details={"state": "not running", "runs": 0, "last exit code": "(never exited)"},
    )
    s_never.diagnostics = diagnose_service(s_never, current_uid=os.getuid())
    assert any(d.code == "SPAWN_FAILED_NEVER_RAN" and d.severity == Severity.ERROR for d in s_never.diagnostics)
    assert s_never.state == ServiceState.FAILED

    # 5. Conditional KeepAlive dict with runs=0 -> WAITING_FOR_FIRST_TRIGGER (not SPAWN_FAILED_NEVER_RAN)
    p_cond = _write_plist(
        tmp_path / "com.test.cond.plist",
        {
            "Label": "com.test.cond",
            "ProgramArguments": [str(exe)],
            "KeepAlive": {"SuccessfulExit": False},
        },
    )
    s_cond = ServiceInfo(
        label="com.test.cond",
        scope=ServiceScope.USER_AGENT,
        domain_target="gui/501",
        plist_path=p_cond,
        pid=None,
        last_exit_status=None,
        loaded=True,
        plist_data=plistlib.loads(p_cond.read_bytes()),
        runtime_details={"state": "not running", "runs": 0, "last exit code": "(never exited)"},
    )
    s_cond.diagnostics = diagnose_service(s_cond, current_uid=os.getuid())
    codes_cond = [d.code for d in s_cond.diagnostics]
    assert "WAITING_FOR_FIRST_TRIGGER" in codes_cond
    assert "SPAWN_FAILED_NEVER_RAN" not in codes_cond

    # 6. last terminating signal from launchctl print with last_exit_status=None -> KILLED_BY_SIGNAL (ERROR)
    s_sig = ServiceInfo(
        label="com.test.crashed",
        scope=ServiceScope.USER_AGENT,
        domain_target="gui/501",
        plist_path=p_wait,
        pid=None,
        last_exit_status=None,
        loaded=True,
        plist_data=plistlib.loads(p_wait.read_bytes()),
        runtime_details={
            "state": "not running",
            "runs": 1,
            "last terminating signal": "Segmentation fault: 11",
        },
    )
    s_sig.diagnostics = diagnose_service(s_sig, current_uid=os.getuid())
    assert any(d.code == "KILLED_BY_SIGNAL" and d.severity == Severity.ERROR for d in s_sig.diagnostics)
    assert s_sig.state == ServiceState.FAILED

    # refresh_service_diagnostics backfills runtime exit status and updates diagnostics
    s_refresh = ServiceInfo(
        label="com.test.waiting",
        scope=ServiceScope.USER_AGENT,
        domain_target="gui/501",
        plist_path=p_wait,
        pid=None,
        last_exit_status=None,
        loaded=True,
        plist_data=plistlib.loads(p_wait.read_bytes()),
    )
    sample_print = "gui/501/com.test.waiting = {\n\tstate = not running\n\truns = 4\n\tlast exit code = 78\n}\n"
    with patch("lazylaunchd.core._run_launchctl", return_value=sample_print):
        refresh_service_diagnostics(s_refresh, current_uid=os.getuid())
    assert s_refresh.last_exit_status == 78
    assert any(d.code == "NON_ZERO_EXIT" for d in s_refresh.diagnostics)


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------


def test_tail_file_and_read_service_logs(tmp_path: Path) -> None:
    log_path = tmp_path / "big.log"
    lines = [f"line {i:04d} info ok" for i in range(500)]
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    tailed, err = tail_file(log_path, max_lines=25, chunk_size=256)
    assert err is None
    assert len(tailed) == 25
    assert tailed[0] == "line 0475 info ok"
    assert tailed[-1] == "line 0499 info ok"

    svc = ServiceInfo(
        label="com.test.logs",
        scope=ServiceScope.USER_AGENT,
        domain_target="gui/501",
        plist_data={"StandardOutPath": str(log_path), "StandardErrorPath": str(log_path)},
    )
    bundle = read_service_logs(svc, max_lines=10)
    assert len(bundle.stdout_lines) == 10
    assert bundle.stderr_lines == bundle.stdout_lines


# ---------------------------------------------------------------------------
# Actions & Plist Validation
# ---------------------------------------------------------------------------


def test_lifecycle_actions_with_mock_runner(tmp_path: Path) -> None:
    plist_path = _write_plist(
        tmp_path / "com.test.svc.plist",
        {"Label": "com.test.svc", "ProgramArguments": ["/usr/bin/true"]},
    )
    svc = ServiceInfo(
        label="com.test.svc",
        scope=ServiceScope.USER_AGENT,
        domain_target="gui/501",
        plist_path=plist_path,
        loaded=False,
    )

    calls: list[list[str]] = []

    def runner_bootstrap_fallback(cmd: list[str]) -> tuple[int, str, str]:
        calls.append(cmd)
        if cmd[1] == "bootstrap":
            return 5, "", "Input/output error"
        return 0, "", ""

    res = load_service(svc, runner=runner_bootstrap_fallback)
    assert res.ok
    assert calls[0][:2] == ["launchctl", "bootstrap"]
    assert calls[1][:3] == ["launchctl", "load", "-w"]

    svc.loaded = True
    calls.clear()
    res_kick = restart_service(svc, runner=lambda c: (calls.append(c) or (0, "", "")))
    assert res_kick.ok
    assert calls[0] == ["launchctl", "kickstart", "-k", "gui/501/com.test.svc"]

    calls.clear()
    res_dis = toggle_enable_service(svc, runner=lambda c: (calls.append(c) or (0, "", "")))
    assert res_dis.ok
    assert calls[0] == ["launchctl", "disable", "gui/501/com.test.svc"]

    calls.clear()
    res_un = unload_service(svc, runner=lambda c: (calls.append(c) or (0, "", "")))
    assert res_un.ok
    assert calls[0] == ["launchctl", "bootout", "gui/501/com.test.svc"]


def test_validate_save_and_generate_plist(tmp_path: Path) -> None:
    xml_text = generate_agent_plist(
        label="com.test.gen",
        program_args=["/usr/bin/python3", "/tmp/script.py", "--flag"],
        run_at_load=True,
        keep_alive=False,
        stdout_path=str(tmp_path / "out.log"),
        start_interval=60,
    )
    ok, msg, parsed = validate_plist_content(xml_text, use_plutil=False, require_label=True)
    assert ok, msg
    assert parsed is not None
    assert parsed["Label"] == "com.test.gen"
    assert parsed["StartInterval"] == 60

    out_path = tmp_path / "com.test.gen.plist"
    save_res = save_plist_content(out_path, xml_text, use_plutil=False, require_label=True)
    assert save_res.ok
    assert out_path.exists()

    bad_res = save_plist_content(out_path, "<plist><broken>", use_plutil=False)
    assert not bad_res.ok


# ---------------------------------------------------------------------------
# CLI non-interactive modes
# ---------------------------------------------------------------------------


def test_cli_demo_list_doctor_and_json(capsys: pytest.CaptureFixture[str]) -> None:
    rc_list = cli_main(["--demo", "--list"])
    assert rc_list == 0
    out_list = capsys.readouterr().out
    assert "com.prtg.monitor" in out_list
    assert "0 OK" in out_list
    assert "127 NOT_FOUND" in out_list
    assert "78 EX_CONFIG" in out_list

    rc_doc_ok = cli_main(["--demo", "--doctor", "com.prtg.monitor"])
    assert rc_doc_ok == 0
    out_ok = capsys.readouterr().out
    assert "SERVICE_HEALTHY" in out_ok

    rc_doc_wait = cli_main(["--demo", "--doctor", "com.dev.nightly-cleanup"])
    assert rc_doc_wait == 0
    out_wait = capsys.readouterr().out
    assert "WAITING_FOR_FIRST_TRIGGER" in out_wait

    rc_doc_err = cli_main(["--demo", "--doctor", "com.company.backup-agent"])
    assert rc_doc_err == 1
    out_err = capsys.readouterr().out
    assert "MISSING_LOG_DIR" in out_err

    rc_doc_missing = cli_main(["--demo", "--doctor", "com.does.not.exist"])
    assert rc_doc_missing == 2
    capsys.readouterr()

    rc_json = cli_main(["--demo", "--json"])
    assert rc_json == 0
    payload = json.loads(capsys.readouterr().out)
    assert isinstance(payload, list)
    assert any(item["label"] == "com.prtg.monitor" for item in payload)


def test_cli_dir_scan(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exe = _make_executable(tmp_path / "run.sh")
    _write_plist(
        tmp_path / "com.custom.agent.plist",
        {"Label": "com.custom.agent", "ProgramArguments": [str(exe)], "RunAtLoad": True},
    )
    rc = cli_main(["--dir", str(tmp_path), "--filter", "com.custom.agent", "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 1
    assert data[0]["label"] == "com.custom.agent"


# ---------------------------------------------------------------------------
# Textual TUI async pilot tests
# ---------------------------------------------------------------------------


def test_tui_navigation_tabs_filters_and_actions() -> None:
    async def _run() -> None:
        app = LazyLaunchdApp(demo=True)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            table = app.query_one("#service-table", DataTable)
            assert table.row_count == len(build_demo_services())

            # Verify decoded exit codes are rendered in the table's Exit column
            exit_cells = [str(table.get_row_at(i)[3]) for i in range(table.row_count)]
            assert "0 OK" in exit_cells
            assert "127 NOT_FOUND" in exit_cells
            assert "78 EX_CONFIG" in exit_cells

            # Filtering by decoded exit reason works too
            await pilot.press("/")
            await pilot.press("E", "X", "_", "C", "O", "N", "F", "I", "G")
            await pilot.pause()
            assert table.row_count == 1
            await pilot.press("escape")
            await pilot.pause()
            assert table.row_count == len(build_demo_services())

            # Navigate down and switch tabs
            await pilot.press("j")
            await pilot.press("2")
            await pilot.pause()
            assert app.active_tab == "logs"

            await pilot.press("3")
            await pilot.pause()
            assert app.active_tab == "plist"

            await pilot.press("4")
            await pilot.pause()
            assert app.active_tab == "runtime"

            await pilot.press("1")
            await pilot.pause()
            assert app.active_tab == "diagnostics"

            # Cycle domain filter
            await pilot.press("d")
            await pilot.pause()
            assert "User Agents" in str(app.query_one("#scope-pill", Static).content)

            # Reset back to All via cycling
            for _ in range(5):
                await pilot.press("d")
            await pilot.pause()
            assert table.row_count == len(build_demo_services())

            # Live search via '/'
            await pilot.press("/")
            search = app.query_one("#search-input", Input)
            assert search.has_focus
            await pilot.press("p", "r", "t", "g")
            await pilot.pause()
            assert table.row_count == 1

            # Escape clears filter and returns focus to table
            await pilot.press("escape")
            await pilot.pause()
            assert table.has_focus
            assert table.row_count == len(build_demo_services())

            # Demo lifecycle action (start/kickstart)
            await pilot.press("j")
            await pilot.press("s")
            await pilot.pause()
            status_text = str(app.query_one("#status-line", Static).content)
            assert "Kickstarted" in status_text or "Demo" in status_text

            # Help modal
            await pilot.press("?")
            await pilot.pause()
            assert isinstance(app.screen, HelpModal)
            await pilot.press("escape")
            await pilot.pause()
            assert not isinstance(app.screen, HelpModal)

    asyncio.run(_run())


def test_tui_editor_and_new_agent_modals(tmp_path: Path) -> None:
    async def _run() -> None:
        app = LazyLaunchdApp(demo=True, extra_dirs=[(tmp_path, ServiceScope.USER_AGENT)])
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()

            # Open Plist Editor modal on first service
            await pilot.press("E")
            await pilot.pause()
            assert isinstance(app.screen, PlistEditorModal)
            await pilot.press("ctrl+t")
            await pilot.pause()
            await pilot.press("ctrl+s")
            await pilot.pause()
            assert not isinstance(app.screen, PlistEditorModal)

            # Open New Agent modal and create a service in demo mode
            await pilot.press("n")
            await pilot.pause()
            assert isinstance(app.screen, NewAgentModal)
            app.screen.query_one("#new-label", Input).value = "com.demo.created"
            app.screen.query_one("#new-command", Input).value = "/usr/bin/true"
            await pilot.click("#btn-create")
            await pilot.pause()
            assert not isinstance(app.screen, NewAgentModal)
            assert any(s.label == "com.demo.created" for s in app.all_services)

    asyncio.run(_run())
