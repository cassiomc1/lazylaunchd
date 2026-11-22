"""Command-line entry point for lazylaunchd."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from lazylaunchd import __version__
from lazylaunchd.core import build_demo_services, discover_services
from lazylaunchd.models import ServiceInfo, ServiceScope, ServiceState, Severity


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser for lazylaunchd."""
    parser = argparse.ArgumentParser(
        prog="lazylaunchd",
        description="lazygit-style TUI and diagnostic CLI for macOS LaunchAgents and LaunchDaemons.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Print services table non-interactively and exit.",
    )
    parser.add_argument(
        "--doctor",
        nargs="?",
        const="",
        default=None,
        metavar="LABEL",
        help="Run 'Why isn't it running?' diagnostics (for all services or a specific LABEL).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON (use with --list, --doctor, or standalone).",
    )
    parser.add_argument(
        "--dir",
        action="append",
        default=[],
        metavar="PATH",
        help="Additional directory containing .plist files to inspect (repeatable).",
    )
    parser.add_argument(
        "--include-apple",
        action="store_true",
        help="Include Apple /System/Library services and com.apple.* runtime jobs.",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Use realistic built-in demo services (great for testing or recordings).",
    )
    parser.add_argument(
        "-f",
        "--filter",
        default="",
        metavar="QUERY",
        help="Filter services by label, path, or executable substring.",
    )
    return parser


def _filter_services(services: list[ServiceInfo], query: str) -> list[ServiceInfo]:
    if not query:
        return services
    q = query.lower()
    return [
        s
        for s in services
        if q in s.label.lower()
        or q in str(s.plist_path or "").lower()
        or q in " ".join(s.program_command).lower()
    ]


def _render_list(services: list[ServiceInfo], console: Console) -> None:
    table = Table(
        title="launchd Services",
        header_style="bold cyan",
        box=box.SIMPLE_HEAD,
        padding=(0, 1),
        expand=True,
    )
    table.add_column("State", no_wrap=True)
    table.add_column("Scope", no_wrap=True)
    table.add_column("PID", justify="right", no_wrap=True)
    table.add_column("Exit", justify="right", no_wrap=True)
    table.add_column("Label", overflow="fold")
    table.add_column("Issues", justify="right", no_wrap=True)

    state_styles = {
        ServiceState.RUNNING: "bold green",
        ServiceState.LOADED: "cyan",
        ServiceState.FAILED: "bold red",
        ServiceState.DISABLED: "yellow",
        ServiceState.UNLOADED: "dim",
        ServiceState.INVALID: "bold magenta",
    }

    for svc in services:
        pid_str = str(svc.pid) if svc.pid else "-"
        exit_str = str(svc.last_exit_status) if svc.last_exit_status is not None else "-"
        errs = svc.error_count
        warns = svc.warning_count
        if errs:
            issue_text = Text(f"{errs}E", style="bold red")
            if warns:
                issue_text.append(f" {warns}W", style="yellow")
        elif warns:
            issue_text = Text(f"{warns}W", style="yellow")
        else:
            issue_text = Text("OK", style="green")

        table.add_row(
            Text(svc.status_badge, style=state_styles[svc.state]),
            svc.scope.label,
            pid_str,
            exit_str,
            svc.label,
            issue_text,
        )

    console.print(table)


def _select_doctor_targets(services: list[ServiceInfo], label_arg: str) -> list[ServiceInfo]:
    if label_arg:
        exact = [s for s in services if s.label == label_arg]
        if exact:
            return exact
        q = label_arg.lower()
        return [s for s in services if q in s.label.lower()]

    flagged = [
        s
        for s in services
        if any(d.severity in (Severity.ERROR, Severity.WARNING) for d in s.diagnostics)
    ]
    return flagged if flagged else services


def _render_doctor(
    targets: list[ServiceInfo],
    *,
    explicit_label: bool,
    console: Console,
) -> int:
    if not targets:
        console.print("[red]No matching service found.[/red]")
        return 2

    any_errors = False
    for svc in targets:
        errs = svc.error_count
        if errs > 0:
            any_errors = True
        if not explicit_label and errs == 0 and svc.warning_count == 0:
            continue

        lines: list[Text] = []
        lines.append(
            Text.assemble(
                ("Domain: ", "dim"),
                (svc.domain_target, "white"),
                ("  Scope: ", "dim"),
                (svc.scope.label, "cyan"),
                ("  PID: ", "dim"),
                (str(svc.pid) if svc.pid else "-", "white"),
                ("  Exit: ", "dim"),
                (svc.exit_summary, "yellow" if svc.last_exit_status else "green"),
            )
        )
        if svc.plist_path:
            lines.append(Text.assemble(("Plist:  ", "dim"), (str(svc.plist_path), "white")))

        for diag in svc.diagnostics:
            sev_style = {
                Severity.ERROR: "bold red",
                Severity.WARNING: "bold yellow",
                Severity.INFO: "cyan",
                Severity.OK: "bold green",
            }[diag.severity]
            lines.append(Text(""))
            lines.append(Text(f"[{diag.severity.value.upper()}] {diag.title} ({diag.code})", style=sev_style))
            lines.append(Text(f"  {diag.detail}", style="white"))
            if diag.fix_hint:
                lines.append(Text(f"  Fix: {diag.fix_hint}", style="green"))

        from rich.console import Group

        border = "red" if errs else ("yellow" if svc.warning_count else "green")
        console.print(
            Panel(
                Group(*lines),
                title=f"[bold]{svc.label}[/bold] ({svc.status_badge})",
                border_style=border,
            )
        )

    if not explicit_label and not any_errors and all(s.warning_count == 0 for s in targets):
        console.print(f"[bold green]✔ All {len(targets)} services passed health checks.[/bold green]")

    return 1 if any_errors else 0


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point for `lazylaunchd`."""
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    extra_dirs = [
        (Path(p).expanduser(), ServiceScope.USER_AGENT)
        for p in args.dir
    ]

    if args.list or args.doctor is not None or args.json:
        if args.demo:
            services = build_demo_services()
        else:
            services = discover_services(
                include_apple=args.include_apple,
                extra_dirs=extra_dirs or None,
            )
        services = _filter_services(services, args.filter)

        if args.doctor is not None:
            targets = _select_doctor_targets(services, args.doctor)
            if args.json:
                if args.doctor and not targets:
                    print(json.dumps({"error": f"No service matching '{args.doctor}'"}, indent=2))
                    return 2
                payload = [s.to_dict() for s in targets]
                print(json.dumps(payload, indent=2))
                return 1 if any(s.error_count > 0 for s in targets) else 0
            console = Console()
            return _render_doctor(
                targets,
                explicit_label=bool(args.doctor),
                console=console,
            )

        if args.json:
            print(json.dumps([s.to_dict() for s in services], indent=2))
            return 0

        _render_list(services, Console())
        return 0

    from lazylaunchd.tui import LazyLaunchdApp

    app = LazyLaunchdApp(
        demo=args.demo,
        include_apple=args.include_apple,
        extra_dirs=extra_dirs or None,
        initial_query=args.filter,
    )
    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
