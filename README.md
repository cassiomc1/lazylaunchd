# lazylaunchd

**A `lazygit`-style Terminal UI and diagnostic CLI for macOS `LaunchAgents` and `LaunchDaemons`.**

Inspect service status, PIDs, decoded exit codes, stdout/stderr/Unified Logs, syntax-highlighted plists, and root-cause answers to *"Why isn't my service starting?"* — without leaving your terminal or paying for GUI utilities.

---

## Why `lazylaunchd`?

macOS `launchd` is powerful, yet day-to-day debugging usually means bouncing between `launchctl list`, `launchctl print gui/$(id -u)/...`, `plutil -lint`, tailing multiple log paths, and guessing why an agent exited with `78` or `127`.

`lazylaunchd` brings a keyboard-first split-pane workflow inspired by `lazygit`:

- **Live service list** across `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons`, and optionally `/System/Library/*`.
- **Instant root-cause diagnostics (`1:Why / Diagnostics`)**: detects malformed XML, missing `Label`, group/world-writable plist permissions (`0666`), wrong ownership on `LaunchDaemons` (`root:wheel`), missing log parent directories (classic exit `78`), missing executables or non-executable scripts, bad `#!` shebangs, shell `~`/`$VAR` expansion mistakes, and commands missing from `launchd`'s minimal `PATH` (such as `/opt/homebrew/bin` binaries).
- **Decoded exit codes & signals**: turns opaque numbers like `78`, `127`, `-9`, and `-15` into actionable explanations.
- **Unified Log + file log viewer (`2:Logs`)**: tails `StandardOutPath` and `StandardErrorPath` in bounded memory and queries macOS Unified Logging (`log show --last 15m`) with `[L]`.
- **Built-in XML Plist Editor (`E`) & `$EDITOR` support (`Ctrl+E`)**: validates with `plistlib` and `plutil -lint` before atomic save, with one-key save-and-reload (`Ctrl+R`).
- **New User LaunchAgent wizard (`n`)**: generates a clean `.plist`, creates log directories automatically, validates XML, and loads it.
- **Non-interactive CLI modes**: `--list`, `--doctor [LABEL]`, `--json`, and `--demo`.

---

## Quick Comparison

| Feature | `lazylaunchd` | `launchctl` (built-in) | LaunchControl / Lingon |
|---|---|---|---|
| Interface | Keyboard-first TUI + CLI | Raw CLI subcommands | Paid macOS GUI apps |
| Price & License | Free & Open Source (MIT) | Built into macOS | Paid license |
| "Why isn't it running?" doctor | Automatic checks + fix hints | Manual `print` + `error` | Built-in |
| Stdout / Stderr / Unified Logs | Built-in pane | Manual `tail` / `log show` | Built-in |
| Built-in XML editor + `plutil` validation | Yes (`E` / `Ctrl+E`) | Manual editor | Built-in |
| SSH / headless friendly | Yes | Yes | No |

---

## Installation

### macOS App Bundle (`.app` + `lazylaunchd` CLI)

```bash
git clone https://github.com/cassiomc1/lazylaunchd.git
cd lazylaunchd
./build_app.sh          # Installs /Applications/LazyLaunchd.app and ~/.local/bin/lazylaunchd
./build_app.sh --user   # Or install into ~/Applications/LazyLaunchd.app
```

### With `uv` or `pip`

```bash
git clone https://github.com/cassiomc1/lazylaunchd.git
cd lazylaunchd
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Run directly:

```bash
lazylaunchd
```

Or try the built-in zero-setup showcase dataset:

```bash
lazylaunchd --demo
```

---

## CLI Usage

```text
lazylaunchd [options]

Options:
  --list            Print services table non-interactively and exit
  --doctor [LABEL]  Run 'Why isn't it running?' diagnostics (all flagged services or a specific label)
  --json            Output machine-readable JSON
  --dir PATH        Additional directory containing .plist files to inspect (repeatable)
  --include-apple   Include Apple /System/Library services and com.apple.* runtime jobs
  --demo            Use realistic built-in demo services
  -f, --filter Q    Pre-filter services by label, path, or executable substring
  --version         Show version and exit
```

### Examples

```bash
# Launch interactive TUI
lazylaunchd

# List all non-Apple services with PID, exit status, and issue counts
lazylaunchd --list

# Diagnose a specific LaunchAgent (exits 1 if errors exist, 0 if healthy)
lazylaunchd --doctor com.prtg.monitor

# Export full service inventory + diagnostics as JSON
lazylaunchd --json
```

---

## Keyboard Shortcuts (TUI)

| Key | Action |
|---|---|
| `j` / `k` / `↑` / `↓` | Move selection up / down |
| `/` or `f` | Focus live search filter (`Esc` clears/returns to list) |
| `1` `2` `3` `4` / `Tab` | Switch inspector: Diagnostics, Logs, Plist XML, Runtime |
| `d` | Cycle filter: All → User Agents → Global Agents → Global Daemons → Failed → Running |
| `a` | Toggle Apple `/System/Library` services |
| `s` | Start / Kickstart service (`launchctl kickstart -k`) |
| `l` / `u` | Load (`bootstrap`) / Unload (`bootout`) service |
| `e` | Toggle Enable / Disable (`launchctl enable` / `disable`) |
| `E` | Open built-in XML Plist Editor (with `plutil` / `plistlib` validation) |
| `Ctrl+E` | Open plist in external `$EDITOR` |
| `n` | Open New User LaunchAgent wizard |
| `L` | Toggle macOS Unified Logs (`log show --last 15m`) |
| `y` | Copy recommended fix command or plist path to macOS clipboard (`pbcopy`) |
| `r` | Refresh services and live `launchctl` state |
| `?` | Open shortcut & exit-code help modal |
| `q` | Quit |

---

## Common `launchd` Failure Patterns Detected Automatically

- **Exit `78` (`EX_CONFIG`)**: `StandardOutPath`, `StandardErrorPath`, or `WorkingDirectory` references a non-existent folder (`launchd` will not `mkdir -p` log directories for you).
- **Exit `127` / Homebrew `PATH` mismatch**: `launchd` starts with `/usr/bin:/bin:/usr/sbin:/sbin` and ignores `~/.zshrc`. Bare commands like `uvicorn`, `node`, or `#!/usr/bin/env <tool>` fail unless given an absolute path or `EnvironmentVariables.PATH`.
- **Plist permissions / ownership**: `launchd` silently refuses plists writable by group/others (`chmod 644` required) or `/Library/LaunchDaemons` files not owned by `root:wheel`.
- **Unexpanded shell syntax**: `~` or `$HOME` in `ProgramArguments`, `WorkingDirectory`, or log paths.
- **Disabled overrides**: services disabled in `launchd`'s override database (`launchctl print-disabled`) even when the `.plist` itself has no `Disabled` key.

---

## Development & Tests

```bash
pytest
ruff check .
```

## License

MIT — see [LICENSE](LICENSE).
