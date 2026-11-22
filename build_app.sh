#!/usr/bin/env bash
# ==============================================================================
# lazylaunchd — package and install the macOS application bundle.
# Creates LazyLaunchd.app and the ~/.local/bin/lazylaunchd terminal command.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_NAME="LazyLaunchd"
DEFAULT_TARGET="/Applications/${APP_NAME}.app"
USER_TARGET="$HOME/Applications/${APP_NAME}.app"
TARGET_APP="$DEFAULT_TARGET"
INSTALL_CLI=true

usage() {
    cat <<EOF
Usage: $0 [options]

Options:
  --system           Install to /Applications (default)
  --user             Install to ~/Applications
  --target PATH      Custom destination for the .app bundle
  --no-cli           Do not install the 'lazylaunchd' terminal command
  -h, --help         Show this help
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --system)
            TARGET_APP="$DEFAULT_TARGET"
            shift
            ;;
        --user)
            TARGET_APP="$USER_TARGET"
            shift
            ;;
        --target)
            [[ -n "${2:-}" ]] || { echo "Error: --target requires a path"; exit 1; }
            TARGET_APP="$2"
            shift 2
            ;;
        --no-cli)
            INSTALL_CLI=false
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

echo "Packaging LazyLaunchd..."
echo "App destination: $TARGET_APP"

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "Error: build_app.sh packages a macOS application and requires macOS."
    exit 1
fi

if [[ ! -f "$SCRIPT_DIR/lazylaunchd.py" || ! -d "$SCRIPT_DIR/lazylaunchd" ]]; then
    echo "Error: lazylaunchd.py or lazylaunchd/ was not found next to build_app.sh."
    exit 1
fi

APP_VERSION="$(sed -n 's/^__version__ = "\([^"]*\)"/\1/p' "$SCRIPT_DIR/lazylaunchd/__init__.py" | head -n 1)"
APP_VERSION="${APP_VERSION:-0.1.0}"
echo "Version: $APP_VERSION"

TARGET_PARENT="$(dirname "$TARGET_APP")"
if [[ ! -d "$TARGET_PARENT" ]]; then
    mkdir -p "$TARGET_PARENT" 2>/dev/null || true
fi
if [[ ! -w "$TARGET_PARENT" ]]; then
    echo "Error: cannot write to $TARGET_PARENT"
    echo "Try: $0 --user"
    exit 1
fi
TARGET_APP="$(cd "$TARGET_PARENT" && pwd)/$(basename "$TARGET_APP")"

# 1. Generate the .icns icon if missing
ICON_PATH="$SCRIPT_DIR/assets/AppIcon.icns"
if [[ ! -f "$ICON_PATH" ]]; then
    echo "Generating AppIcon.icns..."
    ICON_PY="$SCRIPT_DIR/.venv/bin/python"
    if [[ ! -x "$ICON_PY" ]]; then
        ICON_PY="$(command -v python3 || true)"
    fi
    if [[ -z "$ICON_PY" ]] || ! "$ICON_PY" -c "import PIL" >/dev/null 2>&1; then
        echo "Error: Pillow is required to generate the icon."
        echo "Run: python3 -m pip install pillow"
        exit 1
    fi
    "$ICON_PY" "$SCRIPT_DIR/scripts/generate_icon.py" "$ICON_PATH"
fi

# 2. Create the .app bundle directories
CONTENTS_DIR="$TARGET_APP/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
RESOURCES_DIR="$CONTENTS_DIR/Resources"

if [[ -d "$CONTENTS_DIR" ]]; then
    if grep -q "<string>com.cassio.lazylaunchd</string>" "$CONTENTS_DIR/Info.plist" 2>/dev/null; then
        echo "Replacing the existing LazyLaunchd bundle..."
        rm -rf "$CONTENTS_DIR"
    else
        echo "Error: $TARGET_APP exists and is not a LazyLaunchd bundle."
        exit 1
    fi
fi

echo "Creating bundle directories..."
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"

# 3. Write Info.plist
echo "Writing Info.plist..."
cat << EOF > "$CONTENTS_DIR/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>LazyLaunchd</string>
    <key>CFBundleDisplayName</key>
    <string>LazyLaunchd</string>
    <key>CFBundleIdentifier</key>
    <string>com.cassio.lazylaunchd</string>
    <key>CFBundleVersion</key>
    <string>${APP_VERSION}</string>
    <key>CFBundleShortVersionString</key>
    <string>${APP_VERSION}</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleSignature</key>
    <string>????</string>
    <key>CFBundleExecutable</key>
    <string>LazyLaunchd</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.15</string>
    <key>LSApplicationCategoryType</key>
    <string>public.app-category.utilities</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
EOF

if command -v plutil >/dev/null 2>&1; then
    plutil -lint "$CONTENTS_DIR/Info.plist" >/dev/null
fi

echo -n "APPL????" > "$CONTENTS_DIR/PkgInfo"

# 4. Copy icon and application source
echo "Copying resources..."
cp "$ICON_PATH" "$RESOURCES_DIR/AppIcon.icns"
cp "$SCRIPT_DIR/lazylaunchd.py" "$RESOURCES_DIR/lazylaunchd.py"
mkdir -p "$RESOURCES_DIR/lazylaunchd"
cp "$SCRIPT_DIR/lazylaunchd/"*.py "$RESOURCES_DIR/lazylaunchd/"
cat << 'EOF' > "$RESOURCES_DIR/requirements.txt"
textual>=0.82.0
rich>=13.0.0
EOF

# 5. Terminal launcher (Contents/Resources/lazylaunchd.command)
REPO_VENV_PY_Q="$(printf '%q' "$SCRIPT_DIR/.venv/bin/python3")"
cat << EOF > "$RESOURCES_DIR/lazylaunchd.command"
#!/usr/bin/env bash
# LazyLaunchd Terminal Runner

printf "\033]0;%s\007" "LazyLaunchd"

if [ \$# -eq 0 ]; then
    cd "\$HOME" || exit 1
fi

APP_DIR="\$(cd "\$(dirname "\$0")" && pwd)"
TARGET_PY="\$APP_DIR/lazylaunchd.py"
VENV_DIR="\$HOME/Library/Application Support/LazyLaunchd/venv"
REPO_VENV_PY=${REPO_VENV_PY_Q}

find_python() {
    local candidates=(
        "\$VENV_DIR/bin/python3"
        "\$REPO_VENV_PY"
    )
    while IFS= read -r p; do
        candidates+=("\$p")
    done < <(ls -1r /Library/Frameworks/Python.framework/Versions/*/bin/python3 2>/dev/null || true)

    candidates+=(
        "\$(command -v python3 2>/dev/null || true)"
        "/opt/homebrew/bin/python3"
        "/usr/local/bin/python3"
        "/usr/bin/python3"
    )

    for p in "\${candidates[@]}"; do
        if [ -n "\$p" ] && [ -x "\$p" ]; then
            if "\$p" -c "import textual, rich" >/dev/null 2>&1; then
                echo "\$p"
                return 0
            fi
        fi
    done
    return 1
}

PY_EXEC="\$(find_python || true)"

if [ -z "\$PY_EXEC" ]; then
    echo "Python with 'textual' and 'rich' was not found."
    echo "Installing dependencies in \$VENV_DIR..."
    BASE_PY="\$(command -v python3 || true)"
    if [ -n "\$BASE_PY" ]; then
        mkdir -p "\$(dirname "\$VENV_DIR")"
        "\$BASE_PY" -m venv "\$VENV_DIR"
        "\$VENV_DIR/bin/pip" install --upgrade pip
        "\$VENV_DIR/bin/pip" install -r "\$APP_DIR/requirements.txt"
        PY_EXEC="\$VENV_DIR/bin/python3"
    else
        echo "Install Python 3, then run: pip3 install textual rich"
        read -r -p "Press Enter to close..."
        exit 1
    fi
fi

PYTHONPATH="\$APP_DIR\${PYTHONPATH:+:\$PYTHONPATH}" "\$PY_EXEC" "\$TARGET_PY" "\$@"
EOF
chmod +x "$RESOURCES_DIR/lazylaunchd.command"

# 6. Bundle executable (Contents/MacOS/LazyLaunchd)
cat << 'EOF' > "$MACOS_DIR/LazyLaunchd"
#!/usr/bin/env bash
# LazyLaunchd macOS App Entrypoint

DIR="$(cd "$(dirname "$0")/.." && pwd)"
RESOURCES="$DIR/Resources"

open -a Terminal "$RESOURCES/lazylaunchd.command"
EOF
chmod +x "$MACOS_DIR/LazyLaunchd"

# 7. Register the app with Launch Services
touch "$TARGET_APP"
if [[ -x "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister" ]]; then
    /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$TARGET_APP" 2>/dev/null || true
fi

echo "App installed at: $TARGET_APP"

# 8. Install the lazylaunchd terminal command
if [[ "$INSTALL_CLI" == true ]]; then
    CLI_BIN_DIR="$HOME/.local/bin"
    mkdir -p "$CLI_BIN_DIR"
    CLI_PATH="$CLI_BIN_DIR/lazylaunchd"
    APP_RES_Q="$(printf '%q' "$RESOURCES_DIR")"
    FALLBACK_DIR_Q="$(printf '%q' "$SCRIPT_DIR")"

    cat << EOF > "$CLI_PATH"
#!/usr/bin/env bash
# LazyLaunchd CLI Wrapper

APP_DIR=${APP_RES_Q}
if [[ ! -f "\$APP_DIR/lazylaunchd.py" ]]; then
    APP_DIR=${FALLBACK_DIR_Q}
fi

PY_EXEC=""
while IFS= read -r p; do
    if [[ -n "\$p" && -x "\$p" ]] && "\$p" -c "import textual, rich" >/dev/null 2>&1; then
        PY_EXEC="\$p"
        break
    fi
done < <(
    printf "%s\n" "\$HOME/Library/Application Support/LazyLaunchd/venv/bin/python3"
    printf "%s\n" ${REPO_VENV_PY_Q}
    ls -1r /Library/Frameworks/Python.framework/Versions/*/bin/python3 2>/dev/null || true
    command -v python3 2>/dev/null || true
    printf "%s\n" "/opt/homebrew/bin/python3" "/usr/local/bin/python3" "/usr/bin/python3"
)

if [[ -z "\$PY_EXEC" ]]; then
    PY_EXEC="python3"
fi

export PYTHONPATH="\$APP_DIR\${PYTHONPATH:+:\$PYTHONPATH}"
exec "\$PY_EXEC" "\$APP_DIR/lazylaunchd.py" "\$@"
EOF
    chmod +x "$CLI_PATH"
    echo "Terminal command installed at: $CLI_PATH"
fi

echo ""
echo "Done. LazyLaunchd $APP_VERSION is installed."
echo "   - App: $TARGET_APP (also available in Spotlight / Launchpad)"
echo "   - Terminal: run 'lazylaunchd' from any folder"
echo ""
