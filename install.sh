#!/bin/sh
set -eu
umask 077

if [ "$(id -u)" -eq 0 ]; then
    echo "Refusing to install rai-scan while running as root." >&2
    exit 1
fi

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VENV_DIR="$PROJECT_DIR/.venv"
USER_BIN="${HOME}/.local/bin"
LAUNCHER="${USER_BIN}/rai-scan"

if [ -e "$LAUNCHER" ] || [ -L "$LAUNCHER" ]; then
    if [ -L "$LAUNCHER" ] ||
       ! head -1 "$LAUNCHER" | grep -q "^#!/bin/sh" ||
       ! grep -Fqx "PROJECT_DIR=\"$PROJECT_DIR\"" "$LAUNCHER" 2>/dev/null ||
       ! grep -Fq 'exec "$VENV_DIR/bin/python" -m rai_scan "$@"' "$LAUNCHER" 2>/dev/null; then
        echo "Refusing to overwrite an unrelated launcher: $LAUNCHER" >&2
        exit 1
    fi
fi

echo "Installing rai-scan from: $PROJECT_DIR"
echo "Creating an isolated Python environment..."

if python3 -m venv --clear "$VENV_DIR" 2>/dev/null &&
   "$VENV_DIR/bin/python" -m pip install -e "$PROJECT_DIR"; then
    :
else
    echo "Isolated installation was unavailable; using system-site build tools."
    echo "The rai-scan runtime still has no third-party dependencies."
    python3 -m venv --clear --system-site-packages "$VENV_DIR"
    "$VENV_DIR/bin/python" -m pip install --no-build-isolation -e "$PROJECT_DIR"
fi
mkdir -p "$USER_BIN"

cat > "$LAUNCHER" << 'WRAPPER'
#!/bin/sh
PROJECT_DIR="__PROJECT_DIR__"
VENV_DIR="$PROJECT_DIR/.venv"
exec "$VENV_DIR/bin/python" -m rai_scan "$@"
WRAPPER
chmod +x "$LAUNCHER"
sed -i "s|__PROJECT_DIR__|${PROJECT_DIR}|g" "$LAUNCHER"

echo
echo "Installation complete."
echo "Command: $LAUNCHER"
echo

case ":${PATH}:" in
    *":${USER_BIN}:"*) ;;
    *)
        echo "Add this line to your shell configuration:"
        echo "export PATH=\"\$HOME/.local/bin:\$PATH\""
        ;;
esac

echo "Start the guided menu with:"
echo "rai-scan"
