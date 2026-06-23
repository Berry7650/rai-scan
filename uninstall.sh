#!/bin/sh
set -eu
umask 077

if [ "$(id -u)" -eq 0 ]; then
    echo "Refusing to uninstall rai-scan while running as root." >&2
    exit 1
fi

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VENV_DIR="$PROJECT_DIR/.venv"
LAUNCHER="${HOME}/.local/bin/rai-scan"
STATE_DIR="${RAI_SCAN_HOME:-${HOME}/.rai-scan}"
PURGE_STATE=0
DRY_RUN=0

canonicalize() {
    python3 -c 'import os, sys; print(os.path.realpath(os.path.expanduser(sys.argv[1])))' "$1"
}

usage() {
    echo "Usage: ./uninstall.sh [--purge-state] [--dry-run]"
    echo
    echo "  --purge-state  Also permanently delete scan cache, trash, and rollback history"
    echo "  --dry-run      Show what would be removed without changing anything"
}

for argument in "$@"; do
    case "$argument" in
        --purge-state) PURGE_STATE=1 ;;
        --dry-run) DRY_RUN=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $argument" >&2; usage >&2; exit 2 ;;
    esac
done

CANON_STATE=""
if [ "$PURGE_STATE" -eq 1 ]; then
    CANON_STATE=$(canonicalize "$STATE_DIR")
    CANON_HOME=$(canonicalize "$HOME")
    CANON_PROJECT=$(canonicalize "$PROJECT_DIR")
    case "$CANON_STATE" in
        ""|"/"|"$CANON_HOME"|"$CANON_PROJECT")
            echo "Refusing unsafe state directory: $STATE_DIR" >&2
            exit 1
            ;;
    esac
    case "$CANON_HOME/" in
        "$CANON_STATE"/*)
            echo "Refusing state directory that contains the home directory: $STATE_DIR" >&2
            exit 1
            ;;
    esac
    case "$CANON_PROJECT/" in
        "$CANON_STATE"/*)
            echo "Refusing state directory that contains the project: $STATE_DIR" >&2
            exit 1
            ;;
    esac
    if [ -L "$STATE_DIR" ]; then
        echo "Refusing symlinked state directory: $STATE_DIR" >&2
        exit 1
    fi
fi

remove_path() {
    path=$1
    label=$2
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        echo "Not found: $label ($path)"
        return
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "Would remove: $label ($path)"
    else
        rm -rf -- "$path"
        echo "Removed: $label ($path)"
    fi
}

echo "rai-scan uninstall"
echo "Project source will be kept: $PROJECT_DIR"
echo

if [ -e "$LAUNCHER" ]; then
    if [ ! -L "$LAUNCHER" ] &&
       head -1 "$LAUNCHER" | grep -q "^#!/bin/sh" &&
       grep -Fqx "PROJECT_DIR=\"$PROJECT_DIR\"" "$LAUNCHER" 2>/dev/null &&
       grep -Fq 'exec "$VENV_DIR/bin/python" -m rai_scan "$@"' "$LAUNCHER" 2>/dev/null; then
        remove_path "$LAUNCHER" "command launcher"
    else
        echo "Kept launcher because it was not created by this project: $LAUNCHER"
    fi
else
    echo "Not found: command launcher ($LAUNCHER)"
fi

remove_path "$VENV_DIR" "private Python environment"

if [ "$PURGE_STATE" -eq 1 ]; then
    remove_path "$CANON_STATE" "state, rollback history, and recoverable trash"
else
    echo "Kept user data: $STATE_DIR"
    echo "Use --purge-state only if you also want to permanently delete trash and history."
fi

echo
if [ "$DRY_RUN" -eq 1 ]; then
    echo "Dry run complete. Nothing was changed."
else
    echo "rai-scan command uninstalled."
fi
echo "To delete the source code later: rm -rf \"$PROJECT_DIR\""
