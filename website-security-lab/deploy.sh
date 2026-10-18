#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Python 3.10+ is required." >&2
  exit 1
fi

"$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' || {
  echo "Python 3.10+ is required. Current version: $("$PYTHON_BIN" --version 2>&1)" >&2
  exit 1
}

if [ "${SKIP_TESTS:-0}" != "1" ]; then
  echo "Running inspector regression tests..."
  (cd "$ROOT_DIR/framework" && "$PYTHON_BIN" -B -m unittest discover -s tests)
  echo "Running range regression tests..."
  "$PYTHON_BIN" -B -m unittest discover -s "$ROOT_DIR/range/tests"
fi

if [ "${VERIFY_ONLY:-0}" = "1" ]; then
  echo "Verification passed. Nothing was started."
  exit 0
fi

if [ -z "${LAB_CONTROL_TOKEN:-}" ]; then
  LAB_CONTROL_TOKEN="$("$PYTHON_BIN" -c 'import secrets; print(secrets.token_urlsafe(18))')"
  export LAB_CONTROL_TOKEN
fi

LAB_HOST="${LAB_HOST:-0.0.0.0}"
LAB_PORT="${LAB_PORT:-8080}"
LAB_INITIAL_STATE="${LAB_INITIAL_STATE:-clean}"
LAB_NO_CONTROL="${LAB_NO_CONTROL:-0}"

export LAB_HOST LAB_PORT LAB_INITIAL_STATE LAB_NO_CONTROL
exec "$ROOT_DIR/range/start.sh"
