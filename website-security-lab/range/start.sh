#!/usr/bin/env sh
set -eu

if [ -z "${LAB_CONTROL_TOKEN:-}" ]; then
  LAB_CONTROL_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
  export LAB_CONTROL_TOKEN
fi

CONTROL_ARGS=""
if [ "${LAB_NO_CONTROL:-0}" = "1" ]; then
  CONTROL_ARGS="--no-control"
fi

exec python3 "$(dirname "$0")/server.py" \
  --host "${LAB_HOST:-0.0.0.0}" \
  --port "${LAB_PORT:-8080}" \
  --initial-state "${LAB_INITIAL_STATE:-clean}" \
  $CONTROL_ARGS
