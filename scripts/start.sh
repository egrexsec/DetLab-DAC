#!/bin/bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RUN_DIR="$ROOT_DIR/.detlab-run"
API_PID_FILE="$RUN_DIR/api.pid"
WEB_PID_FILE="$RUN_DIR/web.pid"
API_LOG="$RUN_DIR/api.log"
WEB_LOG="$RUN_DIR/web.log"

mkdir -p "$RUN_DIR"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

is_running() {
  local pid_file="$1"
  if [[ -f "$pid_file" ]]; then
    local pid
    pid=$(cat "$pid_file")
    if kill -0 "$pid" >/dev/null 2>&1; then
      return 0
    fi
    rm -f "$pid_file"
  fi
  return 1
}

wait_for_http() {
  local name="$1"
  local pid_file="$2"
  local url="$3"
  local log_file="$4"

  for _ in {1..60}; do
    if curl -fsS "$url" >/dev/null 2>&1; then
      echo "$name is ready at $url"
      return 0
    fi

    if [[ -f "$pid_file" ]]; then
      local pid
      pid=$(cat "$pid_file")
      if ! kill -0 "$pid" >/dev/null 2>&1; then
        echo "$name failed to stay running. Last log lines:" >&2
        tail -n 20 "$log_file" >&2 || true
        exit 1
      fi
    fi

    sleep 1
  done

  echo "Timed out waiting for $name at $url. Last log lines:" >&2
  tail -n 20 "$log_file" >&2 || true
  exit 1
}

require_command uv
require_command npm
require_command curl

cd "$ROOT_DIR"
uv sync --all-extras >/dev/null

if [[ ! -d "$ROOT_DIR/web/node_modules" ]]; then
  (cd "$ROOT_DIR/web" && npm install >/dev/null)
fi

if is_running "$API_PID_FILE"; then
  echo "API already running with PID $(cat "$API_PID_FILE")"
else
  nohup uv run uvicorn detlab.api:app --host 127.0.0.1 --port 8000 >"$API_LOG" 2>&1 &
  echo $! >"$API_PID_FILE"
  echo "Started API on http://127.0.0.1:8000 (PID $(cat "$API_PID_FILE"))"
fi

wait_for_http "API" "$API_PID_FILE" "http://127.0.0.1:8000/health" "$API_LOG"

if is_running "$WEB_PID_FILE"; then
  echo "Web app already running with PID $(cat "$WEB_PID_FILE")"
else
  (
    cd "$ROOT_DIR/web"
    nohup ./node_modules/.bin/next dev --hostname 127.0.0.1 --port 3000 >"$WEB_LOG" 2>&1 &
    echo $! >"$WEB_PID_FILE"
  )
  echo "Started web app on http://127.0.0.1:3000 (PID $(cat "$WEB_PID_FILE"))"
fi

wait_for_http "Web app" "$WEB_PID_FILE" "http://127.0.0.1:3000" "$WEB_LOG"

echo "Logs:"
echo "  API: $API_LOG"
echo "  Web: $WEB_LOG"
