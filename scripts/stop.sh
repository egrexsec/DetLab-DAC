#!/bin/bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RUN_DIR="$ROOT_DIR/.detlab-run"

stop_process() {
  local name="$1"
  local pid_file="$2"
  if [[ ! -f "$pid_file" ]]; then
    echo "$name is not running"
    return 0
  fi

  local pid
  pid=$(cat "$pid_file")
  if kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid"
    echo "Stopped $name (PID $pid)"
  else
    echo "$name PID file was stale ($pid)"
  fi
  rm -f "$pid_file"
}

stop_process "web app" "$RUN_DIR/web.pid"
stop_process "api" "$RUN_DIR/api.pid"
