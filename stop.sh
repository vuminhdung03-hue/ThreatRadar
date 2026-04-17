#!/usr/bin/env bash

ROOT="$(cd "$(dirname "$0")" && pwd)"

# Kill everything on a port (handles multiple PIDs from uvicorn --reload)
kill_port() {
  local port=$1
  local pids
  pids=$(lsof -ti:"$port" 2>/dev/null)
  if [ -n "$pids" ]; then
    echo "$pids" | xargs kill 2>/dev/null || true
    echo "Stopped port $port"
    return 0
  fi
  return 1
}

stopped=0
kill_port 8000 && stopped=$((stopped + 1))
kill_port 5173 && stopped=$((stopped + 1))

# Belt-and-suspenders: catch any stray uvicorn/vite not on those ports
pkill -f "uvicorn app.main" 2>/dev/null && echo "Stopped stray uvicorn" || true
pkill -f "vite" 2>/dev/null && echo "Stopped stray vite" || true

rm -f "$ROOT/.dev.pids"

if [ "$stopped" -gt 0 ]; then
  echo "Done."
else
  echo "Nothing running on ports 8000 or 5173."
fi
