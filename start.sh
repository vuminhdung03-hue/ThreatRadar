#!/usr/bin/env bash

ROOT="$(cd "$(dirname "$0")" && pwd)"
VENV="$ROOT/.venv/bin/activate"

# Verify venv exists
if [ ! -f "$VENV" ]; then
  echo "ERROR: venv not found at $ROOT/.venv"
  echo "       Run: python3 -m venv .venv && .venv/bin/pip install -r backend/requirements.txt"
  exit 1
fi

# Clear any leftover processes on these ports
for port in 8000 5173; do
  pids=$(lsof -ti:"$port" 2>/dev/null)
  if [ -n "$pids" ]; then
    echo "Freeing port $port..."
    echo "$pids" | xargs kill 2>/dev/null || true
    sleep 0.5
  fi
done

echo ""
echo "  ThreatRadar — starting dev servers"
echo "  Backend  → http://localhost:8000"
echo "  Frontend → http://localhost:5173"
echo "  API docs → http://localhost:8000/docs"
echo "  Press Ctrl+C or run ./stop.sh to shut down"
echo ""

# ── Backend (FastAPI + uvicorn) ──────────────────────────────────────────────
source "$VENV"
cd "$ROOT/backend"
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload \
  > "$ROOT/backend.log" 2>&1 &
BACKEND_PID=$!

# ── Frontend (Vite) ──────────────────────────────────────────────────────────
cd "$ROOT/frontend"
npm run dev -- --host 0.0.0.0 \
  > "$ROOT/frontend.log" 2>&1 &
FRONTEND_PID=$!

echo "Backend  PID $BACKEND_PID  → backend.log"
echo "Frontend PID $FRONTEND_PID → frontend.log"
echo ""

# Ctrl+C kills both process groups cleanly
trap '
  echo ""
  echo "Shutting down..."
  kill -- -'"$BACKEND_PID"' 2>/dev/null || kill '"$BACKEND_PID"' 2>/dev/null || true
  kill -- -'"$FRONTEND_PID"' 2>/dev/null || kill '"$FRONTEND_PID"' 2>/dev/null || true
  exit 0
' INT TERM

wait $BACKEND_PID $FRONTEND_PID
