#!/usr/bin/env bash
#
# One command to boot the whole RedHive stack for local dev / demos:
#   - applies DB migrations
#   - starts the vulnerable demo target  (http://localhost:8780)
#   - starts the API                     (http://localhost:8000)
#   - starts a scan worker
#   - starts the Next.js dashboard        (http://localhost:3000)
#
# Everything runs until you Ctrl-C, which tears all of it down cleanly.
# Requires: Postgres reachable at $DATABASE_URL, Python venv, and `npm i` in ui/.
#
#   ./scripts/dev.sh
#
set -euo pipefail
cd "$(dirname "$0")/.."

# Activate the venv if present.
if [ -f venv/bin/activate ]; then source venv/bin/activate; fi

echo "▶ Applying database migrations…"
alembic upgrade head

pids=()
cleanup() {
  echo; echo "▶ Shutting down…"
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "▶ Starting demo target on :8780…"
uvicorn demo_target.app:app --host 127.0.0.1 --port 8780 >/tmp/redhive-demo.log 2>&1 & pids+=($!)

echo "▶ Starting API on :8000…"
uvicorn redhive.api.app:app --host 127.0.0.1 --port 8000 >/tmp/redhive-api.log 2>&1 & pids+=($!)

echo "▶ Starting scan worker…"
python -m redhive.worker >/tmp/redhive-worker.log 2>&1 & pids+=($!)

echo "▶ Starting dashboard on :3000…"
( cd ui && npm run dev >/tmp/redhive-ui.log 2>&1 ) & pids+=($!)

sleep 4
cat <<EOF

  ✅ RedHive is up.

     Dashboard      http://localhost:3000
     API + docs     http://localhost:8000/docs
     Demo target    http://localhost:8780   ← scan this (intentionally vulnerable)

     Logs: /tmp/redhive-{api,worker,ui,demo}.log
     Press Ctrl-C to stop everything.

EOF

wait
