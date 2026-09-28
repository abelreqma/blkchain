#!/bin/sh
# Manage the blkChain service stack on demand: qdrant, embed_server, api.
# No autostart — you bring it up/down yourself (via `blk up|down|status`).
#
#   scripts/stack.sh up      start qdrant + embed_server + api (wait for health)
#   scripts/stack.sh down    stop them
#   scripts/stack.sh status  show which are up
#
# The Tavily web-search token is passed through to the api/agent: inherited from
# your shell if set, otherwise pulled from your zsh login env. Never printed.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN="$ROOT/.run"; mkdir -p "$RUN"
PY="$ROOT/.venv/bin/python"
QDRANT_NAME=blkchain-qdrant

# Make the Tavily token available to child processes (web fallback in kb_answer).
if [ -z "${TAVILY_SETUP_TOKEN:-}" ]; then
  TAVILY_SETUP_TOKEN=$(zsh -ic 'print -rn -- ${TAVILY_SETUP_TOKEN:-}' 2>/dev/null || true)
fi
export TAVILY_SETUP_TOKEN

health()  { curl -s -m 2 "http://127.0.0.1:$1/health" >/dev/null 2>&1; }
qhealth() { curl -s -m 2 "http://127.0.0.1:6333/" 2>/dev/null | grep -q qdrant; }

start_py() { # name module port
  name=$1; mod=$2; port=$3
  if health "$port"; then echo "  $name: already up (:$port)"; return; fi
  # Run with the project root on PYTHONPATH so `-m blkchain.*` resolves no
  # matter which directory `blk up` was invoked from (blk now runs anywhere).
  PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" nohup "$PY" -m "$mod" >"$RUN/$name.log" 2>&1 &
  echo $! > "$RUN/$name.pid"
  i=0; while ! health "$port" && [ $i -lt 90 ]; do sleep 1; i=$((i+1)); done
  if health "$port"; then echo "  $name: up (:$port, pid $(cat "$RUN/$name.pid"))"
  else echo "  $name: FAILED to become healthy (see $RUN/$name.log)"; fi
}

stop_py() { # name
  name=$1; pidf="$RUN/$name.pid"
  if [ -f "$pidf" ] && kill "$(cat "$pidf")" 2>/dev/null; then rm -f "$pidf"; echo "  $name: stopped"
  elif pkill -f "$name" 2>/dev/null; then rm -f "$pidf"; echo "  $name: stopped"
  else echo "  $name: not running"; fi
}

case "${1:-status}" in
  up)
    echo "blkChain stack: starting..."
    if qhealth; then echo "  qdrant: already up (:6333)"
    elif docker ps -a --format '{{.Names}}' | grep -qx "$QDRANT_NAME"; then
      docker start "$QDRANT_NAME" >/dev/null 2>&1 && echo "  qdrant: started (:6333)" || echo "  qdrant: FAILED to start"
    else
      "$ROOT/scripts/start_qdrant.sh" >/dev/null 2>&1 && echo "  qdrant: created (:6333)" || echo "  qdrant: FAILED to create"
    fi
    start_py embed_server blkchain.embed_server 8100
    start_py api blkchain.api 8200
    [ -n "${TAVILY_SETUP_TOKEN:-}" ] && echo "  tavily: web fallback enabled" || echo "  tavily: token not found (web fallback off)"
    ;;
  down)
    echo "blkChain stack: stopping..."
    stop_py api
    stop_py embed_server
    docker stop "$QDRANT_NAME" >/dev/null 2>&1 && echo "  qdrant: stopped" || echo "  qdrant: not running"
    ;;
  status)
    qhealth && echo "  qdrant:       up (:6333)" || echo "  qdrant:       down (:6333)"
    health 8100 && echo "  embed_server: up (:8100)" || echo "  embed_server: down (:8100)"
    health 8200 && echo "  api:          up (:8200)" || echo "  api:          down (:8200)"
    ;;
  *) echo "usage: stack.sh {up|down|status}"; exit 1 ;;
esac
