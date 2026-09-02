#!/bin/zsh
set -e
unsetopt bg_nice 2>/dev/null || true
APP_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$APP_DIR"
PORT="18777"
DEV_PORT="5173"
VENV_DIR="$APP_DIR/mac_runtime/.venv"
export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"
echo "gptPhone development launcher"
echo "App dir: $APP_DIR"
mkdir -p "$APP_DIR/data" "$APP_DIR/engine"
PYTHON_BIN="$(command -v python3.13 || true)"
if [ -z "$PYTHON_BIN" ] && command -v brew >/dev/null 2>&1; then
  echo "Installing Python 3.13 with Homebrew..."
  brew install python@3.13
  hash -r 2>/dev/null || true
  PYTHON_BIN="$(command -v python3.13 || true)"
fi
if [ -z "$PYTHON_BIN" ]; then echo "Missing Python 3.13. Install it with Homebrew, then retry."; exit 1; fi
if [ -x "$VENV_DIR/bin/python" ] && ! "$VENV_DIR/bin/python" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 13) else 1)' >/dev/null 2>&1; then
  echo "The local Python environment is stale; rebuilding it..."
  rm -rf "$VENV_DIR"
fi
if [ ! -x "$VENV_DIR/bin/python" ]; then echo "Creating local Python virtual environment..."; "$PYTHON_BIN" -m venv "$VENV_DIR"; fi
if ! "$VENV_DIR/bin/python" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 13) else 1)' >/dev/null 2>&1; then echo "The local Python environment is stale or cannot be opened."; exit 1; fi
if ! "$VENV_DIR/bin/python" - <<'PY' >/dev/null 2>&1
import cryptography, curl_cffi, flask, requests, selenium, werkzeug
PY
then
  echo "Installing mac Python dependencies..."
  "$VENV_DIR/bin/python" -m pip install flask==3.1.3 werkzeug==3.1.8 cryptography==46.0.5 curl_cffi==0.15.0 requests selenium rich python-dotenv pysocks certifi charset-normalizer idna urllib3
fi
export XDG_CACHE_HOME="$APP_DIR/data/cache"
if [ ! -f "$APP_DIR/node_chain.dat" ] && [ -f "$APP_DIR/external_assets/node_chain.dat" ]; then
  cp "$APP_DIR/external_assets/node_chain.dat" "$APP_DIR/node_chain.dat"
fi
if [ ! -f "$APP_DIR/engine/node_chain/real_sentinel_runner.js" ] && [ -f "$APP_DIR/node_chain.dat" ]; then
  APP_DIR_FOR_NODE="$APP_DIR" "$VENV_DIR/bin/python" - <<'PY'
import os
import shutil
import sys
from pathlib import Path

app_dir = Path(os.environ["APP_DIR_FOR_NODE"])
sys.path.insert(0, str(app_dir / "business_pyc"))
import resource_runtime

sys.frozen = True
sys.executable = str(app_dir / "plus_launcher.pyc")
node_dir = Path(resource_runtime.resolve_node_chain_dir())
target = app_dir / "engine" / "node_chain"
target.parent.mkdir(parents=True, exist_ok=True)
if target.is_symlink() or target.exists():
    if (target / "real_sentinel_runner.js").exists():
        raise SystemExit(0)
    if target.is_symlink(): target.unlink()
    elif target.is_dir(): shutil.rmtree(target)
    else: target.unlink()
try:
    target.symlink_to(node_dir, target_is_directory=True)
except OSError:
    shutil.copytree(node_dir, target)
PY
fi
if ! "$VENV_DIR/bin/python" - <<'PY' >/dev/null 2>&1
import camoufox
PY
then "$VENV_DIR/bin/python" -m pip install "camoufox[geoip]"; fi
if ! "$VENV_DIR/bin/python" - <<'PY' >/dev/null 2>&1
from camoufox.pkgman import installed_verstr
installed_verstr()
PY
then "$VENV_DIR/bin/python" "$APP_DIR/tools/install_camoufox_runtime.py"; fi
NODE_BIN="$(command -v node || true)"
if [ -n "$NODE_BIN" ]; then export CODEX_NODE_BINARY="$NODE_BIN"; fi
NPM_BIN="$(command -v npm || true)"
if [ -z "$NPM_BIN" ]; then echo "Missing npm. Install Node.js, then retry."; exit 1; fi
FRONTEND_DIR="$APP_DIR/frontend"
if [ ! -x "$FRONTEND_DIR/node_modules/.bin/vite" ]; then (cd "$FRONTEND_DIR" && "$NPM_BIN" ci --no-audit --no-fund); fi
export PYTHONPATH="$APP_DIR/mac_overrides:$APP_DIR/business_pyc"
export EMAIL_AUTH_IMPORTER_GUI_PORT="$PORT"
stop_legacy_webui() {
  local legacy_label="com.gptphone.autophone"
  local legacy_pid=""
  legacy_pid="$(/bin/launchctl print "gui/$(id -u)/$legacy_label" 2>/dev/null | /usr/bin/sed -nE 's/^[[:space:]]*pid = ([0-9]+).*$/\1/p' | head -1)"
  if [ -n "$legacy_pid" ]; then
    /bin/launchctl bootout "gui/$(id -u)/$legacy_label" >/dev/null 2>&1 || true
    kill -TERM "$legacy_pid" 2>/dev/null || true
    sleep 0.5
  fi
}
if /usr/sbin/lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  legacy_listener_pid="$(/usr/sbin/lsof -nP -tiTCP:"$PORT" -sTCP:LISTEN | head -1 || true)"
  legacy_command=""
  if [ -n "$legacy_listener_pid" ]; then
    legacy_command="$(ps -p "$legacy_listener_pid" -o command= 2>/dev/null || true)"
  fi
  if [[ "$legacy_command" == *"$APP_DIR/plus_launcher.pyc"* ]] || [[ "$legacy_command" == *"$APP_DIR/tools/dev_server.py"* ]]; then
    echo "Stopping the previous gptPhone development process..."
    stop_legacy_webui
    legacy_pid="$(/usr/sbin/lsof -nP -tiTCP:"$PORT" -sTCP:LISTEN | head -1 || true)"
    [ -n "$legacy_pid" ] && kill -TERM "$legacy_pid" 2>/dev/null || true
    sleep 0.5
  fi
fi
if /usr/sbin/lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then echo "Port $PORT is already in use by another process."; exit 1; fi
if /usr/sbin/lsof -nP -iTCP:"$DEV_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  vite_listener_pid="$(/usr/sbin/lsof -nP -tiTCP:"$DEV_PORT" -sTCP:LISTEN | head -1 || true)"
  vite_command=""
  if [ -n "$vite_listener_pid" ]; then vite_command="$(ps -p "$vite_listener_pid" -o command= 2>/dev/null || true)"; fi
  if [[ "$vite_command" == *"$FRONTEND_DIR"* ]] || [[ "$vite_command" == *"vite/bin/vite.js"* ]]; then
    echo "Stopping the previous Vite development process..."
    kill -TERM "$vite_listener_pid" 2>/dev/null || true
    sleep 0.5
  fi
fi
if /usr/sbin/lsof -nP -iTCP:"$DEV_PORT" -sTCP:LISTEN >/dev/null 2>&1; then echo "Port $DEV_PORT is already in use by another process."; exit 1; fi
FLASK_PID=""
VITE_PID=""
cleanup() {
  trap - INT TERM EXIT
  [ -n "$VITE_PID" ] && kill "$VITE_PID" 2>/dev/null || true
  [ -n "$FLASK_PID" ] && kill "$FLASK_PID" 2>/dev/null || true
  [ -n "$VITE_PID" ] && wait "$VITE_PID" 2>/dev/null || true
  [ -n "$FLASK_PID" ] && wait "$FLASK_PID" 2>/dev/null || true
}
trap cleanup INT TERM EXIT
echo "Starting Flask with Python auto-reload: http://127.0.0.1:$PORT"
"$VENV_DIR/bin/python" "$APP_DIR/tools/dev_server.py" --port "$PORT" & FLASK_PID=$!
echo "Starting Vite with HMR: http://127.0.0.1:$DEV_PORT"
(cd "$FRONTEND_DIR" && "$NPM_BIN" run dev -- --host 127.0.0.1 --port "$DEV_PORT" --strictPort) & VITE_PID=$!
ready=""
for attempt in {1..120}; do
  if /usr/bin/curl -fsS "http://127.0.0.1:$PORT/api/state" >/dev/null 2>&1 && /usr/bin/curl -fsS "http://127.0.0.1:$DEV_PORT/" >/dev/null 2>&1; then ready="1"; /usr/bin/open "http://127.0.0.1:$DEV_PORT/" >/dev/null 2>&1 || true; break; fi
  if ! kill -0 "$FLASK_PID" 2>/dev/null || ! kill -0 "$VITE_PID" 2>/dev/null; then echo "Flask or Vite failed to start; inspect the terminal output."; exit 1; fi
  sleep 0.5
done
if [ -z "$ready" ]; then echo "Development services did not become ready within 60 seconds."; exit 1; fi
echo "开发模式已启动：前端 http://127.0.0.1:$DEV_PORT，API http://127.0.0.1:$PORT"
echo "修改 Vue 或 Python 文件会自动更新；按 Ctrl-C 停止两个服务。"
wait "$FLASK_PID" "$VITE_PID"
