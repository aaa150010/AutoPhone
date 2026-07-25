#!/bin/zsh
set -e
unsetopt bg_nice 2>/dev/null || true

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$APP_DIR"

PORT="${GPTPHONE_PORT:-18777}"
VENV_DIR="$APP_DIR/mac_runtime/.venv"

export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"

echo "gptPhone mac launcher"
echo "App dir: $APP_DIR"

mkdir -p "$APP_DIR/data" "$APP_DIR/engine"

PYTHON_BIN="$(command -v python3.13 || true)"
if [ -z "$PYTHON_BIN" ]; then
  if command -v brew >/dev/null 2>&1; then
    echo "Installing Python 3.13 with Homebrew..."
    brew install python@3.13
    PYTHON_BIN="$(command -v python3.13 || true)"
  else
    echo "Missing Python 3.13 and Homebrew was not found."
    echo "Please install Homebrew or Python 3.13, then run this command again."
    read "?Press Enter to close..."
    exit 1
  fi
fi

if [ -z "$PYTHON_BIN" ] || [ ! -x "$PYTHON_BIN" ]; then
  echo "Python 3.13 was not found after installation."
  read "?Press Enter to close..."
  exit 1
fi

if [ ! -x "$VENV_DIR/bin/python" ]; then
  echo "Creating local Python virtual environment..."
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

if ! "$VENV_DIR/bin/python" - <<'PY' >/dev/null 2>&1
import cryptography
import curl_cffi
import flask
import requests
import werkzeug
PY
then
  echo "Installing mac Python dependencies..."
  "$VENV_DIR/bin/pip" install \
    flask==3.1.3 \
    werkzeug==3.1.8 \
    cryptography==46.0.5 \
    curl_cffi==0.15.0 \
    requests \
    rich \
    python-dotenv \
    pysocks \
    certifi \
    charset-normalizer \
    idna \
    urllib3
fi

NODE_BIN="$(command -v node || true)"
if [ -z "$NODE_BIN" ] && command -v brew >/dev/null 2>&1; then
  echo "Installing Node.js with Homebrew..."
  brew install node
  NODE_BIN="$(command -v node || true)"
fi
if [ -n "$NODE_BIN" ]; then
  export CODEX_NODE_BINARY="${CODEX_NODE_BINARY:-$NODE_BIN}"
fi

export PYTHONPATH="$APP_DIR/mac_overrides:$APP_DIR/business_pyc"
export EMAIL_AUTH_IMPORTER_GUI_PORT="$PORT"

(
  for attempt in {1..30}; do
    if /usr/bin/curl -fsS "http://127.0.0.1:$PORT/api/state" >/dev/null 2>&1; then
      /usr/bin/open "http://127.0.0.1:$PORT/" >/dev/null 2>&1 || true
      exit 0
    fi
    sleep 0.5
  done
) &

echo "Starting WebUI: http://127.0.0.1:$PORT"
echo "Close this Terminal window or press Ctrl-C to stop."
exec "$VENV_DIR/bin/python" "$APP_DIR/plus_launcher.pyc" --no-browser --port "$PORT"
