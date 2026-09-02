"""Foreground Flask development entry point with Python auto-reload."""

from __future__ import annotations

import argparse
import os
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18777)
    args = parser.parse_args()

    # Import through the maintained override module so all recovered routes
    # and macOS patches are installed before Flask starts serving requests.
    import web_gui

    data_dir = os.environ.get("GPTPHONE_DATA_DIR") or str(Path(__file__).resolve().parents[1] / "data")
    app = web_gui.create_app(data_dir)
    app.run(
        host="127.0.0.1",
        port=args.port,
        debug=True,
        use_reloader=True,
        threaded=True,
    )


if __name__ == "__main__":
    os.environ.setdefault("FLASK_ENV", "development")
    main()
