from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil


def configure(config_path: Path, credentials_path: Path) -> None:
    credentials = json.loads(credentials_path.read_text(encoding="utf-8"))
    api_token = str(credentials.get("api_token") or "").strip()
    base_url = str(credentials.get("base_url") or "").strip()
    if not api_token or not base_url:
        raise ValueError("credentials file is incomplete")
    current = {}
    if config_path.exists():
        current = json.loads(config_path.read_text(encoding="utf-8"))
        if not isinstance(current, dict):
            raise ValueError("local config must be a JSON object")
        backup = config_path.with_suffix(config_path.suffix + ".before-online-mailbox")
        if not backup.exists():
            shutil.copy2(config_path, backup)
    current["online_mailbox"] = {
        **dict(current.get("online_mailbox") or {}),
        "base_url": base_url,
        "api_token": api_token,
    }
    config_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = config_path.with_suffix(config_path.suffix + ".online-mailbox.tmp")
    temporary.write_text(
        json.dumps(current, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    temporary.replace(config_path)
    print("AutoPhone online mailbox configuration updated without printing secrets.")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--credentials", type=Path, required=True)
    args = parser.parse_args()
    configure(args.config.resolve(), args.credentials.resolve())


if __name__ == "__main__":
    main()
