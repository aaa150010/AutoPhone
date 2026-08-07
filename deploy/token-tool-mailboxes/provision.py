from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets

from security import hash_password, token_hash


def provision(root: Path, data_dir: Path) -> None:
    env_path = root / ".env"
    credentials_path = root / "credentials.once.json"
    if env_path.exists():
        print("Online mailbox secrets already provisioned; existing files were preserved.")
        return

    web_password = secrets.token_urlsafe(18)
    api_token = secrets.token_urlsafe(32)
    session_secret = secrets.token_urlsafe(48)
    env_text = "\n".join((
        f"DATABASE_PATH=/data/mailboxes.db",
        f"WEB_PASSWORD_HASH={hash_password(web_password)}",
        f"API_TOKEN_SHA256={token_hash(api_token)}",
        f"SESSION_SECRET={session_secret}",
        "MAX_IMPORT_ITEMS=10000",
        "",
    ))
    env_path.write_text(env_text, encoding="utf-8")
    os.chmod(env_path, 0o600)
    credentials_path.write_text(
        json.dumps(
            {
                "manager_url": "https://lynote.xyz/token-tool/mailboxes/",
                "base_url": "https://lynote.xyz/token-tool",
                "web_password": web_password,
                "api_token": api_token,
            },
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    os.chmod(credentials_path, 0o600)
    data_dir.mkdir(parents=True, exist_ok=True)
    if os.geteuid() == 0:
        os.chown(data_dir, 10001, 10001)
    os.chmod(data_dir, 0o700)
    print("Online mailbox secrets provisioned without printing credential values.")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--data-dir", type=Path, default=Path("/opt/token-tool-mailboxes-data"))
    args = parser.parse_args()
    provision(args.root.resolve(), args.data_dir.resolve())


if __name__ == "__main__":
    main()
