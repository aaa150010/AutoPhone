from __future__ import annotations

import argparse
from pathlib import Path
import shutil


OLD_HEADER = """      <div class="privacy-status">
        <span class="status-dot" aria-hidden="true"></span>
        本地处理
      </div>"""
NEW_HEADER = """      <div class="topbar-actions">
        <a class="compact-button" href="./mailboxes/">在线邮箱管理</a>
        <div class="privacy-status">
          <span class="status-dot" aria-hidden="true"></span>
          本地处理
        </div>
      </div>"""
STYLE_MARKER = "/* online-mailbox-manager-link */"
STYLE_PATCH = """

/* online-mailbox-manager-link */
.topbar-actions {
  display: flex;
  align-items: center;
  gap: 10px;
}
"""


def patch(root: Path) -> None:
    index_path = root / "index.html"
    style_path = root / "styles.css"
    index = index_path.read_text(encoding="utf-8")
    style = style_path.read_text(encoding="utf-8")
    if "./mailboxes/" not in index:
        if OLD_HEADER not in index:
            raise RuntimeError("token-tool header marker was not found")
        backup = index_path.with_suffix(".html.before-mailboxes")
        if not backup.exists():
            shutil.copy2(index_path, backup)
        index_path.write_text(index.replace(OLD_HEADER, NEW_HEADER, 1), encoding="utf-8")
    if STYLE_MARKER not in style:
        backup = style_path.with_suffix(".css.before-mailboxes")
        if not backup.exists():
            shutil.copy2(style_path, backup)
        style_path.write_text(style.rstrip() + STYLE_PATCH, encoding="utf-8")
    print("Token tool online mailbox link is installed.")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("/opt/token-tool"))
    args = parser.parse_args()
    patch(args.root.resolve())


if __name__ == "__main__":
    main()
