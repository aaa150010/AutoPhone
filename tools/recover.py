#!/usr/bin/env python3
"""Recover readable artifacts from the extracted PyInstaller bundle."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


ROOT = Path("/Users/lwh/Downloads/gptPhone")
EXTRACTED = Path("/private/tmp/PlusBindTool_V1.0.3.exe_extracted")
PYZ = EXTRACTED / "PYZ.pyz_extracted"
PYDISASM = Path("/private/tmp/plusbind-re/bin/pydisasm")
PYCDC = Path("/private/tmp/pycdc/pycdc")

BUSINESS_MODULES = [
    "chatgpt_fields.pyc",
    "codex_chain_runner.pyc",
    "codex_node_bridge.pyc",
    "codex_oauth_chain.pyc",
    "codex_runtime_context.pyc",
    "email_code_poll.pyc",
    "email_provider_branch.pyc",
    "file_safety.pyc",
    "imap_poller.pyc",
    "license_gate.pyc",
    "mailmanage_client.pyc",
    "oauth_local_archive.pyc",
    "openai_oauth.pyc",
    "proxy_scope.pyc",
    "resource_runtime.pyc",
    "runtime.pyc",
    "runtime_paths.pyc",
    "sms_providers.pyc",
    "sms_selector.pyc",
    "sub2_groups.pyc",
    "sub2_session.pyc",
    "upload_targets.pyc",
    "web_gui.pyc",
]

ENTRY_PYCS = [
    EXTRACTED / "plus_launcher.pyc",
    EXTRACTED / "pyiboot01_bootstrap.pyc",
    EXTRACTED / "pyi_rth_inspect.pyc",
    EXTRACTED / "pyi_rth_pkgutil.pyc",
    EXTRACTED / "pyi_rth_multiprocessing.pyc",
    EXTRACTED / "pyi_rth_cryptography_openssl.pyc",
    EXTRACTED / "pyi_rth_setuptools.pyc",
]


def copy_with_tree(src: Path, dest_root: Path, base: Path) -> Path:
    rel = src.relative_to(base)
    dest = dest_root / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    return dest


def run_to_file(args: list[str], out_file: Path) -> int:
    out_file.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out_file.write_text(proc.stdout, encoding="utf-8", errors="replace")
    return proc.returncode


def main() -> int:
    business_dest = ROOT / "business_pyc"
    disasm_dest = ROOT / "disassembly"
    pycdc_dest = ROOT / "pycdc_attempt"

    selected: list[tuple[Path, str]] = []
    for entry in ENTRY_PYCS:
        if entry.exists():
            selected.append((entry, entry.name))

    for name in BUSINESS_MODULES:
        src = PYZ / name
        if src.exists():
            selected.append((src, name))

    tools_dir = PYZ / "tools"
    if tools_dir.exists():
        for src in sorted(tools_dir.rglob("*.pyc")):
            selected.append((src, str(src.relative_to(PYZ))))

    manifest_lines = [
        "# Selected Business Bytecode",
        "",
        "These files were selected from the PyInstaller/PYZ extraction as likely first-party modules.",
        "",
    ]

    for src, rel_name in selected:
        if src.is_relative_to(PYZ):
            copy_with_tree(src, business_dest, PYZ)
        else:
            shutil.copy2(src, business_dest / src.name)

        stem = rel_name[:-4] if rel_name.endswith(".pyc") else rel_name
        disasm_file = disasm_dest / f"{stem}.dis.txt"
        pycdc_file = pycdc_dest / f"{stem}.py"

        run_to_file([str(PYDISASM), str(src)], disasm_file)
        run_to_file([str(PYCDC), str(src)], pycdc_file)

        manifest_lines.append(f"- `{rel_name}`")

    (ROOT / "BUSINESS_MODULES.md").write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
