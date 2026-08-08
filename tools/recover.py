#!/usr/bin/env python3
"""Recover readable artifacts from an extracted PyInstaller bundle."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable

if __package__:
    from .disassembly_archive import ArchiveError, DEFAULT_MAX_LINES, create_archive
else:
    from disassembly_archive import ArchiveError, DEFAULT_MAX_LINES, create_archive

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

ENTRY_PYC_NAMES = [
    "plus_launcher.pyc",
    "pyiboot01_bootstrap.pyc",
    "pyi_rth_inspect.pyc",
    "pyi_rth_pkgutil.pyc",
    "pyi_rth_multiprocessing.pyc",
    "pyi_rth_cryptography_openssl.pyc",
    "pyi_rth_setuptools.pyc",
]


class RecoveryError(RuntimeError):
    """Raised when bytecode recovery cannot produce a valid archive."""


def copy_with_tree(src: Path, dest_root: Path, base: Path) -> Path:
    rel = src.relative_to(base)
    dest = dest_root / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    return dest


def run_to_file(args: list[str], out_file: Path) -> int:
    out_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    except OSError as exc:
        raise RecoveryError(f"cannot run {args[0]}: {exc}") from exc
    out_file.write_bytes(proc.stdout)
    return proc.returncode


def resolve_executable(value: str) -> str:
    candidate = Path(value).expanduser()
    if candidate.parent != Path("."):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate.resolve())
        raise RecoveryError(f"executable not found or not executable: {value}")
    resolved = shutil.which(value)
    if resolved is None:
        raise RecoveryError(f"executable not found on PATH: {value}")
    return resolved


def recover(
    *,
    root: Path,
    extracted: Path,
    pydisasm: str,
    pycdc: str | None,
    max_lines: int,
) -> dict[str, int]:
    root = root.resolve()
    extracted = extracted.resolve()
    pyz = extracted / "PYZ.pyz_extracted"
    if not pyz.is_dir():
        raise RecoveryError(f"PYZ extraction directory not found: {pyz}")

    business_dest = root / "business_pyc"
    disasm_dest = root / "disassembly"
    pycdc_dest = root / "pycdc_attempt"

    selected: list[tuple[Path, str]] = []
    for name in ENTRY_PYC_NAMES:
        entry = extracted / name
        if entry.exists():
            selected.append((entry, entry.name))

    for name in BUSINESS_MODULES:
        src = pyz / name
        if src.exists():
            selected.append((src, name))

    tools_dir = pyz / "tools"
    if tools_dir.exists():
        for src in sorted(tools_dir.rglob("*.pyc")):
            selected.append((src, str(src.relative_to(pyz))))
    if not selected:
        raise RecoveryError(f"no selected bytecode modules found under {extracted}")

    manifest_lines = [
        "# Selected Business Bytecode",
        "",
        "These files were selected from the PyInstaller/PYZ extraction as likely first-party modules.",
        "",
    ]

    with tempfile.TemporaryDirectory(prefix="gptphone-disassembly-") as temp_dir:
        full_disassembly = Path(temp_dir)
        for src, rel_name in selected:
            if src.is_relative_to(pyz):
                copy_with_tree(src, business_dest, pyz)
            else:
                business_dest.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, business_dest / src.name)

            stem = rel_name[:-4] if rel_name.endswith(".pyc") else rel_name
            disasm_file = full_disassembly / f"{stem}.dis.txt"
            return_code = run_to_file([pydisasm, str(src)], disasm_file)
            if return_code != 0:
                raise RecoveryError(f"pydisasm failed for {rel_name} with exit code {return_code}")

            if pycdc is not None:
                pycdc_file = pycdc_dest / f"{stem}.py"
                run_to_file([pycdc, str(src)], pycdc_file)

            manifest_lines.append(f"- `{rel_name}`")

        try:
            stats = create_archive(full_disassembly, disasm_dest, max_lines=max_lines)
        except ArchiveError as exc:
            raise RecoveryError(str(exc)) from exc

    (root / "BUSINESS_MODULES.md").write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")
    return stats


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository/output root (default: repository containing this script)",
    )
    parser.add_argument(
        "--extracted",
        type=Path,
        required=True,
        help="PyInstaller extraction root containing PYZ.pyz_extracted",
    )
    parser.add_argument("--pydisasm", default="pydisasm", help="pydisasm executable or PATH name")
    parser.add_argument("--pycdc", default="pycdc", help="pycdc executable or PATH name")
    parser.add_argument("--skip-pycdc", action="store_true", help="do not generate pycdc_attempt files")
    parser.add_argument("--max-lines", type=int, default=DEFAULT_MAX_LINES)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        pydisasm = resolve_executable(args.pydisasm)
        pycdc = None if args.skip_pycdc else resolve_executable(args.pycdc)
        stats = recover(
            root=args.root,
            extracted=args.extracted,
            pydisasm=pydisasm,
            pycdc=pycdc,
            max_lines=args.max_lines,
        )
    except RecoveryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(", ".join(f"{key}={value}" for key, value in stats.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
