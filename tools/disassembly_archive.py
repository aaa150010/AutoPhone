#!/usr/bin/env python3
"""Pack pydisasm text into indexed, lossless, line-bounded chunks."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


ARCHIVE_FORMAT = "gptphone-disassembly-archive"
ARCHIVE_VERSION = 1
DEFAULT_MAX_LINES = 800
INDEX_NAME = "index.json"
CHUNKS_DIR = "chunks"


class ArchiveError(RuntimeError):
    """Raised when a disassembly archive is invalid or cannot be built."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _physical_lines(data: bytes) -> list[bytes]:
    return data.splitlines(keepends=True)


def _safe_relative_path(value: str, *, field: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ArchiveError(f"invalid {field}: {value!r}")
    return path


def _parse_int(value: str) -> int | str:
    try:
        return int(value)
    except ValueError:
        return value


def parse_symbols(lines: list[bytes]) -> list[dict[str, Any]]:
    """Index pydisasm code-object headers without changing their bytes."""

    method_prefix = "# Method Name:"
    filename_prefix = "# Filename:"
    first_line_prefix = "# First Line:"
    starts: list[int] = []
    decoded: list[str] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
        decoded.append(line)
        if line.startswith(method_prefix):
            starts.append(line_number)

    symbols: list[dict[str, Any]] = []
    for ordinal, start_line in enumerate(starts, start=1):
        end_line = starts[ordinal] - 1 if ordinal < len(starts) else len(lines)
        header = decoded[start_line - 1 : end_line]
        name = header[0][len(method_prefix) :].strip()
        source_filename: str | None = None
        first_source_line: int | str | None = None
        for line in header[1:]:
            if line.startswith(filename_prefix):
                source_filename = line[len(filename_prefix) :].strip()
            elif line.startswith(first_line_prefix):
                first_source_line = _parse_int(line[len(first_line_prefix) :].strip())
            if source_filename is not None and first_source_line is not None:
                break
        symbols.append(
            {
                "ordinal": ordinal,
                "name": name,
                "source_filename": source_filename,
                "first_source_line": first_source_line,
                "start_line": start_line,
                "end_line": end_line,
            }
        )
    return symbols


def _source_files(source_root: Path) -> list[Path]:
    files: list[Path] = []
    for path in source_root.rglob("*.dis.txt"):
        relative = path.relative_to(source_root)
        if relative.parts and relative.parts[0] == CHUNKS_DIR:
            continue
        files.append(path)
    return sorted(files, key=lambda item: item.relative_to(source_root).as_posix())


def _module_name(source_path: str) -> str:
    suffix = ".dis.txt"
    if not source_path.endswith(suffix):
        raise ArchiveError(f"unexpected disassembly filename: {source_path}")
    return source_path[: -len(suffix)]


def _write_archive(source_root: Path, archive_root: Path, max_lines: int) -> dict[str, Any]:
    sources = _source_files(source_root)
    if not sources:
        raise ArchiveError(f"no .dis.txt files found under {source_root}")

    chunks_root = archive_root / CHUNKS_DIR
    chunks_root.mkdir(parents=True, exist_ok=True)
    modules: list[dict[str, Any]] = []

    for source in sources:
        source_relative = source.relative_to(source_root).as_posix()
        module_name = _module_name(source_relative)
        data = source.read_bytes()
        lines = _physical_lines(data)
        module_chunks: list[dict[str, Any]] = []
        chunk_count = (len(lines) + max_lines - 1) // max_lines
        width = max(4, len(str(chunk_count)))

        for chunk_index, offset in enumerate(range(0, len(lines), max_lines), start=1):
            chunk_lines = lines[offset : offset + max_lines]
            chunk_data = b"".join(chunk_lines)
            chunk_relative = PurePosixPath(CHUNKS_DIR, module_name, f"{chunk_index:0{width}d}.dis.txt")
            chunk_path = archive_root.joinpath(*chunk_relative.parts)
            chunk_path.parent.mkdir(parents=True, exist_ok=True)
            chunk_path.write_bytes(chunk_data)
            module_chunks.append(
                {
                    "path": chunk_relative.as_posix(),
                    "start_line": offset + 1,
                    "end_line": offset + len(chunk_lines),
                    "line_count": len(chunk_lines),
                    "byte_count": len(chunk_data),
                    "sha256": _sha256(chunk_data),
                }
            )

        modules.append(
            {
                "module": module_name,
                "source_path": source_relative,
                "line_count": len(lines),
                "byte_count": len(data),
                "source_sha256": _sha256(data),
                "chunks": module_chunks,
                "symbols": parse_symbols(lines),
            }
        )

    index: dict[str, Any] = {
        "format": ARCHIVE_FORMAT,
        "version": ARCHIVE_VERSION,
        "max_lines_per_chunk": max_lines,
        "modules": modules,
    }
    (archive_root / INDEX_NAME).write_text(
        json.dumps(index, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return index


def load_index(archive_root: Path) -> dict[str, Any]:
    index_path = archive_root / INDEX_NAME
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ArchiveError(f"archive index not found: {index_path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ArchiveError(f"cannot read archive index {index_path}: {exc}") from exc
    if not isinstance(index, dict):
        raise ArchiveError("archive index root must be an object")
    return index


def _validated_module_entries(index: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
    if index.get("format") != ARCHIVE_FORMAT or index.get("version") != ARCHIVE_VERSION:
        raise ArchiveError("unsupported disassembly archive format or version")
    max_lines = index.get("max_lines_per_chunk")
    if not isinstance(max_lines, int) or isinstance(max_lines, bool) or not 1 <= max_lines <= DEFAULT_MAX_LINES:
        raise ArchiveError(f"max_lines_per_chunk must be between 1 and {DEFAULT_MAX_LINES}")
    modules = index.get("modules")
    if not isinstance(modules, list):
        raise ArchiveError("archive modules must be a list")
    return max_lines, modules


def _chunk_bytes(archive_root: Path, chunk: dict[str, Any]) -> bytes:
    relative = _safe_relative_path(str(chunk.get("path", "")), field="chunk path")
    if relative.parts[0] != CHUNKS_DIR:
        raise ArchiveError(f"chunk path must be under {CHUNKS_DIR}/: {relative}")
    path = archive_root.joinpath(*relative.parts)
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ArchiveError(f"cannot read chunk {relative}: {exc}") from exc


def reassemble_module(archive_root: Path, module: dict[str, Any], *, verify: bool = True) -> bytes:
    chunks = module.get("chunks")
    if not isinstance(chunks, list):
        raise ArchiveError(f"module {module.get('module')!r} chunks must be a list")
    data = b"".join(_chunk_bytes(archive_root, chunk) for chunk in chunks)
    if verify:
        expected = module.get("source_sha256")
        actual = _sha256(data)
        if expected != actual:
            raise ArchiveError(
                f"module {module.get('module')!r} source SHA-256 mismatch: expected {expected}, got {actual}"
            )
    return data


def verify_archive(archive_root: Path) -> dict[str, int]:
    index = load_index(archive_root)
    max_lines, modules = _validated_module_entries(index)
    seen_modules: set[str] = set()
    declared_chunks: set[str] = set()
    total_lines = 0
    total_bytes = 0
    total_symbols = 0

    for module in modules:
        if not isinstance(module, dict):
            raise ArchiveError("each module entry must be an object")
        name = module.get("module")
        source_path = module.get("source_path")
        if not isinstance(name, str) or not name or name in seen_modules:
            raise ArchiveError(f"invalid or duplicate module name: {name!r}")
        seen_modules.add(name)
        source_relative = _safe_relative_path(str(source_path or ""), field="source path")
        if _module_name(source_relative.as_posix()) != name:
            raise ArchiveError(f"module/source path mismatch for {name!r}")

        chunks = module.get("chunks")
        if not isinstance(chunks, list):
            raise ArchiveError(f"module {name!r} chunks must be a list")
        expected_start = 1
        assembled: list[bytes] = []
        for chunk in chunks:
            if not isinstance(chunk, dict):
                raise ArchiveError(f"module {name!r} has a non-object chunk entry")
            chunk_path = str(chunk.get("path", ""))
            if chunk_path in declared_chunks:
                raise ArchiveError(f"duplicate chunk path: {chunk_path}")
            declared_chunks.add(chunk_path)
            data = _chunk_bytes(archive_root, chunk)
            lines = _physical_lines(data)
            line_count = len(lines)
            start_line = chunk.get("start_line")
            end_line = chunk.get("end_line")
            if start_line != expected_start:
                raise ArchiveError(f"non-contiguous chunk range in {name!r} at {chunk_path}")
            if line_count < 1 or line_count > max_lines:
                raise ArchiveError(f"chunk {chunk_path} has {line_count} lines; limit is {max_lines}")
            if end_line != start_line + line_count - 1 or chunk.get("line_count") != line_count:
                raise ArchiveError(f"line metadata mismatch for chunk {chunk_path}")
            if chunk.get("byte_count") != len(data):
                raise ArchiveError(f"byte count mismatch for chunk {chunk_path}")
            actual_chunk_sha = _sha256(data)
            if chunk.get("sha256") != actual_chunk_sha:
                raise ArchiveError(f"SHA-256 mismatch for chunk {chunk_path}")
            expected_start = end_line + 1
            assembled.append(data)

        data = b"".join(assembled)
        lines = _physical_lines(data)
        if module.get("line_count") != len(lines):
            raise ArchiveError(f"line count mismatch for module {name!r}")
        if module.get("byte_count") != len(data):
            raise ArchiveError(f"byte count mismatch for module {name!r}")
        actual_source_sha = _sha256(data)
        if module.get("source_sha256") != actual_source_sha:
            raise ArchiveError(f"source SHA-256 mismatch for module {name!r}")
        expected_symbols = parse_symbols(lines)
        if module.get("symbols") != expected_symbols:
            raise ArchiveError(f"symbol index mismatch for module {name!r}")
        total_lines += len(lines)
        total_bytes += len(data)
        total_symbols += len(expected_symbols)

    actual_chunks = {
        path.relative_to(archive_root).as_posix()
        for path in (archive_root / CHUNKS_DIR).rglob("*.dis.txt")
    }
    missing = declared_chunks - actual_chunks
    unexpected = actual_chunks - declared_chunks
    if missing or unexpected:
        raise ArchiveError(
            f"chunk inventory mismatch: missing={sorted(missing)}, unexpected={sorted(unexpected)}"
        )

    legacy_sources = [
        path.relative_to(archive_root).as_posix()
        for path in archive_root.rglob("*.dis.txt")
        if path.relative_to(archive_root).parts[0] != CHUNKS_DIR
    ]
    if legacy_sources:
        raise ArchiveError(f"full disassembly files remain outside {CHUNKS_DIR}/: {legacy_sources}")

    return {
        "modules": len(modules),
        "chunks": len(declared_chunks),
        "symbols": total_symbols,
        "lines": total_lines,
        "bytes": total_bytes,
    }


def _remove_empty_parents(path: Path, stop: Path) -> None:
    parent = path.parent
    while parent != stop and parent.is_relative_to(stop):
        try:
            parent.rmdir()
        except OSError:
            break
        parent = parent.parent


def _publish_archive(staging: Path, output_root: Path) -> None:
    output_root.mkdir(parents=True, exist_ok=True)
    legacy_sources = [
        path
        for path in output_root.rglob("*.dis.txt")
        if path.relative_to(output_root).parts[0] != CHUNKS_DIR
    ]
    old_chunks = output_root / CHUNKS_DIR
    backup_chunks: Path | None = None

    if old_chunks.exists():
        backup_chunks = Path(
            tempfile.mkdtemp(prefix=f".{output_root.name}-chunks-backup-", dir=output_root.parent)
        )
        backup_chunks.rmdir()
        old_chunks.replace(backup_chunks)
    try:
        (staging / CHUNKS_DIR).replace(old_chunks)
        os.replace(staging / INDEX_NAME, output_root / INDEX_NAME)
    except BaseException:
        if old_chunks.exists():
            shutil.rmtree(old_chunks)
        if backup_chunks is not None and backup_chunks.exists():
            backup_chunks.replace(old_chunks)
        raise

    for source in legacy_sources:
        source.unlink()
        _remove_empty_parents(source, output_root)
    if backup_chunks is not None and backup_chunks.exists():
        shutil.rmtree(backup_chunks)


def create_archive(
    source_root: Path,
    output_root: Path,
    *,
    max_lines: int = DEFAULT_MAX_LINES,
) -> dict[str, int]:
    source_root = source_root.resolve()
    output_root = output_root.resolve()
    if (
        not isinstance(max_lines, int)
        or isinstance(max_lines, bool)
        or not 1 <= max_lines <= DEFAULT_MAX_LINES
    ):
        raise ArchiveError(f"max_lines must be between 1 and {DEFAULT_MAX_LINES}")
    if not source_root.is_dir():
        raise ArchiveError(f"source directory not found: {source_root}")
    if source_root != output_root and (
        source_root.is_relative_to(output_root) or output_root.is_relative_to(source_root)
    ):
        raise ArchiveError("source and output directories must be equal or non-overlapping")

    output_root.parent.mkdir(parents=True, exist_ok=True)
    staging_path = Path(
        tempfile.mkdtemp(prefix=f".{output_root.name}-build-", dir=output_root.parent)
    )
    try:
        _write_archive(source_root, staging_path, max_lines)
        verify_archive(staging_path)
        _publish_archive(staging_path, output_root)
        return verify_archive(output_root)
    finally:
        shutil.rmtree(staging_path, ignore_errors=True)


def restore_archive(archive_root: Path, output_root: Path, *, overwrite: bool = False) -> dict[str, int]:
    archive_root = archive_root.resolve()
    output_root = output_root.resolve()
    if archive_root == output_root or archive_root.is_relative_to(output_root) or output_root.is_relative_to(archive_root):
        raise ArchiveError("archive and restore directories must not overlap")
    index = load_index(archive_root)
    _, modules = _validated_module_entries(index)
    destinations: list[tuple[dict[str, Any], Path]] = []
    for module in modules:
        relative = _safe_relative_path(str(module.get("source_path", "")), field="source path")
        destination = output_root.joinpath(*relative.parts)
        if destination.exists() and not overwrite:
            raise ArchiveError(f"restore target already exists: {destination}")
        destinations.append((module, destination))

    restored = 0
    restored_bytes = 0
    for module, destination in destinations:
        data = reassemble_module(archive_root, module, verify=True)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        restored += 1
        restored_bytes += len(data)
    return {"modules": restored, "bytes": restored_bytes}


def _format_stats(stats: dict[str, int]) -> str:
    return ", ".join(f"{key}={value}" for key, value in stats.items())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    pack = subparsers.add_parser("pack", help="replace full .dis.txt files with an indexed archive")
    pack.add_argument("--source", type=Path, required=True, help="directory containing full .dis.txt files")
    pack.add_argument("--output", type=Path, help="archive directory; defaults to --source")
    pack.add_argument("--max-lines", type=int, default=DEFAULT_MAX_LINES)

    verify = subparsers.add_parser("verify", help="verify chunks, metadata, and source SHA-256 values")
    verify.add_argument("--root", type=Path, required=True, help="archive directory")

    restore = subparsers.add_parser("restore", help="reconstruct original full .dis.txt files")
    restore.add_argument("--root", type=Path, required=True, help="archive directory")
    restore.add_argument("--output", type=Path, required=True, help="destination directory")
    restore.add_argument("--overwrite", action="store_true")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "pack":
            stats = create_archive(args.source, args.output or args.source, max_lines=args.max_lines)
        elif args.command == "verify":
            stats = verify_archive(args.root)
        else:
            stats = restore_archive(args.root, args.output, overwrite=args.overwrite)
    except ArchiveError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(_format_stats(stats))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
