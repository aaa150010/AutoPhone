#!/usr/bin/env python3
"""Query indexed disassembly modules and symbols without loading full files."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Iterable

if __package__:
    from .disassembly_archive import (
        ArchiveError,
        _chunk_bytes,
        _physical_lines,
        _validated_module_entries,
        load_index,
        reassemble_module,
    )
else:
    from disassembly_archive import (  # type: ignore[no-redef]
        ArchiveError,
        _chunk_bytes,
        _physical_lines,
        _validated_module_entries,
        load_index,
        reassemble_module,
    )


class QueryError(ArchiveError):
    """Raised when query filters are invalid or ambiguous."""


def _modules(archive_root: Path) -> list[dict[str, Any]]:
    index = load_index(archive_root)
    _, modules = _validated_module_entries(index)
    return modules


def _module_aliases(module: dict[str, Any]) -> set[str]:
    name = str(module["module"])
    source_path = str(module["source_path"])
    return {name, source_path, Path(name).name, Path(source_path).name}


def resolve_module(archive_root: Path, query: str) -> dict[str, Any]:
    modules = _modules(archive_root)
    exact = [module for module in modules if query in _module_aliases(module)]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        names = ", ".join(str(item["module"]) for item in exact)
        raise QueryError(f"ambiguous module {query!r}: {names}")
    partial = [module for module in modules if query in str(module["module"])]
    if len(partial) == 1:
        return partial[0]
    if len(partial) > 1:
        names = ", ".join(str(item["module"]) for item in partial)
        raise QueryError(f"ambiguous module {query!r}: {names}")
    raise QueryError(f"module not found: {query!r}")


def find_symbols(
    archive_root: Path,
    *,
    module_query: str | None = None,
    symbol: str | None = None,
    first_source_line: int | None = None,
    ordinal: int | None = None,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    modules = [resolve_module(archive_root, module_query)] if module_query else _modules(archive_root)
    results: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for module in modules:
        symbols = module.get("symbols")
        if not isinstance(symbols, list):
            raise QueryError(f"invalid symbol index for module {module.get('module')!r}")
        for entry in symbols:
            if symbol is not None and entry.get("name") != symbol:
                continue
            if first_source_line is not None and entry.get("first_source_line") != first_source_line:
                continue
            if ordinal is not None and entry.get("ordinal") != ordinal:
                continue
            results.append((module, entry))
    return results


def read_line_range(archive_root: Path, module: dict[str, Any], start_line: int, end_line: int) -> bytes:
    if start_line < 1 or end_line < start_line or end_line > module.get("line_count", 0):
        raise QueryError(
            f"invalid line range {start_line}-{end_line} for module {module.get('module')!r}"
        )
    output: list[bytes] = []
    for chunk in module.get("chunks", []):
        chunk_start = chunk["start_line"]
        chunk_end = chunk["end_line"]
        if chunk_end < start_line or chunk_start > end_line:
            continue
        chunk_data = _chunk_bytes(archive_root, chunk)
        actual_sha256 = hashlib.sha256(chunk_data).hexdigest()
        if chunk.get("sha256") != actual_sha256:
            raise QueryError(f"SHA-256 mismatch for chunk {chunk.get('path')}")
        lines = _physical_lines(chunk_data)
        local_start = max(start_line, chunk_start) - chunk_start
        local_end = min(end_line, chunk_end) - chunk_start + 1
        output.extend(lines[local_start:local_end])
    return b"".join(output)


def _record(module: dict[str, Any], symbol: dict[str, Any]) -> dict[str, Any]:
    return {
        "module": module["module"],
        "ordinal": symbol["ordinal"],
        "symbol": symbol["name"],
        "source_filename": symbol["source_filename"],
        "first_source_line": symbol["first_source_line"],
        "disassembly_start_line": symbol["start_line"],
        "disassembly_end_line": symbol["end_line"],
    }


def _print_find_results(results: list[tuple[dict[str, Any], dict[str, Any]]], *, as_json: bool) -> None:
    records = [_record(module, symbol) for module, symbol in results]
    if as_json:
        print(json.dumps(records, ensure_ascii=False, indent=2))
        return
    for record in records:
        print(
            "{module}\t{ordinal}\t{symbol}\t{source_filename}:{first_source_line}"
            "\tdisassembly:{disassembly_start_line}-{disassembly_end_line}".format(**record)
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("disassembly"), help="archive directory")
    subparsers = parser.add_subparsers(dest="command", required=True)

    modules = subparsers.add_parser("modules", help="list indexed modules")
    modules.add_argument("--contains", help="only names containing this text")
    modules.add_argument("--json", action="store_true", dest="as_json")

    find = subparsers.add_parser("find", help="find symbols by module, exact name, or source first line")
    find.add_argument("--module")
    find.add_argument("--symbol")
    find.add_argument("--first-line", type=int)
    find.add_argument("--ordinal", type=int)
    find.add_argument("--json", action="store_true", dest="as_json")

    show = subparsers.add_parser("show", help="print a full module or one uniquely selected symbol")
    show.add_argument("--module", required=True)
    show.add_argument("--symbol")
    show.add_argument("--first-line", type=int)
    show.add_argument("--ordinal", type=int)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    archive_root = args.root.resolve()
    try:
        if args.command == "modules":
            records = [
                {
                    "module": module["module"],
                    "source_path": module["source_path"],
                    "lines": module["line_count"],
                    "chunks": len(module["chunks"]),
                    "symbols": len(module["symbols"]),
                    "source_sha256": module["source_sha256"],
                }
                for module in _modules(archive_root)
                if args.contains is None or args.contains in str(module["module"])
            ]
            if args.as_json:
                print(json.dumps(records, ensure_ascii=False, indent=2))
            else:
                for record in records:
                    print(
                        "{module}\tlines={lines}\tchunks={chunks}\tsymbols={symbols}\tsha256={source_sha256}".format(
                            **record
                        )
                    )
            return 0

        if args.command == "find":
            if all(
                value is None
                for value in (args.module, args.symbol, args.first_line, args.ordinal)
            ):
                raise QueryError("find requires at least one query filter")
            results = find_symbols(
                archive_root,
                module_query=args.module,
                symbol=args.symbol,
                first_source_line=args.first_line,
                ordinal=args.ordinal,
            )
            _print_find_results(results, as_json=args.as_json)
            return 0 if results else 1

        module = resolve_module(archive_root, args.module)
        has_symbol_filter = any(
            value is not None for value in (args.symbol, args.first_line, args.ordinal)
        )
        if not has_symbol_filter:
            sys.stdout.buffer.write(reassemble_module(archive_root, module, verify=True))
            return 0
        results = find_symbols(
            archive_root,
            module_query=args.module,
            symbol=args.symbol,
            first_source_line=args.first_line,
            ordinal=args.ordinal,
        )
        if not results:
            raise QueryError("no symbol matched the supplied filters")
        if len(results) != 1:
            matches = ", ".join(
                f"{entry['name']}#{entry['ordinal']}@{entry['first_source_line']}"
                for _, entry in results
            )
            raise QueryError(f"symbol query is ambiguous; add --first-line or --ordinal: {matches}")
        _, symbol = results[0]
        sys.stdout.buffer.write(
            read_line_range(archive_root, module, symbol["start_line"], symbol["end_line"])
        )
        return 0
    except ArchiveError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
