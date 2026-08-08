from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools import recover
from tools.disassembly_archive import ArchiveError, create_archive, restore_archive, verify_archive
from tools.disassembly_query import find_symbols, read_line_range, resolve_module


def _disassembly(*symbols: tuple[str, int, list[str]]) -> bytes:
    lines = ["# pydisasm version test\n", "# Python bytecode test\n"]
    for name, first_line, body in symbols:
        lines.extend(
            [
                f"# Method Name:       {name}\n",
                "# Filename:          sample.py\n",
                "# Argument count:    0\n",
                f"# First Line:        {first_line}\n",
                "# Constants:\n",
            ]
        )
        lines.extend(f"{item}\n" for item in body)
    return "".join(lines).encode("utf-8")


class DisassemblyArchiveTests(unittest.TestCase):
    def test_in_place_archive_is_line_bounded_and_losslessly_restorable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "disassembly"
            nested = root / "tools"
            nested.mkdir(parents=True)
            originals = {
                "alpha.dis.txt": _disassembly(
                    ("<module>", 1, [f"module-{index}" for index in range(8)]),
                    ("work", 10, [f"work-{index}" for index in range(7)]),
                ),
                "tools/beta.dis.txt": _disassembly(("beta", 22, ["one", "two"])),
            }
            for relative, data in originals.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)

            stats = create_archive(root, root, max_lines=6)

            self.assertEqual(stats["modules"], 2)
            self.assertFalse((root / "alpha.dis.txt").exists())
            self.assertFalse((root / "tools" / "beta.dis.txt").exists())
            index = json.loads((root / "index.json").read_text(encoding="utf-8"))
            for module in index["modules"]:
                expected = originals[module["source_path"]]
                self.assertEqual(module["source_sha256"], hashlib.sha256(expected).hexdigest())
                self.assertTrue(all(chunk["line_count"] <= 6 for chunk in module["chunks"]))

            restored = Path(temp_dir) / "restored"
            restore_archive(root, restored)
            for relative, expected in originals.items():
                self.assertEqual((restored / relative).read_bytes(), expected)

    def test_symbol_queries_use_module_name_symbol_and_first_source_line(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source"
            archive = Path(temp_dir) / "archive"
            source.mkdir()
            source_data = _disassembly(
                ("duplicate", 10, ["first body"]),
                ("duplicate", 20, ["second body"]),
                ("unique", 30, ["third body"]),
            )
            (source / "sample.dis.txt").write_bytes(source_data)
            create_archive(source, archive, max_lines=7)

            module = resolve_module(archive, "sample")
            duplicate_matches = find_symbols(archive, module_query="sample", symbol="duplicate")
            self.assertEqual(len(duplicate_matches), 2)
            line_match = find_symbols(
                archive,
                module_query="sample",
                symbol="duplicate",
                first_source_line=20,
            )
            self.assertEqual(len(line_match), 1)
            symbol = line_match[0][1]
            selected = read_line_range(archive, module, symbol["start_line"], symbol["end_line"])
            self.assertIn(b"second body", selected)
            self.assertNotIn(b"first body", selected)

    def test_verification_rejects_modified_chunk(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source"
            archive = Path(temp_dir) / "archive"
            source.mkdir()
            (source / "sample.dis.txt").write_bytes(_disassembly(("sample", 1, ["body"])))
            create_archive(source, archive, max_lines=4)
            index = json.loads((archive / "index.json").read_text(encoding="utf-8"))
            chunk = archive / index["modules"][0]["chunks"][0]["path"]
            chunk.write_bytes(chunk.read_bytes() + b"tampered\n")

            with self.assertRaisesRegex(ArchiveError, "mismatch|lines"):
                verify_archive(archive)


class RecoverCliTests(unittest.TestCase):
    def test_recover_uses_cli_paths_and_writes_an_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            extracted = temp / "bundle"
            pyz = extracted / "PYZ.pyz_extracted"
            pyz.mkdir(parents=True)
            (pyz / "chatgpt_fields.pyc").write_bytes(b"test bytecode")
            fake_pydisasm = temp / "fake-pydisasm"
            fake_pydisasm.write_text(
                "#!/bin/sh\n"
                "printf '# Method Name:       <module>\\n'\n"
                "printf '# Filename:          fake.py\\n'\n"
                "printf '# First Line:        1\\n'\n"
                "printf '0 RETURN_CONST         (None)\\n'\n",
                encoding="utf-8",
            )
            fake_pydisasm.chmod(0o755)
            output_root = temp / "output"

            exit_code = recover.main(
                [
                    "--root",
                    str(output_root),
                    "--extracted",
                    str(extracted),
                    "--pydisasm",
                    str(fake_pydisasm),
                    "--skip-pycdc",
                ]
            )

            self.assertEqual(exit_code, 0)
            self.assertTrue((output_root / "disassembly" / "index.json").is_file())
            stats = verify_archive(output_root / "disassembly")
            self.assertEqual(stats["modules"], 1)
            self.assertTrue((output_root / "business_pyc" / "chatgpt_fields.pyc").is_file())


if __name__ == "__main__":
    unittest.main()
