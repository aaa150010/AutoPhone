from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from mac_overrides.node_runtime import configure_node_runtime


class NodeRuntimeTests(unittest.TestCase):
    def test_valid_explicit_binary_is_used_and_path_is_prepended(self):
        with tempfile.TemporaryDirectory() as tempdir:
            node = Path(tempdir) / "node"
            node.write_text("#!/bin/sh\n", encoding="utf-8")
            node.chmod(0o755)
            env = {"CODEX_NODE_BINARY": str(node), "PATH": "/usr/bin"}

            resolved = configure_node_runtime(env, which=lambda _name: None)

            self.assertEqual(resolved, str(node.resolve()))
            self.assertEqual(env["CODEX_NODE_BINARY"], str(node.resolve()))
            self.assertEqual(env["PATH"].split(os.pathsep)[0], str(node.resolve().parent))

    def test_invalid_explicit_binary_falls_back_to_node(self):
        with tempfile.TemporaryDirectory() as tempdir:
            node = Path(tempdir) / "node"
            node.write_text("#!/bin/sh\n", encoding="utf-8")
            node.chmod(0o755)
            env = {"CODEX_NODE_BINARY": "/missing/node", "PATH": "/usr/bin"}

            resolved = configure_node_runtime(env, which=lambda name: str(node) if name == "node" else None)

            self.assertEqual(resolved, str(node.resolve()))
            self.assertEqual(env["CODEX_NODE_BINARY"], str(node.resolve()))

    def test_missing_node_does_not_write_a_fake_path(self):
        env = {"CODEX_NODE_BINARY": "/missing/node", "PATH": "/usr/bin"}

        resolved = configure_node_runtime(env, which=lambda _name: None)

        self.assertIsNone(resolved)
        self.assertNotIn("CODEX_NODE_BINARY", env)
        self.assertEqual(env["PATH"], "/usr/bin")


if __name__ == "__main__":
    unittest.main()
