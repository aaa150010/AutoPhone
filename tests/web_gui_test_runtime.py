from __future__ import annotations

import importlib
from pathlib import Path
import sys
from typing import Any


class RecoveredWebGuiImport:
    """Isolate the recovered ``tools`` package from repository test tools."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.owns_import = "web_gui" not in sys.modules
        self.preexisting_modules = set(sys.modules)
        self.added_paths: list[str] = []
        self.stashed_tools: dict[str, Any] = {}

    def load(self):
        if not self.owns_import:
            return importlib.import_module("web_gui")
        import_paths = (
            str(self.root / "mac_overrides"),
            str(self.root / "business_pyc"),
        )
        for path in reversed(import_paths):
            if path not in sys.path:
                sys.path.insert(0, path)
                self.added_paths.append(path)
        self.stashed_tools = {
            name: value
            for name, value in tuple(sys.modules.items())
            if name == "tools" or name.startswith("tools.")
        }
        for name in self.stashed_tools:
            sys.modules.pop(name, None)
        try:
            return importlib.import_module("web_gui")
        except Exception:
            self.cleanup()
            raise

    def cleanup(self) -> None:
        if not self.owns_import:
            return
        for name in tuple(sys.modules):
            if name == "tools" or name.startswith("tools."):
                sys.modules.pop(name, None)
        runtime_roots = (
            (self.root / "mac_overrides").resolve(),
            (self.root / "business_pyc").resolve(),
        )
        for name, module in tuple(sys.modules.items()):
            if name in self.preexisting_modules:
                continue
            module_file = getattr(module, "__file__", None)
            if not module_file:
                continue
            try:
                path = Path(module_file).resolve()
            except (OSError, RuntimeError, TypeError, ValueError):
                continue
            if any(path.is_relative_to(root) for root in runtime_roots):
                sys.modules.pop(name, None)
        sys.modules.update(self.stashed_tools)
        for path in self.added_paths:
            try:
                sys.path.remove(path)
            except ValueError:
                pass
        self.added_paths.clear()
