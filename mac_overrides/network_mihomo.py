"""Small isolated Mihomo lifecycle helper for subscription diagnostics."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
from typing import Any, Mapping


class MihomoUnavailable(RuntimeError):
    pass


class IsolatedMihomo:
    def __init__(self, binary_path: str | Path) -> None:
        self.binary_path = Path(binary_path).expanduser() if str(binary_path or "").strip() else None
        self._temp_dir: Path | None = None
        self._process: subprocess.Popen[Any] | None = None

    @property
    def available(self) -> bool:
        return bool(self.binary_path and self.binary_path.is_file())

    def status(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "path_configured": self.binary_path is not None,
            "message": "可使用隔离临时 Mihomo 测试订阅节点" if self.available else "未找到 Mihomo，仅展示解析结果，无法进行真实节点测试",
        }

    def start(self, config: Mapping[str, Any]) -> int:
        if not self.available:
            raise MihomoUnavailable("Mihomo 不可用")
        self.stop()
        self._temp_dir = Path(tempfile.mkdtemp(prefix="gptphone-mihomo-"))
        config_path = self._temp_dir / "config.yaml"
        config_path.write_text(str(config.get("yaml") or "mixed-port: 0\nmode: rule\n"), encoding="utf-8")
        env = {key: value for key, value in os.environ.items() if key.upper() not in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"}}
        self._process = subprocess.Popen(
            [str(self.binary_path), "-d", str(self._temp_dir), "-f", str(config_path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
        )
        return int(self._process.pid)

    def stop(self) -> None:
        process, temp_dir = self._process, self._temp_dir
        self._process = None
        self._temp_dir = None
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
        if temp_dir is not None:
            for path in sorted(temp_dir.glob("**/*"), reverse=True):
                if path.is_file():
                    path.unlink(missing_ok=True)
                elif path.is_dir():
                    path.rmdir()
            temp_dir.rmdir()


__all__ = ["IsolatedMihomo", "MihomoUnavailable"]
