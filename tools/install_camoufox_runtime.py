#!/usr/bin/env python3
"""Install Camoufox without requiring the GitHub releases API.

The normal ``CamoufoxFetcher()`` constructor discovers releases through the
GitHub API. That endpoint is rate-limited for unauthenticated clients, which
made a fresh clone fail before the WebUI could start. This helper keeps the
package's own versioned installer, but supplies a release asset directly.
"""

from __future__ import annotations

import os
import platform
import re
import sys


DEFAULT_VERSION = "152.0.4-beta.29"
DEFAULT_REPO = "daijro/camoufox"


def _arch() -> str:
    value = platform.machine().lower()
    return {
        "arm64": "arm64",
        "aarch64": "arm64",
        "x86_64": "x86_64",
        "amd64": "x86_64",
    }.get(value, value)


def _version_parts(value: str) -> tuple[str, str]:
    match = re.fullmatch(r"(\d+(?:\.\d+){1,3})-([A-Za-z0-9.]+)", value.strip())
    if not match:
        raise ValueError("CAMOUFOX_BROWSER_VERSION must look like 152.0.4-beta.29")
    return match.group(1), match.group(2)


def _direct_version():
    from camoufox.pkgman import AvailableVersion, Version

    full_version = os.environ.get("CAMOUFOX_BROWSER_VERSION", DEFAULT_VERSION)
    version, build = _version_parts(full_version)
    url = os.environ.get("CAMOUFOX_BROWSER_URL", "").strip()
    if not url:
        repo = os.environ.get("CAMOUFOX_BROWSER_REPO", DEFAULT_REPO).strip() or DEFAULT_REPO
        url = (
            f"https://github.com/{repo}/releases/download/v{full_version}/"
            f"camoufox-{full_version}-mac.{_arch()}.zip"
        )
    digest = os.environ.get("CAMOUFOX_BROWSER_SHA256", "").strip().lower()
    if digest and not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("CAMOUFOX_BROWSER_SHA256 must be a 64-character SHA-256 digest")
    return AvailableVersion(
        version=Version(build=build, version=version),
        url=url,
        is_prerelease=False,
        sha256=digest or None,
    )


def main() -> int:
    try:
        from camoufox.multiversion import get_cached_versions
        from camoufox.pkgman import CamoufoxFetcher

        # A populated cache is more accurate and avoids both API calls and a
        # needless redownload after a restart.
        selected = None
        try:
            cached = get_cached_versions("Official")
            if cached:
                selected = cached[0]
        except Exception:
            selected = None
        fetcher = CamoufoxFetcher(selected_version=selected or _direct_version())
        fetcher.install()
        return 0
    except Exception as exc:
        print(
            f"Camoufox direct install failed: {type(exc).__name__}: {str(exc)[:240]}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
