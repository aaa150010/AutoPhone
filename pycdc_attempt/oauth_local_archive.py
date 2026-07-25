Unsupported opcode: MAKE_FUNCTION (122)
# Source Generated with Decompyle++
# File: oauth_local_archive.pyc (Python 3.13)

__doc__ = 'Build local, importable archives from Codex OAuth token bundles.'
from __future__ import annotations
import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict
DEFAULT_LOCAL_ARCHIVE_DIR = 'runtime/local_archive'
PROJECT_ROOT = None(__file__).resolve().parents[2]
if None(PROJECT_ROOT) not in sys.path:
    pass
str(None(PROJECT_ROOT))
# WARNING: Decompyle incomplete
