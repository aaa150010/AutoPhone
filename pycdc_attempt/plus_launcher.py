Unsupported opcode: MAKE_FUNCTION (122)
# Source Generated with Decompyle++
# File: plus_launcher.pyc (Python 3.13)

__doc__ = 'Standalone entry point for the plus tool and its Node Sentinel fallback.'
from __future__ import annotations
import json
import hashlib
import os
import sys
from pathlib import Path
from typing import Any
TOOL_DIR = None(__file__).resolve().parent
ENGINE_DIR = TOOL_DIR / 'engine'
if None(ENGINE_DIR) not in sys.path:
    pass
0(str, None(ENGINE_DIR))
# WARNING: Decompyle incomplete
