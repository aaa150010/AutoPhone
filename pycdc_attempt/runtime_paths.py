Unsupported opcode: MAKE_FUNCTION (122)
# Source Generated with Decompyle++
# File: runtime_paths.pyc (Python 3.13)

__doc__ = 'Runtime/resource path helpers for source and one-file exe modes.'
from __future__ import annotations
import os
import shutil
import sys
import time
from pathlib import Path
RUNTIME_DIR_NAMES = ('results', 'data', 'logs', 'archive', 'configs')
# WARNING: Decompyle incomplete
