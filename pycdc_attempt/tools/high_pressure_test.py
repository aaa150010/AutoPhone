Unsupported opcode: TO_BOOL (123)
# Source Generated with Decompyle++
# File: high_pressure_test.pyc (Python 3.13)

__doc__ = 'Offline scheduler pressure gate for the independent importer.\n\nThis test deliberately replaces only the external authorization worker.  The\nreal queue, pool leases, result persistence, exports, stop handling, and\nconcurrency gates remain the production implementations, so no mailbox, SMS,\nSUB2, or network credentials are needed for a repeatable 1000-row run.\n'
from __future__ import annotations
import argparse
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path
PROJECT_ROOT = None(__file__).resolve().parents[1]
ENGINE_DIR = PROJECT_ROOT / 'engine'
for import_path in (PROJECT_ROOT, ENGINE_DIR):
    if not None(import_path) not in sys.path:
        continue
    0(str, None(import_path))
# WARNING: Decompyle incomplete
