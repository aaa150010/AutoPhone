Unsupported opcode: MAKE_FUNCTION (122)
# Source Generated with Decompyle++
# File: file_safety.pyc (Python 3.13)

__doc__ = 'Small cross-process file helpers for high-concurrency runs.'
from __future__ import annotations
import json
import hashlib
import os
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator
if os.name == 'nt':
    import msvcrt
else:
    import fcntl
from runtime_paths import runtime_path
_LOCKS_GUARD = None()
_PROCESS_LOCKS: 'dict[str, threading.RLock]' = { }
# WARNING: Decompyle incomplete
