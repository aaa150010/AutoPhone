Unsupported opcode: CALL_KW (247)
# Source Generated with Decompyle++
# File: sms_selector.pyc (Python 3.13)

__doc__ = 'Thread-safe smart SMS number route selector.\n\nThe selector only picks country/provider routes. Each worker still calls\ngetNumber on its own SMS provider instance, so activation_id and phone ownership\nstay local to the thread that bought the number.\n'
from __future__ import annotations
import threading
import time
import random
from dataclasses import dataclass
from typing import Any, Callable
from file_safety import locked_update_json
from runtime_paths import runtime_path
LogFn = Callable[([
    str], None)]
_DISCOVERY_CACHE: 'dict[tuple[str, str, str, str, tuple[str, ...]], tuple[float, list[dict[str, Any]]]]' = { }
_DISCOVERY_CACHE_LOCK = None()
# WARNING: Decompyle incomplete
