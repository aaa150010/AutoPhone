Unsupported opcode: MAKE_FUNCTION (122)
# Source Generated with Decompyle++
# File: sub2_session.pyc (Python 3.13)

__doc__ = 'Cross-process SUB2 admin login throttling and token cache.'
from __future__ import annotations
import hashlib
import json
import time
from pathlib import Path
from typing import Any, Callable, Dict
import requests
from file_safety import atomic_write_json, named_file_lock
from proxy_scope import requests_kwargs
from runtime_paths import runtime_path
LogFn = Callable[([
    str], None)]
SESSION_FILE = None('data', 'sub2_session_cache.json')
LOGIN_LOCK = 'sub2_admin_login.lock'
TOKEN_TTL_SECONDS = 600
RATE_LIMIT_COOLDOWN_SECONDS = 90
MIN_LOGIN_INTERVAL_SECONDS = 2
# WARNING: Decompyle incomplete
