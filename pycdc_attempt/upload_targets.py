Unsupported opcode: MAKE_FUNCTION (122)
# Source Generated with Decompyle++
# File: upload_targets.pyc (Python 3.13)

__doc__ = 'Upload target helpers for SUB2API and CLIProxyAPI (CPA).'
from __future__ import annotations
import time
import os
import json
import re
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Optional
from urllib.parse import urljoin
import requests
from chatgpt_fields import merge_chatgpt_fields
from proxy_scope import scoped_requests_kwargs
from runtime_paths import runtime_path
if os.name == 'nt':
    import msvcrt
else:
    import fcntl
ROOT = None()
UPLOAD_TARGET_SUB2 = 'sub2'
UPLOAD_TARGET_CPA = 'cpa'
UPLOAD_TARGET_LOCAL = 'local'
VALID_UPLOAD_TARGETS = {
    UPLOAD_TARGET_SUB2,
    UPLOAD_TARGET_CPA,
    UPLOAD_TARGET_LOCAL}
# WARNING: Decompyle incomplete
