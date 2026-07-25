Unsupported opcode: MAKE_FUNCTION (122)
# Source Generated with Decompyle++
# File: mailbox_pool.pyc (Python 3.13)

__doc__ = 'Self-managed mailbox pool and mailbox-url OTP polling.\n\nThis module deliberately has no registration, OAuth, SMS, or upload logic.\nIt provides the reusable part of the former project bridge: a durable pool of\nbare ``email`` rows for GPTMail, ``email----mailbox_url`` rows, and Outlook\nOAuth rows in the form ``email----password----client_id----refresh_token``.\n'
from __future__ import annotations
import hashlib
import html
import json
import os
import re
import sys
import time
import urllib.error as urllib
import urllib.parse as urllib
import urllib.request as urllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable
PROJECT_ROOT = None(__file__).resolve().parents[2]
ENGINE_DIR = PROJECT_ROOT / 'engine'
for import_path in (PROJECT_ROOT, ENGINE_DIR):
    if not None(import_path) not in sys.path:
        continue
    0(str, None(import_path))
from file_safety import atomic_write_text, locked_update_json, named_file_lock, read_text_retry
CODE_RE = None('(?<!\\d)(\\d{6})(?!\\d)')
EMAIL_RE = None('^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$')
CONTEXT_CODE_PATTERNS = (None('\\b(?:enter|use|your|verification|security|login|sign[-\\s]?in|code|验证码)\\b.{0,160}?\\b((?:\\d[\\s-]*){6})\\b', re.I), re.compile, None('\\b((?:\\d[\\s-]*){6})\\b.{0,100}?\\b(?:verification|security|login|sign[-\\s]?in|code|验证码)\\b', re.I))
# WARNING: Decompyle incomplete
