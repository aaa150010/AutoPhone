Unsupported opcode: MAKE_FUNCTION (122)
# Source Generated with Decompyle++
# File: codex_oauth_chain.pyc (Python 3.13)

__doc__ = 'Codex OAuth phase-2 state machine.\n\nMock/diagnostic/replay modes stay side-effect free. Real mode follows the\nobserved log chain: Node SentinelRunner -> Codex email OTP -> phone OTP ->\nauthorization code -> token exchange -> SUB2 upload/group verification.\n'
from __future__ import annotations
import json
import base64
import hashlib
import os
import random
import re
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse
from codex_runtime_context import runtime_context_from_inputs, validate_runtime_context
from openai_oauth import DEFAULT_CLIENT_ID, DEFAULT_REDIRECT_URI, OpenAI_OAuth, parse_oauth_url, strip_oauth_login_for_session_reuse
STATE_START = 'START'
STATE_CHAT_REQUIREMENTS_READY = 'CHAT_REQUIREMENTS_READY'
STATE_OAUTH_STARTED = 'OAUTH_STARTED'
STATE_SENTINEL_READY = 'SENTINEL_READY'
STATE_PASSWORD_REQUIRED = 'PASSWORD_REQUIRED'
STATE_PASSWORD_VERIFIED = 'PASSWORD_VERIFIED'
STATE_MFA_OTP_REQUIRED = 'MFA_OTP_REQUIRED'
STATE_MFA_OTP_VERIFIED = 'MFA_OTP_VERIFIED'
STATE_EMAIL_OTP_REQUIRED = 'EMAIL_OTP_REQUIRED'
STATE_EMAIL_OTP_VERIFIED = 'EMAIL_OTP_VERIFIED'
STATE_PHONE_REQUIRED = 'PHONE_REQUIRED'
STATE_PHONE_SEND_REJECTED = 'PHONE_SEND_REJECTED'
STATE_PHONE_OTP_SENT = 'PHONE_OTP_SENT'
STATE_PHONE_OTP_VERIFIED = 'PHONE_OTP_VERIFIED'
STATE_CONSENT_REQUIRED = 'CONSENT_REQUIRED'
STATE_CALLBACK_RECEIVED = 'CALLBACK_RECEIVED'
STATE_TOKEN_EXCHANGED = 'TOKEN_EXCHANGED'
STATE_UPLOAD_SKIPPED = 'UPLOAD_SKIPPED'
STATE_UPLOADED = 'UPLOADED'
STATE_DONE = 'DONE'
STATE_FAILED = 'FAILED'
STATE_DIAGNOSTIC_READY = 'DIAGNOSTIC_READY'
AUTH = 'https://auth.openai.com'
CHATGPT = 'https://chatgpt.com'
UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36'
PAGE_HEADERS = {
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'accept-language': 'zh-CN,zh-Hans-CN;q=0.9,en;q=0.8',
    'user-agent': UA,
    'sec-ch-ua': '"Google Chrome";v="145"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"' }
JSON_HEADERS = {
    'accept': 'application/json',
    'accept-language': 'zh-CN,zh-Hans-CN;q=0.9,en;q=0.8',
    'content-type': 'application/json',
    'origin': AUTH,
    'user-agent': UA,
    'sec-ch-ua': '"Google Chrome";v="145"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"' }
TOKEN_KEYS = {
    'token',
    'id_token',
    'access_token',
    'refresh_token'}
FIRST_NAMES = ('James', 'John', 'Robert', 'Michael', 'William', 'David', 'Richard', 'Joseph', 'Thomas', 'Daniel')
LAST_NAMES = ('Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Miller', 'Davis', 'Garcia', 'Wilson', 'Taylor')
PROJECT_ROOT = None(__file__).resolve().parents[2]
if None(PROJECT_ROOT) not in sys.path:
    pass
str(None(PROJECT_ROOT))
LogFn = Optional[Callable[(..., None)]]
# WARNING: Decompyle incomplete
