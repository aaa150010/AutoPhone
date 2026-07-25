Unsupported opcode: MAKE_FUNCTION (122)
# Source Generated with Decompyle++
# File: chatgpt_fields.pyc (Python 3.13)

__doc__ = 'Shared helpers for extracting and preserving ChatGPT account metadata.\n\nThe registration flow gets credentials from several places (OpenAI JWTs,\nSUB2 exchange-code responses, local result JSON, and sometimes SUB2 account\ndetail responses).  This module keeps the field mapping conservative so we do\nnot accidentally treat a SUB2 account id as a ChatGPT account id.\n'
from __future__ import annotations
import base64
import json
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Tuple
CHATGPT_FIELD_KEYS = ('chatgpt_account_id', 'chatgpt_account_user_id', 'chatgpt_user_id', 'chatgpt_plan_type')
CHATGPT_ALL_KEYS = CHATGPT_FIELD_KEYS + ('account_id', 'chatgpt_auth_user_id', 'chatgpt_field_source', 'chatgpt_field_checked_at', 'cpa_ready', 'cpa_missing_reason')
_BAD_ACCOUNT_PATH_HINTS = {
    'sub2',
    'admin',
    'group',
    'proxy',
    'groups',
    'billing',
    'sub2api'}
_SAFE_ACCOUNT_PATH_HINTS = {
    'auth',
    'openai',
    'chatgpt',
    'workspace',
    'workspaces'}
_SAFE_USER_PATH_HINTS = {
    'jwt',
    'auth',
    'claims',
    'openai',
    'chatgpt',
    'profile',
    'credential',
    'credentials'}
# WARNING: Decompyle incomplete
