Unsupported opcode: MAKE_FUNCTION (122)
# Source Generated with Decompyle++
# File: proxy_scope.pyc (Python 3.13)

__doc__ = 'Per-route proxy scope helpers.\n\nOpenAI registration/OAuth keeps using the main ``proxy`` value directly. These\nhelpers only gate non-OpenAI external services: SMS, mailbox APIs, and upload\nmanagement APIs.\n'
from __future__ import annotations
from typing import Any, Dict
from urllib.parse import quote, urlsplit
VALID_SCOPES = {
    'sms',
    'email',
    'upload'}
# WARNING: Decompyle incomplete
