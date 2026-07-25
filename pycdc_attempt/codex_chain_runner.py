Unsupported opcode: MAKE_FUNCTION (122)
# Source Generated with Decompyle++
# File: codex_chain_runner.pyc (Python 3.13)

__doc__ = 'Standalone runner for the Codex phase-2 chain.\n\nUsage examples:\n  python codex_chain_runner.py --email test@example.com --mode mock\n  python codex_chain_runner.py --email test@example.com --mode diagnostic\n  python codex_chain_runner.py --email test@example.com --mode manual --fixture fixtures/manual.json\n  python codex_chain_runner.py --email test@example.com --mode replay --fixture fixtures/manual.json\n  python codex_chain_runner.py --email auto --mode real --config real_config.json\n  python codex_chain_runner.py --email test@example.com --phone-rejects 1 --json\n'
from __future__ import annotations
import argparse
import json
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse
from codex_node_bridge import run_node_bridge
from codex_oauth_chain import FixedEmailOtpProvider, FixedPhoneOtpProvider, FileEmailOtpProvider, FilePhoneOtpProvider, InteractiveEmailOtpProvider, InteractivePhoneOtpProvider, run_codex_after_registration
from codex_runtime_context import proxy_label_for
from openai_oauth import DEFAULT_CLIENT_ID, DEFAULT_REDIRECT_URI, build_oauth_url, strip_oauth_login_for_session_reuse
PROJECT_ROOT = None(__file__).resolve().parents[2]
if None(PROJECT_ROOT) not in sys.path:
    pass
str(None(PROJECT_ROOT))
# WARNING: Decompyle incomplete
