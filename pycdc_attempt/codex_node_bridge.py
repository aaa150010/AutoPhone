Unsupported opcode: MAKE_FUNCTION (122)
# Source Generated with Decompyle++
# File: codex_node_bridge.pyc (Python 3.13)

__doc__ = 'Node bridge for the standalone Codex chain.\n\n``mock`` and ``diagnostic`` stay side-effect free for tests. ``real`` is a hard\ncontract to an external Node SentinelRunner: if no runner is configured, or the\nrunner does not return a generated token, the real chain must fail instead of\nsilently falling back to mock data.\n'
from __future__ import annotations
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict
BRIDGE_VERSION = 'node-bridge-v2'
# WARNING: Decompyle incomplete
