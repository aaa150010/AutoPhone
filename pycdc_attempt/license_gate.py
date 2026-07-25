Unsupported opcode: MAKE_FUNCTION (122)
# Source Generated with Decompyle++
# File: license_gate.pyc (Python 3.13)

__doc__ = 'Offline machine-bound license gate for protected releases.'
from __future__ import annotations
import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
# WARNING: Decompyle incomplete
