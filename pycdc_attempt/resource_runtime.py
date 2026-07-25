Unsupported opcode: MAKE_FUNCTION (122)
# Source Generated with Decompyle++
# File: resource_runtime.pyc (Python 3.13)

__doc__ = 'Resolve the encrypted Node chain for the standalone portable package.'
from __future__ import annotations
import base64
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from license_gate import require_license_or_exit
RESOURCE_KEY_B64 = 'WjgVPFMyM_3YMy8wxb_fYBulpYyBrJolkPcmucCB9ZY'
MAGIC = b'NCR1'
NODE_CHAIN_MANIFEST = 'node_chain_manifest.json'
NODE_CHAIN_CONTRACT = 'plus-bind-node-chain-api-v2'
# WARNING: Decompyle incomplete
