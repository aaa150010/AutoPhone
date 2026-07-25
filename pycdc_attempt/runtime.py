Unsupported opcode: TO_BOOL (123)
# Source Generated with Decompyle++
# File: runtime.pyc (Python 3.13)

__doc__ = "Independent queue runner for self-managed mailbox URLs and SUB2 upload.\n\nThe runner does not modify the registration application. It imports the\nexisting email-first Node state machine and its SMS selector as libraries,\nwhile keeping its own config, pool, results, and logs below this tool's data\ndirectory.\n"
from __future__ import annotations
import copy
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit
import requests
# WARNING: Decompyle incomplete
