Unsupported opcode: MAP_ADD (188)
# Source Generated with Decompyle++
# File: sms_providers.pyc (Python 3.13)

__doc__ = '\n统一接码平台接口 — 支持 SMSBower / Hero-SMS / 5sim / SMSVirtual / GrizzlySMS / SMS-Verification-Number\n\n用法:\n    from sms_providers import create_provider\n\n    sms = create_provider("smsbower", api_key="xxx", proxy="http://127.0.0.1:7890")\n    # 或\n    sms = create_provider("herosms", api_key="xxx", proxy="...")\n    # 或\n    sms = create_provider("5sim", api_key="xxx", proxy="...")\n\n    print(sms.balance())\n    aid, phone = sms.get_number(service="dr", country="151")\n    sms.set_ready()\n    code = sms.wait_code(timeout=300)\n    sms.complete()\n'
import abc
import hashlib
import json
import os
import random
import re
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from typing import Optional, Tuple
from file_safety import atomic_write_text, locked_update_json, named_file_lock
from runtime_paths import resolve_runtime_path, runtime_path
# WARNING: Decompyle incomplete
