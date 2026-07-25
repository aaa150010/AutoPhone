Unsupported opcode: MAKE_FUNCTION (122)
# Source Generated with Decompyle++
# File: mailmanage_client.pyc (Python 3.13)

__doc__ = '\nMailManage 邮箱管理平台 API 客户端\nhttps://mailmanage.lizaliza.top\n\n功能:\n  - 按分类查询邮箱池 (GET /api/mailboxes)\n  - 原子领取邮箱，默认领取即远程消费，避免多线程/多机器重复使用 (POST /api/mailboxes/reserve)\n  - 从指定邮箱获取验证码 (GET /api/mail/<email>)\n  - 后端标记已用，本地记录作为兜底 (POST /api/mailboxes/mark-used)\n'
import datetime
import json
import os
import re
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional, Dict, List
from urllib.parse import quote, urlencode
import requests
from runtime_paths import runtime_path
from file_safety import atomic_write_json, named_file_lock
from proxy_scope import requests_kwargs
DEFAULT_BASE_URL = 'https://mailmanage.lizaliza.top'
DEFAULT_USED_FILE = runtime_path(None('used_emails.json'))
OPENAI_OTP_KEYWORD = 'temporary verification code,临时验证码,输入此临时验证码以继续,Enter this temporary verification code'
OPENAI_OTP_SUBJECT_KEYWORD = 'Your temporary OpenAI verification code,Your temporary ChatGPT verification code,Your temporary ChatGPT login code,你的 OpenAI 临时验证码,你的临时 ChatGPT 登录代码,临时 ChatGPT 登录代码,OpenAI verification code,ChatGPT verification code,ChatGPT login code,OpenAI 临时验证码'
OPENAI_OTP_BROAD_KEYWORD = 'OpenAI,ChatGPT,gpt'
OPENAI_OTP_ANCHORS = ('enter this temporary verification code to continue', 'temporary verification code', 'temporary chatgpt verification code', 'your temporary chatgpt verification code', 'temporary chatgpt login code', 'your temporary chatgpt login code', 'your temporary openai verification code', 'openai verification code', 'chatgpt verification code', 'chatgpt login code', '输入此临时验证码以继续', '临时验证码', 'openai 临时验证码', '临时 chatgpt 登录代码', 'chatgpt 登录代码')
OPENAI_NON_OTP_MARKERS = ('new sign-in', 'new sign in', 'sign-in', 'sign in', 'login', '登录', '登入', '新设备')
# WARNING: Decompyle incomplete
