Unsupported opcode: MAKE_FUNCTION (122)
# Source Generated with Decompyle++
# File: openai_oauth.pyc (Python 3.13)

__doc__ = '\nOpenAI OAuth 纯协议模块\n处理 OAuth 授权码交换、session 管理、邮箱/手机号登录\n\nOpenAI 使用的 OAuth 端点 (Auth0):\n  - authorize:  https://auth.openai.com/oauth/authorize\n  - token:      https://auth.openai.com/oauth/token\n  - userinfo:   https://auth.openai.com/userinfo\n\n登录相关端点 (Auth0 Universal Login):\n  - identifier: POST /u/login/identifier\n  - password:   POST /u/login/password\n  - mfa:        POST /u/mfa-otp-challenge\n'
import re
import json
import time
import secrets
import hashlib
import base64
import requests
from dataclasses import dataclass
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlparse, parse_qs, urlencode
OAUTH_AUTHORIZE_URL = 'https://auth.openai.com/oauth/authorize'
OAUTH_TOKEN_URL = 'https://auth.openai.com/oauth/token'
OAUTH_USERINFO_URL = 'https://auth.openai.com/userinfo'
AUTH0_DOMAIN = 'https://auth.openai.com'
DEFAULT_CLIENT_ID = 'app_EMoamEEZ73f0CkXaXp7hrann'
DEFAULT_REDIRECT_URI = 'http://localhost:1455/auth/callback'
DEFAULT_SCOPE = 'openid profile email offline_access'
DEFAULT_AUDIENCE = ''
CODE_CHALLENGE_METHOD = 'S256'
# WARNING: Decompyle incomplete
