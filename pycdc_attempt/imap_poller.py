Unsupported opcode: MAKE_FUNCTION (122)
# Source Generated with Decompyle++
# File: imap_poller.pyc (Python 3.13)

__doc__ = '\n通用 IMAP 邮箱验证码轮询器\n支持 Outlook/Hotmail、iCloud、Gmail、QQ邮箱 等任意 IMAP 邮箱\n\n用法:\n    from imap_poller import ImapPoller\n\n    poller = ImapPoller("user@outlook.com", "app-password", verbose=True)\n    code = poller.poll_code(timeout=60)\n'
import base64
import re
import time
import imaplib
import email
from email.header import decode_header
from email.utils import parsedate_to_datetime
from typing import Optional
from html.parser import HTMLParser
from proxy_scope import requests_kwargs
IMAP_SERVERS = {
    'outlook': ('outlook.office365.com', 993),
    'hotmail': ('outlook.office365.com', 993),
    'live': ('outlook.office365.com', 993),
    'msn': ('outlook.office365.com', 993),
    'icloud': ('imap.mail.me.com', 993),
    'me': ('imap.mail.me.com', 993),
    'mac': ('imap.mail.me.com', 993),
    'gmail': ('imap.gmail.com', 993),
    'googlemail': ('imap.gmail.com', 993),
    'qq': ('imap.qq.com', 993),
    'foxmail': ('imap.qq.com', 993),
    '163': ('imap.163.com', 993),
    '126': ('imap.126.com', 993),
    'yeah': ('imap.yeah.net', 993),
    'aliyun': ('imap.aliyun.com', 993) }
# WARNING: Decompyle incomplete
