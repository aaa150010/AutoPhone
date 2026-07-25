Unsupported opcode: MAKE_FUNCTION (122)
# Source Generated with Decompyle++
# File: web_gui.pyc (Python 3.13)

__doc__ = 'Local WebUI for the standalone email-first authorization importer.'
from __future__ import annotations
import copy
import os
import re
import threading
import time
import webbrowser
from typing import Any
from flask import Flask, Response, jsonify, request
from werkzeug.serving import BaseWSGIServer, WSGIRequestHandler, make_server
# WARNING: Decompyle incomplete
