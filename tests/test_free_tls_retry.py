"""Focused tests for the same-session transient transport retry wrapper."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from mac_overrides.free_protocol_bootstrap import (
        _response_received,
        wrap_transport_session_retry,
    )
    from mac_overrides.free_live_check import _wrap_session_transient_retry as wrap_live_session
except ImportError:  # pragma: no cover - direct mac_overrides execution
    from free_protocol_bootstrap import (  # type: ignore[no-redef]
        _response_received,
        wrap_transport_session_retry,
    )
    from free_live_check import _wrap_session_transient_retry as wrap_live_session  # type: ignore[no-redef]


class _TlsError(Exception):
    """Simulates curl (35) TLS handshake failure before any response."""


class _TimeoutError(Exception):
    """Simulates a connect timeout before any response."""


class _HttpError(Exception):
    """Simulates a failure that already carries an HTTP response."""

    def __init__(self, status):
        super().__init__(f"HTTP {status}")
        self.status_code = status


class _BusinessError(Exception):
    """Simulates a JSON/parse failure that must never be retried."""


class _Session:
    def __init__(self, behaviors):
        self.behaviors = list(behaviors)
        self.calls = []
        self.cookies = {"oai-did": "device"}

    def _next(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        behavior = self.behaviors.pop(0)
        if isinstance(behavior, Exception):
            raise behavior
        return behavior

    def get(self, *args, **kwargs):
        return self._next(*args, **kwargs)

    def post(self, *args, **kwargs):
        return self._next(*args, **kwargs)


class _Transport:
    def __init__(self, session):
        self.session = session


class WrapTransportSessionRetryTest(unittest.TestCase):
    def test_first_try_success_is_untouched(self):
        session = _Session(["ok"])
        transport = wrap_transport_session_retry(_Transport(session))
        self.assertIs(transport.session, session)
        self.assertEqual(transport.session.get("https://x"), "ok")
        self.assertEqual(len(session.calls), 1)

    def test_transient_failure_retries_same_session_once(self):
        session = _Session([_TlsError("curl: (35) TLS handshake"), "ok"])
        transport = wrap_transport_session_retry(_Transport(session))
        self.assertEqual(transport.session.get("https://x"), "ok")
        self.assertEqual(len(session.calls), 2)

    def test_second_failure_raises_original_error(self):
        session = _Session([_TlsError("curl: (35)"), _TimeoutError("timed out")])
        transport = wrap_transport_session_retry(_Transport(session))
        with self.assertRaises(_TimeoutError):
            transport.session.get("https://x")
        self.assertEqual(len(session.calls), 2)

    def test_response_carrying_failure_is_not_retried(self):
        session = _Session([_HttpError(403)])
        transport = wrap_transport_session_retry(_Transport(session))
        with self.assertRaises(_HttpError):
            transport.session.get("https://x")
        self.assertEqual(len(session.calls), 1)

    def test_business_failure_is_not_retried(self):
        session = _Session([_BusinessError("bad json")])
        transport = wrap_transport_session_retry(_Transport(session))
        with self.assertRaises(_BusinessError):
            transport.session.get("https://x")
        self.assertEqual(len(session.calls), 1)

    def test_post_is_wrapped_too(self):
        session = _Session([_TlsError("reset"), "ok"])
        transport = wrap_transport_session_retry(_Transport(session))
        self.assertEqual(transport.session.post("https://x", data={}), "ok")
        self.assertEqual(len(session.calls), 2)

    def test_kwargs_are_forwarded(self):
        session = _Session([_TlsError("tls"), "ok"])
        transport = wrap_transport_session_retry(_Transport(session))
        transport.session.get("https://x", headers={"a": "b"}, timeout=20)
        self.assertEqual(session.calls[0][1], {"headers": {"a": "b"}, "timeout": 20})
        self.assertEqual(session.calls[1][1], {"headers": {"a": "b"}, "timeout": 20})

    def test_missing_session_is_noop(self):
        transport = wrap_transport_session_retry(_Transport(None))
        self.assertIsNone(transport.session)

    def test_response_received_classifier(self):
        self.assertTrue(_response_received(_HttpError(403)))
        self.assertFalse(_response_received(_TlsError("curl: (35)")))
        self.assertFalse(_response_received(Exception("plain")))


class LiveCheckSessionRetryTest(unittest.TestCase):
    def test_live_session_wrapper_retries_transient(self):
        session = _Session([_TlsError("curl: (35) TLS"), "ok"])
        wrap_live_session(session)
        self.assertEqual(session.get("https://x"), "ok")
        self.assertEqual(len(session.calls), 2)

    def test_live_session_wrapper_skips_http_failures(self):
        session = _Session([_HttpError(403)])
        wrap_live_session(session)
        with self.assertRaises(_HttpError):
            session.get("https://x")
        self.assertEqual(len(session.calls), 1)

    def test_double_wrap_is_noop(self):
        session = _Session(["ok"])
        wrap_live_session(session)
        original_get = session.get
        wrap_live_session(session)
        self.assertIs(session.get, original_get)


if __name__ == "__main__":
    unittest.main()
