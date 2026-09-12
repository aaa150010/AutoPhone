"""Contract tests for the SPA Vite-redirect URL rewriting."""

from __future__ import annotations

import unittest

try:
    from mac_overrides.web_routes_sections import _vite_redirect_target
except ImportError:
    from web_routes_sections import _vite_redirect_target  # type: ignore[no-redef]


class ViteRedirectTargetTests(unittest.TestCase):
    def test_rewrites_the_request_port_onto_the_vite_origin(self) -> None:
        self.assertEqual(
            _vite_redirect_target("http://127.0.0.1:18777/free-register?tab=pool"),
            "http://127.0.0.1:5173/free-register?tab=pool",
        )
        self.assertEqual(
            _vite_redirect_target("http://localhost:18777/"),
            "http://localhost:5173/",
        )

    def test_keeps_urls_without_an_explicit_port(self) -> None:
        # A default-port origin has no ":<port>/" substring to replace; the
        # caller falls back to serving the built bundle unchanged.
        self.assertEqual(
            _vite_redirect_target("https://gptphone.example.test/free-register"),
            "https://gptphone.example.test/free-register",
        )

    def test_survives_a_malformed_port_without_raising(self) -> None:
        self.assertEqual(
            _vite_redirect_target("http://127.0.0.1:99999/free-register"),
            "http://127.0.0.1:99999/free-register",
        )

    def test_rewrites_ipv6_origins_with_an_explicit_port(self) -> None:
        self.assertEqual(
            _vite_redirect_target("http://[::1]:18777/"),
            "http://[::1]:5173/",
        )


if __name__ == "__main__":
    unittest.main()
