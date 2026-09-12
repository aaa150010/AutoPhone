"""Contract tests for the SPA Vite-redirect URL rewriting."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace, ModuleType
import tempfile
import unittest

from flask import Flask, request as flask_request, send_from_directory

try:
    import mac_overrides.web_routes_sections as web_routes_sections
    from mac_overrides.web_routes_sections import _vite_redirect_target
except ImportError:
    import web_routes_sections as web_routes_sections  # type: ignore[no-redef]
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


class _FakeSocketNamespace:
    """Standalone replacement for the module's ``socket`` import."""

    def __init__(self, *, alive: bool):
        self._alive = alive

    def create_connection(self, address, timeout=None):  # noqa: ANN001
        if not self._alive:
            raise OSError("connection refused")
        import socket as real_socket

        return real_socket.socket()


def _build_spa_app(tmp_dir: Path) -> Flask:
    dist = tmp_dir / "frontend" / "dist"
    dist.mkdir(parents=True, exist_ok=True)
    (dist / "index.html").write_text("<html>dist-index</html>", encoding="utf-8")
    module = ModuleType("fake_original_web_gui")
    # The recovered module re-exports Flask's request proxy, which spa_index
    # resolves at call time inside a request context.
    module.request = flask_request
    context = SimpleNamespace(
        failure_secrets=None,
        run_batch_manifest=None,
        write_local_config=lambda *args, **kwargs: None,
        local_config_from_runtime=lambda *args, **kwargs: {},
        read_local_config=lambda: {},
        configure_sms_pool=lambda *args, **kwargs: None,
        app_dir=tmp_dir,
        send_from_directory=send_from_directory,
    )
    app = Flask(__name__)
    scope = web_routes_sections.RouteScope(
        host=None, module=module, context=context, app=app,
        importer=None, logs=None, settings=None, state=None, store=SimpleNamespace(load=lambda: {}),
        mailbox_admin=None, free_manager=None, free_config_store=None, diagnostic_store=None,
    )
    web_routes_sections.build_core_routes(scope, {})
    return app


class SpaIndexRedirectTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.app = _build_spa_app(Path(self._tmp.name))
        self.client = self.app.test_client()
        self._original_socket = web_routes_sections.socket

    def tearDown(self) -> None:
        web_routes_sections.socket = self._original_socket

    def _set_vite_alive(self, alive: bool) -> None:
        web_routes_sections.socket = _FakeSocketNamespace(alive=alive)

    def test_redirects_to_vite_with_path_and_query_preserved(self) -> None:
        self._set_vite_alive(alive=True)
        response = self.client.get(
            "/free-register?tab=pool",
            headers={"Host": "127.0.0.1:18777"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.headers["Location"],
            "http://127.0.0.1:5173/free-register?tab=pool",
        )

    def test_falls_back_to_dist_bundle_when_vite_is_down(self) -> None:
        self._set_vite_alive(alive=False)
        response = self.client.get("/", headers={"Host": "127.0.0.1:18777"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"dist-index", response.data)
        # The global no-cache after_request hook wins over the view's own
        # header write; it must still be a no-cache policy either way.
        self.assertIn("no-cache", response.headers.get("Cache-Control", ""))


if __name__ == "__main__":
    unittest.main()
