from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


class SmsProviderContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        business_dir = root / "business_pyc"
        cls._business_path = str(business_dir)
        sys.path.insert(0, cls._business_path)
        spec = importlib.util.spec_from_file_location(
            "_sms_provider_contracts",
            business_dir / "sms_providers.pyc",
        )
        if spec is None or spec.loader is None:
            raise ImportError("cannot load recovered SMS providers")
        cls.providers = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.providers)

    @classmethod
    def tearDownClass(cls):
        try:
            sys.path.remove(cls._business_path)
        except ValueError:
            pass

    def test_official_base_urls_and_fivesim_bearer_auth(self):
        providers = self.providers
        self.assertEqual(
            providers.SmsBowerProvider.BASE_URL,
            "https://smsbower.page/stubs/handler_api.php",
        )
        self.assertEqual(
            providers.HeroSmsProvider.BASE_URL,
            "https://hero-sms.com/stubs/handler_api.php",
        )
        self.assertEqual(providers.FiveSimProvider.BASE_URL, "https://5sim.net/v1")
        self.assertEqual(
            providers.FiveSimProvider("five-key")._headers(),
            {"Authorization": "Bearer five-key", "Accept": "application/json"},
        )
        self.assertEqual(providers.FiveSimProvider.SERVICE_MAP["dr"], "openai")

    def test_handler_api_status_contract_for_bower_and_hero(self):
        for provider_class in (
            self.providers.SmsBowerProvider,
            self.providers.HeroSmsProvider,
        ):
            calls = []
            provider = provider_class("test-key")
            provider.activation_id = "order-12"
            provider._api = lambda params: calls.append(dict(params)) or "ACCESS_READY"

            provider.set_ready()
            provider.complete()
            provider.cancel()

            self.assertEqual(
                calls,
                [
                    {"action": "setStatus", "status": "1", "id": "order-12"},
                    {"action": "setStatus", "status": "6", "id": "order-12"},
                    {"action": "setStatus", "status": "8", "id": "order-12"},
                ],
            )

    def test_fivesim_activation_and_terminal_paths(self):
        calls = []
        provider = self.providers.FiveSimProvider("five-key")

        def rest_get(path, *args, **kwargs):
            del args, kwargs
            calls.append(path)
            if path == "/guest/products/usa/any":
                return {"openai": {"Price": 0.04, "Qty": 2}}
            if path == "/user/buy/activation/usa/any/openai":
                return {"id": 21, "phone": "+15550001111"}
            return {}

        provider._rest_get = rest_get
        activation_id, phone = provider.get_number(
            service="dr",
            country="1",
            provider_ids="any",
            max_price="0.1",
        )
        provider.complete()
        provider.cancel()

        self.assertEqual((activation_id, phone), ("21", "+15550001111"))
        self.assertEqual(
            calls,
            [
                "/guest/products/usa/any",
                "/user/buy/activation/usa/any/openai",
                "/user/finish/21",
                "/user/cancel/21",
            ],
        )


if __name__ == "__main__":
    unittest.main()
