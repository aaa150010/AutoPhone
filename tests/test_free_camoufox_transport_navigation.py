from __future__ import annotations

import asyncio
import unittest

from mac_overrides.free_camoufox.transport import CamoufoxTransport


class _Locator:
    first = None

    def __init__(self) -> None:
        self.first = self
        self.click_kwargs: dict[str, object] | None = None
        self.press_kwargs: dict[str, object] | None = None

    async def is_visible(self, **_kwargs):
        return True

    async def is_enabled(self, **_kwargs):
        return True

    async def click(self, **kwargs):
        self.click_kwargs = dict(kwargs)

    async def press(self, key, **kwargs):
        self.press_kwargs = {"key": key, **kwargs}


class _Page:
    def __init__(self) -> None:
        self.item = _Locator()

    def locator(self, _selector: str):
        return self.item


class CamoufoxTransportNavigationTests(unittest.TestCase):
    def test_click_dispatch_does_not_wait_for_auth_navigation(self):
        page = _Page()

        async def exercise():
            return await CamoufoxTransport(page).click("#continue")

        self.assertEqual(asyncio.run(exercise()), "#continue")
        self.assertEqual(
            page.item.click_kwargs,
            {"timeout": 2500, "no_wait_after": True},
        )

    def test_enter_dispatch_does_not_wait_for_auth_navigation(self):
        page = _Page()

        async def exercise():
            return await CamoufoxTransport(page).submit("#email")

        self.assertTrue(asyncio.run(exercise()))
        self.assertEqual(
            page.item.press_kwargs,
            {"key": "Enter", "no_wait_after": True},
        )


if __name__ == "__main__":
    unittest.main()
