from __future__ import annotations

from types import SimpleNamespace
import unittest

from mac_overrides.legacy_ui import MAILBOX_MANAGER_HTML, apply_legacy_ui_overrides


class LegacyUiTests(unittest.TestCase):
    def test_mailbox_manager_has_no_manual_code_column_or_action(self):
        self.assertNotIn("最新验证码", MAILBOX_MANAGER_HTML)
        self.assertNotIn("查码", MAILBOX_MANAGER_HTML)
        self.assertNotIn("latestCodes", MAILBOX_MANAGER_HTML)
        self.assertIn("URL 邮箱：邮箱---https://接码地址", MAILBOX_MANAGER_HTML)

    def test_applies_legacy_dashboard_overrides_with_injected_defaults(self):
        header = (
            '<header class="top"><h1>plus绑号码脚本</h1>'
            '<span>独立运行 · 邮箱优先 Auth · SMS 智能选号 · SUB2 严格分组</span></header>'
        )
        mailbox_import = (
            '<section class="panel"><h2>自建邮箱池</h2><div class="field">'
            '<label>批量粘贴（每行：邮箱----邮箱取码地址）</label>'
            '<textarea id="pool_content" placeholder="user@example.test----https://mail.example.test/show/opaque">'
            '</textarea></div><div class="actions"><button onclick="importPool()">导入邮箱池</button></div>'
            '<div class="hint">池文件、接口地址和状态均仅保存在本工具的 data 目录，不写入主项目配置。</div>'
            '<div class="section"><h2>SMS 接码</h2>'
        )
        module = SimpleNamespace(
            _HTML=(
                header
                + mailbox_import
                + 'SMS API Key / 本地号码池文件路径'
                + '<option value="localpool">本地号码池</option>'
                + '<label>管理密码</label><input id="sub2_password">'
            ),
            _LOGIN_FORM_USABILITY_INJECT="if(input){input.type='text';input.autocomplete='off'}",
        )

        apply_legacy_ui_overrides(
            module,
            min_price_default="0.02",
            max_price_default="0.07",
            priority_countries_text="9,8",
        )

        self.assertNotIn("plus绑号码脚本", module._HTML)
        self.assertIn('textarea id="pool_content" style="display:none"', module._HTML)
        self.assertNotIn('option value="localpool"', module._HTML)
        self.assertIn('id="sub2_password" type="password"', module._HTML)
        self.assertIn("input.type='password'", module._LOGIN_FORM_USABILITY_INJECT)
        self.assertIn('const MAX_PRICE_DEFAULT = "0.07";', module._LOGIN_FORM_USABILITY_INJECT)
        self.assertIn('const MIN_PRICE_DEFAULT = "0.02";', module._LOGIN_FORM_USABILITY_INJECT)
        self.assertIn('const SMS_PRIORITY_COUNTRIES = ["9", "8"]', module._LOGIN_FORM_USABILITY_INJECT)
        self.assertNotIn("nvtoken", module._LOGIN_FORM_USABILITY_INJECT.lower())
        self.assertNotIn("拖选任意日志行会自动暂停", module._LOGIN_FORM_USABILITY_INJECT)
        self.assertNotIn('toggle.textContent.includes("暂停")', module._LOGIN_FORM_USABILITY_INJECT)


if __name__ == "__main__":
    unittest.main()
