"""Mac launcher overrides for the recovered web GUI."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import runtime as _runtime


APP_DIR = Path(__file__).resolve().parent.parent
BUSINESS_DIR = APP_DIR / "business_pyc"
ORIGINAL_WEB_GUI = BUSINESS_DIR / "web_gui.pyc"


def _manual_disabled(*args, **kwargs):
    raise _runtime.MailboxPoolError("手动邮箱验证码功能已禁用")


_runtime.ImporterConfigStore.save_manual_pool_text = _manual_disabled
_runtime.EmailAuthImporter.submit_manual_code = _manual_disabled

_spec = importlib.util.spec_from_file_location("_gptphone_original_web_gui", ORIGINAL_WEB_GUI)
if _spec is None or _spec.loader is None:
    raise ImportError(f"Cannot load original web_gui from {ORIGINAL_WEB_GUI}")

_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)

_module._MANUAL_EMAIL_INJECT = ""
_module._LOGIN_FORM_USABILITY_INJECT += r"""
<style>
:root{color-scheme:light!important;background:#f5f7fb!important;color:#172033!important}
body{background:#f5f7fb!important;color:#172033!important}
.top{background:#ffffff!important;border-bottom-color:#d7deea!important;box-shadow:0 1px 2px rgba(16,24,40,.06)!important}
.top h1{color:#172033!important}.top span{color:#60708a!important;border-left-color:#d7deea!important}
.panel{background:#ffffff!important;border-color:#d7deea!important;box-shadow:0 8px 24px rgba(16,24,40,.08)!important}
.panel h2{color:#172033!important}.section{border-top-color:#e3e8f2!important}
.field label{color:#465872!important}
input,select,textarea,.field input,.field select,.field textarea{background:#ffffff!important;color:#172033!important;border-color:#c6d0df!important;box-shadow:inset 0 1px 1px rgba(16,24,40,.04)!important}
input::placeholder,textarea::placeholder{color:#92a0b4!important}
.checks label,.hint,.sms-mode-hint,.automatic-count-hint,.status{color:#60708a!important}
button{background:#eef3fb!important;color:#172033!important;border-color:#b8c5d8!important}
button:hover:not(:disabled){background:#e4ecf8!important;border-color:#8eacd2!important}
button.primary{background:#1f73d8!important;border-color:#1f73d8!important;color:#ffffff!important}
button.warn{background:#fff3e8!important;border-color:#f0b780!important;color:#7a3e07!important}
.metric,.tasks{background:#f8fafd!important;border-color:#d7deea!important}
.metric span{color:#60708a!important}.metric b{color:#172033!important}
.task{border-bottom-color:#e5eaf3!important}.task-account{color:#172033!important}
.log{background:#fbfcff!important;color:#172033!important;border-color:#d7deea!important}
.line{border-bottom-color:#e5eaf3!important}.time{color:#6b7d98!important}
.ok,.success{color:#178a54!important}.failed,.error{color:#c93545!important}.repair_pending,.warn{color:#a86613!important}.info{color:#416f9d!important}
#sub2_url[readonly],
#sub2_email[readonly],
#sub2_password[readonly],
#sub2_group[readonly],
#sms_api_key[readonly] {
  opacity: .82;
  cursor: not-allowed;
}
</style>
<script>
(()=>{
  const SUB2_URL = "http://39.106.173.33:8080/";
  const SUB2_EMAIL = "admin@sub2api.local";
  const SUB2_PASSWORD = "7ZdieFkNOe8K5ilM4Tzd4x";
  const SUB2_GROUP = "自动化接码分组";
  const SMS_API_KEY = "YSCqaPKnXepkGFk0q4TwCcr4gMO9Y0lm";
  const PROXY_DEFAULT = "http://127.0.0.1:7897";
  const MAX_PRICE_DEFAULT = "0.08";
  const setLocked = (id, value, password=false) => {
    const input = g(id);
    if (!input) return;
    input.value = value;
    input.readOnly = true;
    input.autocomplete = "off";
    if (password) input.type = "password";
    input.title = "已写死为默认值";
  };
  const applyHardwiredDefaults = () => {
    setLocked("sub2_url", SUB2_URL);
    setLocked("sub2_email", SUB2_EMAIL);
    setLocked("sub2_password", SUB2_PASSWORD, true);
    setLocked("sub2_group", SUB2_GROUP);
    setLocked("sms_api_key", SMS_API_KEY, true);
    const proxyInput = g("proxy");
    if (proxyInput && !proxyInput.value.trim()) {
      proxyInput.value = PROXY_DEFAULT;
    }
    const maxPriceInput = g("max_price");
    if (maxPriceInput && !maxPriceInput.value.trim()) {
      maxPriceInput.value = MAX_PRICE_DEFAULT;
    }
  };
  const baseCfg = cfg;
  cfg = function(){
    const data = baseCfg();
    data.sms_api_key = SMS_API_KEY;
    data.sub2api = Object.assign({}, data.sub2api || {}, {
      url: SUB2_URL,
      email: SUB2_EMAIL,
      password: SUB2_PASSWORD,
      group: SUB2_GROUP
    });
    data.email_mode = "auto";
    delete data.manual_pool_content;
    return data;
  };
  const baseLoad = load;
  load = function(data){
    const patched = Object.assign({}, data || {});
    patched.sms_api_key = SMS_API_KEY;
    patched.email_mode = "auto";
    if (!patched.proxy) patched.proxy = PROXY_DEFAULT;
    if (!patched.max_price) patched.max_price = MAX_PRICE_DEFAULT;
    patched.sub2api = Object.assign({}, patched.sub2api || {}, {
      url: SUB2_URL,
      email: SUB2_EMAIL,
      password: SUB2_PASSWORD,
      group: SUB2_GROUP
    });
    baseLoad(patched);
    applyHardwiredDefaults();
  };
  applyHardwiredDefaults();
  setTimeout(applyHardwiredDefaults, 0);
  setTimeout(applyHardwiredDefaults, 500);
  const updateGptmailVisibility = () => {
    const checkbox = g("gptmail_enabled");
    const section = checkbox && checkbox.closest(".gptmail-section");
    if (!section) return;
    const enabled = checkbox.checked;
    section.querySelectorAll(".field,.hint").forEach(node => {
      node.style.display = enabled ? "" : "none";
    });
  };
  const bindGptmailVisibility = () => {
    const checkbox = g("gptmail_enabled");
    if (!checkbox || checkbox.dataset.visibilityBound === "1") return;
    checkbox.dataset.visibilityBound = "1";
    checkbox.addEventListener("change", updateGptmailVisibility);
    updateGptmailVisibility();
  };
  bindGptmailVisibility();
  setTimeout(bindGptmailVisibility, 0);
  setTimeout(bindGptmailVisibility, 500);
  setInterval(() => {
    bindGptmailVisibility();
    updateGptmailVisibility();
  }, 1000);
  const visibilityBaseLoad = load;
  load = function(data){
    visibilityBaseLoad(data);
    bindGptmailVisibility();
    updateGptmailVisibility();
  };
  window.preflight = async function(){
    try {
      const content = v("pool_content");
      if (content) {
        await req("/api/pool/import", {pool_content: content});
      }
      await req("/api/preflight", cfg());
      alert("预检通过");
    } catch(e) {
      msg(e);
    }
  };
  window.startRun = async function(){
    try {
      const content = v("pool_content");
      if (content) {
        await req("/api/pool/import", {pool_content: content});
      }
      await req("/api/start", cfg());
    } catch(e) {
      msg(e);
    }
  };
})();
</script>
"""

for _name in dir(_module):
    if _name.startswith("__") and _name not in {"__doc__", "__all__"}:
        continue
    globals()[_name] = getattr(_module, _name)

__doc__ = _module.__doc__
__all__ = [name for name in globals() if not name.startswith("_")]
