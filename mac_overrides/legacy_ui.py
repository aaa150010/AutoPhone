"""Legacy recovered-dashboard compatibility overrides."""

from __future__ import annotations

import html
import json
import textwrap
from typing import Any


MAILBOX_MANAGER_HTML = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>邮箱管理 - gptPhone</title>
<style>
:root{font-family:Arial,"Microsoft YaHei",sans-serif;background:#f5f7fb;color:#172033}*{box-sizing:border-box}html,body{height:100%;overflow:hidden}body{margin:0}.shell{height:100vh;max-width:none;margin:0;padding:10px;display:grid;grid-template-columns:390px minmax(0,1fr);gap:10px;overflow:hidden}.panel{min-height:0;background:#fff;border:1px solid #d7deea;border-radius:8px;padding:12px;box-shadow:0 8px 24px rgba(16,24,40,.08)}.shell>.panel{height:100%;overflow:auto}.shell>.panel:nth-child(2){display:flex;flex-direction:column;overflow:hidden}h2{font-size:15px;margin:0 0 10px}.field label{display:block;color:#465872;font-size:12px;margin-bottom:6px}textarea{width:100%;min-height:260px;resize:vertical;border:1px solid #c6d0df;border-radius:6px;padding:9px;background:#fff;color:#172033;font-family:Consolas,monospace;font-size:13px;line-height:1.45}button{height:32px;padding:0 11px;border:1px solid #b8c5d8;border-radius:6px;background:#eef3fb;color:#172033;font-weight:700;cursor:pointer}button:disabled{opacity:.45;cursor:not-allowed}button.primary{background:#1f73d8;border-color:#1f73d8;color:#fff}button.danger{background:#fff0f0;border-color:#f2b8b8;color:#b42318}.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}.hint{font-size:12px;color:#60708a;line-height:1.5;margin-top:9px}.metrics{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin-bottom:10px}.metric{border:1px solid #d7deea;border-radius:7px;background:#f8fafd;padding:9px}.metric span{display:block;color:#60708a;font-size:11px}.metric b{display:block;font-size:20px;margin-top:4px}.pager{display:flex;align-items:center;justify-content:space-between;gap:10px;margin:8px 0 0;color:#60708a;font-size:12px}.pager-controls{display:flex;align-items:center;gap:8px}.pager select,.bulk-actions select{height:30px;border:1px solid #c6d0df;border-radius:6px;background:#fff;color:#172033}.bulk-actions{display:flex;align-items:center;gap:8px;margin:0 0 8px}.table{flex:1;min-height:0;border:1px solid #d7deea;border-radius:8px;overflow:auto}.row{display:grid;grid-template-columns:34px 54px minmax(220px,1fr) minmax(150px,.58fr) minmax(210px,.9fr) 108px minmax(240px,1.08fr);gap:10px;padding:10px;border-bottom:1px solid #e5eaf3;font-size:12px;align-items:start}.row.head{position:sticky;top:0;background:#f8fafd;font-weight:700;color:#465872;z-index:1}.row input[type=checkbox]{width:16px;height:16px}.email,.password,.code{font-family:Consolas,monospace;word-break:break-all}.code-box{display:flex;gap:6px;align-items:flex-start;flex-wrap:nowrap;min-width:0}.code-box .muted{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.code-box button{height:25px;padding:0 8px;font-size:12px;flex:0 0 auto}.copy-cell{cursor:pointer;color:#174ea6;text-decoration:underline;text-decoration-color:rgba(23,78,166,.25);text-underline-offset:2px}.copy-cell:hover{color:#0b57d0;text-decoration-color:#0b57d0}.muted{color:#7a8798}.reason{color:#465872;word-break:break-word}.status{font-weight:700}.status.available{color:#416f9d}.status.running{color:#a86613}.status.success{color:#178a54}.status.failed{color:#c93545}.toast-host{position:fixed;left:50%;top:18px;z-index:9999;display:flex;flex-direction:column;align-items:center;gap:10px;width:min(520px,calc(100vw - 28px));pointer-events:none;transform:translateX(-50%)}.toast{pointer-events:auto;border:1px solid #dcdfe6;border-radius:4px;background:#f4f4f5;color:#303133;box-shadow:0 6px 18px rgba(31,45,61,.14);padding:10px 14px;font-size:14px}.toast.success{background:#f0f9eb;border-color:#e1f3d8;color:#67c23a}.toast.error{background:#fef0f0;border-color:#fde2e2;color:#f56c6c}.toast.warning{background:#fdf6ec;border-color:#faecd8;color:#e6a23c}@media(max-width:980px){html,body{overflow:auto}.shell{height:auto;min-height:100vh;grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}.table{height:560px;flex:none}.row{grid-template-columns:34px 44px 1fr}.row>div:nth-child(n+4){grid-column:3}}
</style></head><body>
<main class="shell"><section class="panel"><h2>批量追加导入</h2><div class="field"><label>支持 TOTP 与 Outlook OAuth 格式，每行一个账号</label><textarea id="pool_content" placeholder="TOTP：GPT账号---登录密码---Base32 2FA密钥&#10;TOTP：GPT账号|登录密码|Base32 2FA密钥&#10;OAuth：邮箱----密码----client_id----refresh_token&#10;&#10;TOTP 还支持 -- / ----、Tab、逗号、分号、冒号及全角符号"></textarea></div><div class="actions"><button class="primary" onclick="appendMailboxes()">追加导入</button><button onclick="refreshMailboxes()">刷新状态</button></div><div class="hint">每行一个账号；导入会追加到现有邮箱池，不会覆盖旧邮箱；完全重复的行会跳过。</div></section>
<section class="panel"><h2>邮箱状态</h2><div class="metrics"><div class="metric"><span>总数</span><b id="m_total">0</b></div><div class="metric"><span>可领取</span><b id="m_available">0</b></div><div class="metric"><span>运行中</span><b id="m_running">0</b></div><div class="metric"><span>成功</span><b id="m_success">0</b></div><div class="metric"><span>失败</span><b id="m_failed">0</b></div></div><div class="bulk-actions"><select id="status_filter" onchange="setStatusFilter()"><option value="all">全部</option><option value="not_success">未成功</option><option value="available">可领取</option><option value="running">运行中</option><option value="success">成功</option><option value="failed">失败</option></select><button onclick="restoreSelected()">放回可领取</button><button class="danger" onclick="deleteSelected()">删除选中</button></div><div class="table" id="mailbox_table"></div><div class="pager"><span id="page_info">第 1 / 1 页 · 共 0 条 · 已选 0 条</span><div class="pager-controls"><span>每页</span><select id="page_size" onchange="setPageSize()"><option>25</option><option selected>50</option><option>100</option><option>200</option></select><button onclick="prevPage()">上一页</button><button onclick="nextPage()">下一页</button></div></div></section></main>
<script>
const g=id=>document.getElementById(id);
function toast(message,type="info"){let host=document.querySelector(".toast-host");if(!host){host=document.createElement("div");host.className="toast-host";document.body.appendChild(host)}const item=document.createElement("div");item.className="toast "+type;item.textContent=String(message||"");host.appendChild(item);setTimeout(()=>item.remove(),type==="error"?6500:3000)}
function esc(x){let d=document.createElement("div");d.textContent=x||"";return d.innerHTML}
async function api(path,body){const options=body?{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)}:{};const r=await fetch(path,options);const j=await r.json();if(!r.ok||!j.ok)throw Error(j.error||"操作失败");return j}
async function copyText(value,label){const text=String(value||"");if(!text||text==="-"){toast(`${label}为空`,"warning");return}try{if(navigator.clipboard&&window.isSecureContext){await navigator.clipboard.writeText(text)}else{const t=document.createElement("textarea");t.value=text;t.style.position="fixed";t.style.left="-9999px";document.body.appendChild(t);t.focus();t.select();document.execCommand("copy");t.remove()}toast(`已复制${label}`,"success")}catch(e){toast(`复制失败：${e.message||e}`,"error")}}
let mailboxRows=[];let page=1;let pageSize=50;let statusFilter="all";let selected=new Set();let latestCodes={};let checkingCodes=new Set();
function render(data){const c=data.counts||{};["total","available","running","success","failed"].forEach(k=>g("m_"+k).textContent=c[k]||0);mailboxRows=data.rows||[];renderPage()}
function codeCell(row){const item=latestCodes[row.line_no]||{};const busy=checkingCodes.has(row.line_no);const code=item.code||"";const text=busy?"查询中...":(code||item.message||"未查询");const copy=code?`<span class="code copy-cell" data-label="验证码" data-copy="${esc(code)}" onclick="copyText(this.dataset.copy,this.dataset.label)">${esc(code)}</span>`:`<span class="muted">${esc(text)}</span>`;return `<div class="code-box">${copy}<button onclick="checkCode(${row.line_no})" ${busy?"disabled":""}>查码</button></div>`}
function filteredRows(){return mailboxRows.filter(row=>statusFilter==="all"||(statusFilter==="not_success"?row.status!=="success":row.status===statusFilter))}
function renderPage(){const visible=filteredRows();const total=visible.length;const totalPages=Math.max(1,Math.ceil(total/pageSize));page=Math.min(Math.max(1,page),totalPages);const start=(page-1)*pageSize;const rows=visible.slice(start,start+pageSize);g("page_info").textContent=`第 ${page} / ${totalPages} 页 · 共 ${total} 条 · 已选 ${selected.size} 条`;g("mailbox_table").innerHTML='<div class="row head"><div><input type="checkbox" onchange="togglePage(this.checked)"></div><div>#</div><div>邮箱</div><div>密码</div><div>最新验证码</div><div>状态</div><div>失败原因/说明</div></div>'+rows.map(row=>`<div class="row"><div><input type="checkbox" ${selected.has(row.line_no)?"checked":""} onchange="toggleOne(${row.line_no},this.checked)"></div><div>${row.line_no}</div><div class="email copy-cell" title="点击复制邮箱" data-label="邮箱" data-copy="${esc(row.email||"")}" onclick="copyText(this.dataset.copy,this.dataset.label)">${esc(row.email||"-")}</div><div class="password copy-cell" title="点击复制密码" data-label="密码" data-copy="${esc(row.password||"")}" onclick="copyText(this.dataset.copy,this.dataset.label)">${esc(row.password||"-")}</div>${codeCell(row)}<div class="status ${esc(row.status)}">${esc(row.status_label||"-")}</div><div class="reason">${esc(row.error||row.reason||"-")}</div></div>`).join("")}
async function checkCode(lineNo){try{checkingCodes.add(lineNo);renderPage();const j=await api("/api/mailboxes/latest-code",{line_no:lineNo});latestCodes[lineNo]=j;toast(j.message||"查询完成",j.code?"success":"warning")}catch(e){latestCodes[lineNo]={message:e.message||"查询失败"};toast(e.message,"error")}finally{checkingCodes.delete(lineNo);renderPage()}}
function toggleOne(lineNo,checked){if(checked)selected.add(lineNo);else selected.delete(lineNo);renderPage()}
function togglePage(checked){const start=(page-1)*pageSize;filteredRows().slice(start,start+pageSize).forEach(row=>checked?selected.add(row.line_no):selected.delete(row.line_no));renderPage()}
function setStatusFilter(){statusFilter=g("status_filter").value||"all";page=1;renderPage()}
function setPageSize(){pageSize=Number(g("page_size").value||50);page=1;renderPage()}
function prevPage(){page-=1;renderPage()}
function nextPage(){page+=1;renderPage()}
async function refreshMailboxes(){try{render(await api("/api/mailboxes"))}catch(e){toast(e.message,"error")}}
async function appendMailboxes(){try{const content=g("pool_content").value.trim();const j=await api("/api/mailboxes/import",{pool_content:content});g("pool_content").value="";toast(`已追加 ${j.imported||0} 条，跳过 ${j.skipped||0} 条`,"success");localStorage.setItem("gptphone_mailboxes_changed",String(Date.now()));render(j.mailboxes)}catch(e){toast(e.message,"error")}}
async function deleteSelected(){try{if(!selected.size){toast("请先勾选要删除的邮箱","warning");return}if(!confirm(`确定删除选中的 ${selected.size} 条邮箱吗？删除后不会参与运行。`))return;const line_nos=[...selected];const j=await api("/api/mailboxes/delete",{line_nos});selected.clear();toast(`已删除 ${j.deleted||0} 条`,"success");localStorage.setItem("gptphone_mailboxes_changed",String(Date.now()));render(j.mailboxes)}catch(e){toast(e.message,"error")}}
async function restoreSelected(){try{if(!selected.size){toast("请先勾选要放回可领取的邮箱","warning");return}const line_nos=[...selected];const j=await api("/api/mailboxes/restore",{line_nos});selected.clear();toast(`已放回可领取 ${j.restored||0} 条`,"success");localStorage.setItem("gptphone_mailboxes_changed",String(Date.now()));render(j.mailboxes)}catch(e){toast(e.message,"error")}}
refreshMailboxes();setInterval(refreshMailboxes,3000);
</script></body></html>"""


def apply_legacy_ui_overrides(
    module: Any,
    *,
    min_price_default: Any,
    max_price_default: Any,
    priority_countries_text: str,
) -> None:
    """Apply the recovered dashboard's legacy HTML, CSS, and JavaScript patches."""

    _module = module
    _min_price_default = str(min_price_default)
    _max_price_default = str(max_price_default)
    _priority_countries = [
        country.strip()
        for country in str(priority_countries_text).split(",")
        if country.strip()
    ]
    _min_price_html_js = html.escape(_min_price_default, quote=True).replace("\\", "\\\\")
    _ROOT_HEADER_HTML = (
        '<header class="top"><h1>plus绑号码脚本</h1>'
        '<span>独立运行 · 邮箱优先 Auth · SMS 智能选号 · SUB2 严格分组</span></header>'
    )
    _ROOT_MAILBOX_IMPORT_HTML = (
        '<section class="panel"><h2>自建邮箱池</h2><div class="field"><label>批量粘贴（每行：邮箱----邮箱取码地址）</label>'
        '<textarea id="pool_content" placeholder="user@example.test----https://mail.example.test/show/opaque"></textarea></div>'
        '<div class="actions"><button onclick="importPool()">导入邮箱池</button></div>'
        '<div class="hint">池文件、接口地址和状态均仅保存在本工具的 data 目录，不写入主项目配置。</div>'
        '<div class="section"><h2>SMS 接码</h2>'
    )
    _ROOT_MAILBOX_MANAGER_HTML = (
        '<section class="panel"><h2>邮箱队列</h2>'
        '<textarea id="pool_content" style="display:none"></textarea>'
        '<div class="section"><h2>SMS 接码</h2>'
    )
    _module._HTML = _module._HTML.replace(_ROOT_HEADER_HTML, "")
    _module._HTML = _module._HTML.replace(_ROOT_MAILBOX_IMPORT_HTML, _ROOT_MAILBOX_MANAGER_HTML)
    _module._HTML = _module._HTML.replace("SMS API Key / 本地号码池文件路径", "SMS API Key")
    _module._HTML = _module._HTML.replace('<option value="localpool">本地号码池</option>', "")
    _module._HTML = _module._HTML.replace('<label>管理密码</label><input id="sub2_password">', '<label>管理密码</label><input id="sub2_password" type="password">')
    if isinstance(getattr(_module, "_LOGIN_FORM_USABILITY_INJECT", None), str):
        _module._LOGIN_FORM_USABILITY_INJECT = _module._LOGIN_FORM_USABILITY_INJECT.replace(
            "if(input){input.type='text';input.autocomplete='off'}",
            "if(input){input.type='password';input.autocomplete='new-password'}",
        )
    _module._LOGIN_FORM_USABILITY_INJECT += textwrap.dedent(r"""
    <style>
    .log,.log *,.line,.line *{user-select:text!important;-webkit-user-select:text!important}
    .line{cursor:text!important;white-space:pre-wrap!important}
    </style>
    <script>
    (function(){
      const installSelectableLogs = () => {
        const logBox = typeof g === "function" ? g("logs") : document.getElementById("logs");
        if (!logBox || logBox.dataset.selectableLogs === "1") return;
        logBox.dataset.selectableLogs = "1";
        logBox.setAttribute("tabindex", "0");
        logBox.style.userSelect = "text";
        logBox.style.webkitUserSelect = "text";
        logBox.addEventListener("dblclick", event => {
          const line = event.target && event.target.closest ? event.target.closest(".line") : null;
          if (!line) return;
          const selection = window.getSelection && window.getSelection();
          if (!selection) return;
          const range = document.createRange();
          range.selectNodeContents(line);
          selection.removeAllRanges();
          selection.addRange(range);
        });
      };
      installSelectableLogs();
      setTimeout(installSelectableLogs, 0);
      setTimeout(installSelectableLogs, 500);
      document.addEventListener("DOMContentLoaded", installSelectableLogs);
    })();
    </script>
    """)

    _module._MANUAL_EMAIL_INJECT = ""
    if hasattr(_module, "_GPTMAIL_INJECT"):
        _module._GPTMAIL_INJECT = ""
    for _inject_name in dir(_module):
        if not _inject_name.endswith("_INJECT"):
            continue
        _inject_value = getattr(_module, _inject_name, "")
        if isinstance(_inject_value, str) and any(
            marker in _inject_value
            for marker in ("GPTMail", "gptmail", "邮箱验证码来源", "GPTMail 收码")
        ):
            setattr(_module, _inject_name, "")
    _legacy_dashboard_inject = textwrap.dedent(r"""
    <style>
    :root{color-scheme:light!important;background:#f5f7fb!important;color:#172033!important}
    html,body{height:100%!important;overflow:hidden!important}
    body{background:#f5f7fb!important;color:#172033!important}
    .top{display:none!important;background:#ffffff!important;border-bottom-color:#d7deea!important;box-shadow:0 1px 2px rgba(16,24,40,.06)!important}
    .top h1{color:#172033!important}.top span{color:#60708a!important;border-left-color:#d7deea!important}
    .shell{height:100vh!important;max-width:none!important;margin:0!important;padding:10px!important;gap:10px!important;overflow:hidden!important}
    .panel{background:#ffffff!important;border-color:#d7deea!important;box-shadow:0 8px 24px rgba(16,24,40,.08)!important;min-height:0!important}
    .shell>section.panel{height:100%!important;overflow:auto!important}.main{height:100%!important;min-height:0!important;gap:10px!important;overflow:hidden!important;grid-template-rows:auto minmax(0,.42fr) minmax(0,1fr)!important}.main>.panel{min-height:0!important;overflow:hidden!important;display:flex!important;flex-direction:column!important}.main>.panel h2{flex:0 0 auto!important}
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
    .tasks{flex:1 1 auto!important;min-height:0!important;height:auto!important;max-height:none!important;overflow:auto!important}
    .metric span{color:#60708a!important}.metric b{color:#172033!important}
    .task{border-bottom-color:#e5eaf3!important}.task-account{color:#172033!important}
    .log{background:#fbfcff!important;color:#172033!important;border-color:#d7deea!important;flex:1 1 auto!important;min-height:0!important;height:auto!important;overflow:auto!important}
    .line{border-bottom-color:#e5eaf3!important}.time{color:#6b7d98!important}
    .ok,.success{color:#178a54!important}.failed,.error{color:#c93545!important}.repair_pending,.warn{color:#a86613!important}.info{color:#416f9d!important}
    .toast-host{position:fixed;left:50%;top:18px;z-index:9999;display:flex;flex-direction:column;align-items:center;gap:10px;width:min(520px,calc(100vw - 28px));pointer-events:none;transform:translateX(-50%)}
    .toast{pointer-events:auto;display:grid;grid-template-columns:18px 1fr;align-items:start;gap:8px;min-width:min(380px,calc(100vw - 28px));max-width:100%;border:1px solid #dcdfe6;border-radius:4px;background:#f4f4f5;color:#303133;box-shadow:0 6px 18px rgba(31,45,61,.14);padding:10px 14px;font-size:14px;line-height:1.45;white-space:pre-wrap;overflow-wrap:anywhere;animation:gptphone-message-in .18s ease-out}
    .toast-icon{font-weight:700;line-height:1.45;text-align:center}.toast-message{min-width:0}
    .toast.info{background:#edf2fc;border-color:#d9ecff;color:#409eff}.toast.success{background:#f0f9eb;border-color:#e1f3d8;color:#67c23a}.toast.error{background:#fef0f0;border-color:#fde2e2;color:#f56c6c}.toast.warning,.toast.warn{background:#fdf6ec;border-color:#faecd8;color:#e6a23c}
    @keyframes gptphone-message-in{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}
    .mailbox-link-panel{border:1px solid #d7deea;border-radius:7px;background:#f8fafd;padding:12px;margin-bottom:12px}
    .mailbox-link-panel b{display:block;color:#172033;font-size:13px;margin-bottom:5px}.mailbox-link-panel span{display:block;color:#60708a;font-size:12px;line-height:1.45;margin-bottom:10px}
    .secret-input-wrap{position:relative;display:block;width:100%}
    .secret-input-wrap>input{padding-right:42px!important}
    .secret-reveal-btn{position:absolute!important;right:5px!important;top:50%!important;transform:translateY(-50%)!important;display:flex!important;align-items:center!important;justify-content:center!important;width:32px!important;height:27px!important;min-width:0!important;padding:0!important;border:1px solid #c6d0df!important;border-radius:5px!important;background:#f8fafd!important;box-shadow:0 1px 2px rgba(16,24,40,.08)!important;color:#465872!important;font-size:15px!important;line-height:1!important;cursor:pointer!important;z-index:2!important}
    .secret-reveal-btn:hover{background:#eef3fb!important;border-color:#8eacd2!important;color:#174ea6!important}
    .secret-reveal-btn svg{width:17px!important;height:17px!important;display:block!important;stroke:currentColor!important;fill:none!important;stroke-width:2!important;stroke-linecap:round!important;stroke-linejoin:round!important;pointer-events:none!important}
    </style>
    <script>
    (()=>{
      const PROXY_DEFAULT = "http://127.0.0.1:7897";
      const MAX_PRICE_DEFAULT = "0.1";
      const MIN_PRICE_DEFAULT = "0.01";
      const SMS_PRIORITY_COUNTRIES = ["151", "37", "33", "1", "91", "55"];
      let localConfig = {};
      const SECRET_INPUT_IDS = ["sms_api_key", "sub2_password"];
      const SECRET_MASK = "********";
      const clampMaxPrice = value => {
        const parsed = Number(String(value || "").trim());
        if (!Number.isFinite(parsed) || parsed <= 0 || parsed > Number(MAX_PRICE_DEFAULT)) return MAX_PRICE_DEFAULT;
        return String(parsed);
      };
      const normalizeType = (type) => {
        const value = String(type || "info").toLowerCase();
        if (value === "warn") return "warning";
        return ["success", "warning", "error", "info"].includes(value) ? value : "info";
      };
      const messageText = (payload) => {
        if (payload && typeof payload === "object" && "message" in payload) {
          return payload.message;
        }
        if (payload && payload.message) return payload.message;
        return payload;
      };
      const showMessage = (payload, fallbackType="info") => {
        const type = normalizeType(payload && typeof payload === "object" ? payload.type || fallbackType : fallbackType);
        const message = String(messageText(payload) || "");
        let host = document.querySelector(".toast-host");
        if (!host) {
          host = document.createElement("div");
          host.className = "toast-host";
          document.body.appendChild(host);
        }
        const item = document.createElement("div");
        item.className = "toast " + type;
        const iconMap = {success: "✓", warning: "!", error: "×", info: "i"};
        const icon = document.createElement("span");
        icon.className = "toast-icon";
        icon.textContent = iconMap[type] || "i";
        const body = document.createElement("span");
        body.className = "toast-message";
        body.textContent = message;
        item.append(icon, body);
        host.appendChild(item);
        setTimeout(() => {
          item.style.opacity = "0";
          item.style.transform = "translateY(-4px)";
          item.style.transition = "opacity .18s ease, transform .18s ease";
          setTimeout(() => item.remove(), 220);
        }, type === "error" ? 6500 : 3000);
      };
      const toast = (message, type="info") => showMessage(message, type);
      window.showMessage = showMessage;
      window.toast = toast;
      window.ElMessage = function(payload){ showMessage(payload, payload && payload.type); };
      ["success", "warning", "error", "info"].forEach(type => {
        window.ElMessage[type] = (message) => showMessage(message, type);
      });
      window.alert = (message) => showMessage(message, "info");
      const eyeIcon = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
      const eyeOffIcon = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m3 3 18 18"></path><path d="M10.6 10.6A3 3 0 0 0 13.4 13.4"></path><path d="M9.9 5.2A10.7 10.7 0 0 1 12 5c6.5 0 10 7 10 7a18.6 18.6 0 0 1-3.1 4.2"></path><path d="M6.1 6.7C3.4 8.5 2 12 2 12s3.5 7 10 7a10.8 10.8 0 0 0 4.1-.8"></path></svg>';
      const friendlyError = (text) => {
        const value = String(text || "");
        if (value.includes("deleted or deactivated") || value.includes("You do not have an account")) {
          return "邮箱对应的 OpenAI 账号不可用（已删除或停用）";
        }
        if (value.includes("email_otp_failed")) {
          return "邮箱验证码提交后被 OpenAI 拒绝，请确认该邮箱对应的 OpenAI 账号是否可用";
        }
        return value;
      };
      window.msg = function(error){
        const text = friendlyError(error && error.message ? error.message : String(error || "操作失败"));
        if (text.includes("自动模式请先在邮箱池输入框粘贴本次要运行的邮箱")) {
          fetch("/api/state").then(r => r.json()).then(j => {
            const pool = (((j || {}).state || {}).runtime || {}).pool || {};
            if (Number(pool.available || 0) > 0) {
              showMessage("邮箱池已有可领取邮箱，将直接使用现有邮箱池启动", "info");
            } else {
              showMessage("邮箱池没有可领取邮箱，请先导入邮箱", "warning");
            }
          }).catch(() => showMessage("邮箱池没有可领取邮箱，请先导入邮箱", "warning"));
          return;
        }
        showMessage(text, "error");
      };
      const ensureSecretRevealControl = (input) => {
        if (!input || input.dataset.revealControl === "1") return;
        const parent = input.parentElement;
        if (!parent || !parent.classList.contains("secret-input-wrap")) {
          const wrapper = document.createElement("div");
          wrapper.className = "secret-input-wrap";
          input.insertAdjacentElement("beforebegin", wrapper);
          wrapper.appendChild(input);
        }
        const wrapper = input.parentElement;
        if (!wrapper.querySelector(".secret-reveal-btn")) {
          const button = document.createElement("button");
          button.type = "button";
          button.className = "secret-reveal-btn";
          button.innerHTML = eyeIcon;
          button.title = "显示";
          button.setAttribute("aria-label", "显示");
          button.addEventListener("click", async () => {
            if (input.dataset.revealedSecret === "1") {
              input.dataset.revealedSecret = "0";
              input.type = "password";
              if (input.dataset.savedSecret === "1") input.value = SECRET_MASK;
              button.innerHTML = eyeIcon;
              button.title = "显示";
              button.setAttribute("aria-label", "显示");
              input.focus();
              return;
            }
            let value = input.value;
            if (input.dataset.savedSecret === "1" && input.value === SECRET_MASK) {
              try {
                const response = await fetch("/api/local-config/secret", {
                  method: "POST",
                  headers: {"Content-Type": "application/json"},
                  body: JSON.stringify({id: input.id})
                });
                const payload = await response.json();
                if (!response.ok || !payload.ok) throw Error(payload.error || "读取失败");
                value = payload.value || "";
              } catch (error) {
                msg(error);
                return;
              }
            }
            input.dataset.revealedSecret = "1";
            input.type = "text";
            if (value) input.value = value;
            button.innerHTML = eyeOffIcon;
            button.title = "隐藏";
            button.setAttribute("aria-label", "隐藏");
            input.focus();
          });
          wrapper.appendChild(button);
        }
        input.dataset.revealControl = "1";
      };
      const enforceSecretInputs = () => {
        SECRET_INPUT_IDS.forEach(id => {
          const input = g(id);
          if (!input) return;
          ensureSecretRevealControl(input);
          if (input.dataset.revealedSecret !== "1") input.type = "password";
          input.autocomplete = "new-password";
          input.spellcheck = false;
          input.dataset.secretField = "1";
          if (input.dataset.secretBound !== "1") {
            input.dataset.secretBound = "1";
            input.addEventListener("input", () => {
              if (input.value !== SECRET_MASK) input.dataset.savedSecret = "0";
            });
            input.addEventListener("focus", () => {
              if (input.value === SECRET_MASK) input.select();
            });
          }
        });
      };
      const savedSecretFor = (id) => {
        if (id === "sms_api_key") return String(localConfig.sms_api_key || "");
        if (id === "sub2_password") return String(((localConfig.sub2api || {}).password) || "");
        return "";
      };
      const mergeLocalConfigFromSettings = (data) => {
        if (!data || typeof data !== "object") return;
        const sub2api = data.sub2api || {};
        localConfig = Object.assign({}, localConfig || {});
        if (data.sms_api_key) localConfig.sms_api_key = data.sms_api_key;
        localConfig.sub2api = Object.assign({}, localConfig.sub2api || {});
        ["url", "email", "group"].forEach(key => {
          if (sub2api[key]) localConfig.sub2api[key] = sub2api[key];
        });
        if (sub2api.password) localConfig.sub2api.password = sub2api.password;
      };
      const secretInputValue = (id) => {
        const input = g(id);
        if (!input) return "";
        const raw = String(input.value || "");
        if (raw === SECRET_MASK && input.dataset.savedSecret === "1") return savedSecretFor(id);
        return raw;
      };
      const maskSecretInput = (id, value, force=false) => {
        const input = g(id);
        if (!input) return;
        enforceSecretInputs();
        if (input.dataset.revealedSecret === "1") return;
        const hasSecret = String(value || "").length > 0;
        input.dataset.savedSecret = hasSecret ? "1" : "0";
        if (hasSecret) {
          if (force || !input.value || input.value === SECRET_MASK || input.dataset.savedSecret === "1") input.value = SECRET_MASK;
        } else if (force) {
          input.value = "";
        }
      };
      const setEditableValue = (id, value, password=false, force=false) => {
        const input = g(id);
        if (!input) return;
        input.readOnly = false;
        input.disabled = false;
        input.autocomplete = password ? "new-password" : "off";
        if (password) {
          maskSecretInput(id, value, force);
          input.title = "";
          return;
        }
        if (value !== undefined && value !== null && (force || !input.value)) input.value = value;
        input.title = "";
      };
      const applyLocalConfig = (force=false) => {
        const sub2api = localConfig.sub2api || {};
        setEditableValue("sms_api_key", localConfig.sms_api_key || "", true, force);
        setEditableValue("sub2_url", sub2api.url || "", false, force);
        setEditableValue("sub2_email", sub2api.email || "", false, force);
        setEditableValue("sub2_password", sub2api.password || "", true, force);
        setEditableValue("sub2_group", sub2api.group || "", false, force);
        const proxyInput = g("proxy");
        if (proxyInput && !proxyInput.value.trim()) {
          proxyInput.value = PROXY_DEFAULT;
        }
        const maxPriceInput = g("max_price");
        if (maxPriceInput) {
          maxPriceInput.value = clampMaxPrice(maxPriceInput.value);
        }
        ensureSmsMinPriceControl();
      };
      const loadLocalConfig = async () => {
        try {
          const response = await fetch("/api/local-config");
          const payload = await response.json();
          if (payload && payload.ok && payload.config) {
            localConfig = payload.config;
            applyLocalConfig(true);
          }
        } catch(e) {}
      };
      const restoreSecretPlaceholders = () => {
        ensureLocalConfigControls();
        enforceSecretInputs();
        applyLocalConfig(true);
      };
      const reloadSecretPlaceholders = async () => {
        await loadLocalConfig();
        restoreSecretPlaceholders();
      };
      const ensureLocalConfigControls = () => {
        enforceSecretInputs();
        const smsKey = g("sms_api_key");
        if (smsKey) {
          smsKey.type = "password";
          smsKey.autocomplete = "new-password";
        }
        const sub2Password = g("sub2_password");
        if (sub2Password) {
          sub2Password.type = "password";
          sub2Password.autocomplete = "new-password";
        }
        const smsField = smsKey && smsKey.closest(".field");
        if (smsField && !g("local_config_export")) {
          const actions = document.createElement("div");
          actions.className = "actions";
          actions.innerHTML = '<button id="local_config_export" type="button" onclick="exportLocalConfig()">导出本地配置</button><button id="local_config_import_btn" type="button" onclick="document.getElementById(\\'local_config_import\\').click()">导入本地配置</button><input id="local_config_import" type="file" accept="application/json,.json" style="display:none" onchange="importLocalConfig(this.files&&this.files[0])">';
          smsField.insertAdjacentElement("afterend", actions);
        }
      };
      window.exportLocalConfig = async function(){
        try {
          const data = Object.assign({}, cfg(), {download: true});
          const response = await fetch("/api/local-config/export", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(data)});
          const payload = await response.json();
          if (!response.ok || !payload.ok) throw Error(payload.error || "导出失败");
          localConfig = payload.config || {};
          applyLocalConfig(true);
          const blob = new Blob([JSON.stringify(payload.config || {}, null, 2)], {type:"application/json"});
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = "gptphone-local-config.json";
          a.click();
          URL.revokeObjectURL(url);
          showMessage("本地配置已导出", "success");
        } catch(e) { msg(e); }
      };
      window.importLocalConfig = async function(file){
        if (!file) return;
        try {
          const text = await file.text();
          const config = JSON.parse(text);
          const response = await fetch("/api/local-config/import", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({config})});
          const payload = await response.json();
          if (!response.ok || !payload.ok) throw Error(payload.error || "导入失败");
          localConfig = payload.config || {};
          applyLocalConfig(true);
          showMessage("本地配置已导入", "success");
        } catch(e) { msg(e); }
      };
      const ensureSmsMinPriceControl = () => {
        if (g("sms_min_price")) return;
        const maxPriceInput = g("max_price");
        const maxPriceField = maxPriceInput && maxPriceInput.closest(".field");
        if (!maxPriceField || !maxPriceField.parentNode) return;
        const minPriceField = document.createElement("div");
        minPriceField.className = "field";
        minPriceField.innerHTML = '<label>最低价格</label><input id="sms_min_price" inputmode="decimal" placeholder="0.01" value="' + MIN_PRICE_DEFAULT + '">';
        maxPriceField.insertAdjacentElement("beforebegin", minPriceField);
      };
      const replaceRootMailboxImport = () => {
        const input = g("pool_content");
        if (!input || input.dataset.rootMailboxReplaced === "1") return;
        input.dataset.rootMailboxReplaced = "1";
        const field = input.closest(".field");
        if (!field) return;
        const actions = field && field.nextElementSibling;
        const hint = actions && actions.nextElementSibling;
        const title = field && field.parentNode && field.parentNode.querySelector("h2");
        if (title) title.textContent = "邮箱队列";
        if (field) field.style.display = "none";
        if (actions) actions.style.display = "none";
        if (hint) hint.style.display = "none";
      };
      const baseCfg = cfg;
      cfg = function(){
        const data = baseCfg();
        data.concurrency = String(data.concurrency || "5");
        data.node_concurrency = String(data.node_concurrency || "5");
        data.sms_api_key = String(secretInputValue("sms_api_key").trim() || data.sms_api_key || "");
        data.max_price = clampMaxPrice(data.max_price);
        const minPriceInput = g("sms_min_price");
        data.sms_min_price = String((minPriceInput && minPriceInput.value.trim()) || data.sms_min_price || MIN_PRICE_DEFAULT);
        data.sms_mode = "smart";
        data.country = "";
        data.provider_ids = "";
        data.sms_smart = Object.assign({}, data.sms_smart || {}, {
          enabled: true,
          countries: SMS_PRIORITY_COUNTRIES.join(","),
          preferred_countries: SMS_PRIORITY_COUNTRIES.join(",")
        });
        data.sub2api = Object.assign({}, data.sub2api || {}, {
          url: String((g("sub2_url") && g("sub2_url").value.trim()) || ""),
          email: String((g("sub2_email") && g("sub2_email").value.trim()) || ""),
          password: String(secretInputValue("sub2_password") || ""),
          group: String((g("sub2_group") && g("sub2_group").value.trim()) || "")
        });
        data.email_mode = "auto";
        delete data.manual_pool_content;
        return data;
      };
      const baseLoad = load;
      load = function(data){
        const patched = Object.assign({}, data || {});
        mergeLocalConfigFromSettings(patched);
        patched.sms_api_key = patched.sms_api_key || localConfig.sms_api_key || "";
        patched.email_mode = "auto";
        patched.concurrency = patched.concurrency || "5";
        patched.node_concurrency = patched.node_concurrency || "5";
        if (patched.sms_provider === "localpool") patched.sms_provider = "smsbower";
        if (!patched.proxy) patched.proxy = PROXY_DEFAULT;
        patched.max_price = clampMaxPrice(patched.max_price);
        patched.sms_min_price = patched.sms_min_price || MIN_PRICE_DEFAULT;
        patched.sms_mode = "smart";
        patched.country = "";
        patched.provider_ids = "";
        patched.sms_smart = Object.assign({}, patched.sms_smart || {}, {
          enabled: true,
          countries: SMS_PRIORITY_COUNTRIES.join(","),
          preferred_countries: SMS_PRIORITY_COUNTRIES.join(",")
        });
        patched.sub2api = Object.assign({}, patched.sub2api || {}, {
          ...(localConfig.sub2api || {}),
          ...(patched.sub2api || {})
        });
        const displayPatched = Object.assign({}, patched, {
          sms_api_key: patched.sms_api_key ? SECRET_MASK : "",
          sub2api: Object.assign({}, patched.sub2api || {}, {
            password: (patched.sub2api || {}).password ? SECRET_MASK : ""
          })
        });
        baseLoad(displayPatched);
        ensureLocalConfigControls();
        enforceSecretInputs();
        ensureSmsMinPriceControl();
        applyLocalConfig();
        const minPriceInput = g("sms_min_price");
        if (minPriceInput) minPriceInput.value = patched.sms_min_price || MIN_PRICE_DEFAULT;
        applyLocalConfig();
      };
      ensureLocalConfigControls();
      enforceSecretInputs();
      ensureSmsMinPriceControl();
      loadLocalConfig();
      applyLocalConfig();
      replaceRootMailboxImport();
      setTimeout(reloadSecretPlaceholders, 0);
      setTimeout(reloadSecretPlaceholders, 500);
      setTimeout(reloadSecretPlaceholders, 1500);
      setTimeout(reloadSecretPlaceholders, 3000);
      setTimeout(applyLocalConfig, 0);
      setTimeout(applyLocalConfig, 500);
      setTimeout(ensureLocalConfigControls, 0);
      setTimeout(ensureLocalConfigControls, 500);
      setTimeout(enforceSecretInputs, 0);
      setTimeout(enforceSecretInputs, 500);
      setTimeout(ensureSmsMinPriceControl, 0);
      setTimeout(ensureSmsMinPriceControl, 500);
      setTimeout(replaceRootMailboxImport, 0);
      setTimeout(replaceRootMailboxImport, 500);
      window.addEventListener("storage", event => {
        if (event.key === "gptphone_mailboxes_changed" && typeof refresh === "function") {
          refresh();
        }
      });
      const visibilityBaseLoad = load;
      load = function(data){
        visibilityBaseLoad(data);
      };
      const baseRenderForFriendlyErrors = render;
      render = function(state){
        const logBox = g("logs");
        const keepLogScroll = logBox && (logBox.scrollTop + logBox.clientHeight < logBox.scrollHeight - 24);
        const previousLogScrollTop = keepLogScroll ? logBox.scrollTop : 0;
        const patched = JSON.parse(JSON.stringify(state || {}));
        const tasks = ((patched.runtime || {}).tasks || []);
        tasks.forEach(task => {
          const detail = task.technical_error || (task.result && (task.result.local_oauth_exchange_error || task.result.error)) || task.error;
          const friendly = friendlyError(detail);
          if (friendly) task.error = friendly;
        });
        baseRenderForFriendlyErrors(patched);
        setTimeout(restoreSecretPlaceholders, 0);
        setTimeout(enforceSecretInputs, 50);
        if (keepLogScroll && logBox) {
          logBox.scrollTop = previousLogScrollTop;
        }
      };
      window.preflight = async function(){
        try {
          const content = v("pool_content");
          if (content) {
            await req("/api/pool/import", {pool_content: content});
          }
          await req("/api/preflight", cfg());
          showMessage("预检通过", "success");
        } catch(e) {
          msg(e);
        }
      };
      window.startRun = async function(){
        try {
          const content = v("pool_content");
          const data = cfg();
          if (content) {
            data.pool_content = content;
            await req("/api/start", data);
          } else {
            const current = await (await fetch("/api/state")).json();
            const pool = (((current || {}).state || {}).runtime || {}).pool || {};
            if (Number(pool.available || 0) > 0) {
              showMessage("使用现有邮箱池启动", "info");
              await req("/api/start-existing", data);
            } else {
              showMessage("邮箱池没有可领取邮箱，请先导入邮箱", "warning");
              return;
            }
          }
          showMessage("已开始运行", "success");
        } catch(e) {
          msg(e);
        }
      };
      window.importPool = async function(){
        const content = v("pool_content");
        if (!content) {
          showMessage("邮箱池输入框为空，未导入新邮箱", "warning");
          return;
        }
        try {
          await req("/api/pool/import", {pool_content: content});
          g("pool_content").value = "";
          showMessage("邮箱池已导入", "success");
        } catch(e) {
          msg(e);
        }
      };
      window.saveConfig = async function(){
        try {
          const data = cfg();
          const saved = await req("/api/local-config/export", data);
          localConfig = saved.config || {};
          applyLocalConfig(true);
          await req("/api/config", data);
          showMessage("配置已保存", "success");
        } catch(e) {
          msg(e);
        }
      };
      window.stopRun = async function(){
        try {
          await req("/api/stop");
          showMessage("已请求安全停止", "success");
        } catch(e) {
          msg(e);
        }
      };
    })();
    </script>
    """)
    _legacy_dashboard_inject = _legacy_dashboard_inject.replace(
        'const MAX_PRICE_DEFAULT = "0.1";',
        f"const MAX_PRICE_DEFAULT = {json.dumps(_max_price_default, ensure_ascii=False)};",
    )
    _legacy_dashboard_inject = _legacy_dashboard_inject.replace(
        'const MIN_PRICE_DEFAULT = "0.01";',
        f"const MIN_PRICE_DEFAULT = {json.dumps(_min_price_default, ensure_ascii=False)};",
    )
    _legacy_dashboard_inject = _legacy_dashboard_inject.replace(
        'const SMS_PRIORITY_COUNTRIES = ["151", "37", "33", "1", "91", "55"];',
        "const SMS_PRIORITY_COUNTRIES = "
        + json.dumps(_priority_countries, ensure_ascii=False)
        + ";",
    )
    _legacy_dashboard_inject = _legacy_dashboard_inject.replace(
        'placeholder="0.01"',
        f'placeholder="{_min_price_html_js}"',
    )
    _module._LOGIN_FORM_USABILITY_INJECT += _legacy_dashboard_inject
