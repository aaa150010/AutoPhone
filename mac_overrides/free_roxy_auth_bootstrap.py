"""Credential-safe browser bootstrap for a stalled Roxy login form."""

from __future__ import annotations

from typing import Any, Mapping
from urllib.parse import urlsplit
import uuid

try:
    from .free_register_common import clean
except ImportError:
    from free_register_common import clean  # type: ignore[no-redef]


def submit_email_via_browser_nextauth(
    driver: Any,
    email: str,
    timeout: int,
) -> dict[str, Any]:
    """Start the reference NextAuth flow inside the current Roxy profile.

    AutoRegister keeps this path for the ``/auth/login?email=`` state where
    the visible form submits but the SPA never opens Auth. The browser owns
    the cookies and navigation; Python receives only bounded transport
    metadata, never the response body or authorization URL.
    """
    try:
        parsed = urlsplit(str(getattr(driver, "current_url", "") or ""))
    except Exception:
        parsed = urlsplit("")
    host = (parsed.hostname or "").casefold().rstrip(".")
    if parsed.scheme.casefold() != "https" or not (
        host == "chatgpt.com" or host.endswith(".chatgpt.com")
    ):
        return {"ok": False, "stage": "origin", "reason": "not_on_chatgpt"}

    # AutoRegister gives the in-profile CSRF/sign-in exchange a 25 second
    # Selenium script budget.  A shorter budget turns a slow but valid proxy
    # response into a false transport failure while the SPA is still loading.
    script_timeout = 25
    try:
        driver.set_script_timeout(script_timeout)
    except Exception:
        pass
    try:
        result = driver.execute_async_script(r"""
          /* __gptphone_browser_nextauth__ */
          const email = String(arguments[0] || '').trim();
          const did = String(arguments[1] || '');
          const authLogId = String(arguments[2] || '');
          const done = arguments[arguments.length - 1];
          const controller = new AbortController();
          const abortTimer = setTimeout(() => controller.abort(), 22000);
          const finish = value => { clearTimeout(abortTimer); done(value); };
          (async () => {
            try {
              const csrfResp = await fetch('/api/auth/csrf', {
                method: 'GET', credentials: 'include', signal: controller.signal,
                headers: {accept:'application/json', 'cache-control':'no-cache', pragma:'no-cache'}
              });
              let csrfData = {};
              try { csrfData = await csrfResp.json(); } catch (_) {}
              const csrfToken = String(csrfData.csrfToken || '');
              if (!csrfResp.ok || !csrfToken) {
                finish({ok:false, stage:'csrf', status:csrfResp.status});
                return;
              }

              const query = new URLSearchParams({
                prompt:'login', 'ext-oai-did':did,
                auth_session_logging_id:authLogId,
                'ext-passkey-client-capabilities':'11111',
                screen_hint:'login_or_signup', login_hint:email
              });
              const form = new URLSearchParams({
                callbackUrl:'https://chatgpt.com/', csrfToken, json:'true'
              });
              const response = await fetch('/api/auth/signin/openai?' + query.toString(), {
                method:'POST', credentials:'include', signal:controller.signal,
                headers:{accept:'application/json', 'content-type':'application/x-www-form-urlencoded',
                  'cache-control':'no-cache', pragma:'no-cache'},
                body:form.toString()
              });
              let data = {};
              try { data = await response.json(); } catch (_) {}
              if (!response.ok || !data.url) {
                finish({ok:false, stage:'signin', status:response.status});
                return;
              }

              let target;
              try { target = new URL(String(data.url), location.href); }
              catch (_) {
                finish({ok:false, stage:'redirect', status:response.status, reason:'invalid_target'});
                return;
              }
              const targetHost = String(target.hostname || '').toLowerCase().replace(/\.$/, '');
              if (target.protocol !== 'https:' || !(
                targetHost === 'auth.openai.com' || targetHost.endsWith('.auth.openai.com')
              )) {
                finish({ok:false, stage:'redirect', status:response.status, reason:'untrusted_target'});
                return;
              }
              if (!target.searchParams.get('screen_hint')) target.searchParams.set('screen_hint', 'login_or_signup');
              if (!target.searchParams.get('login_hint')) target.searchParams.set('login_hint', email);
              if (!target.searchParams.get('ext-oai-did')) target.searchParams.set('ext-oai-did', did);
              if (!target.searchParams.get('auth_session_logging_id')) {
                target.searchParams.set('auth_session_logging_id', authLogId);
              }
              finish({ok:true, stage:'redirect', status:response.status, target_host:targetHost});
              setTimeout(() => location.assign(target.toString()), 0);
            } catch (error) {
              finish({ok:false, stage:'transport', reason:
                error && error.name === 'AbortError' ? 'timeout' : 'request_failed'});
            }
          })();
        """, email, str(uuid.uuid4()), str(uuid.uuid4())) or {}
        if not isinstance(result, Mapping):
            return {"ok": False, "stage": "transport", "reason": "invalid_result"}
        stage = clean(result.get("stage"), 24)
        reason = clean(result.get("reason"), 48)
        target_host = clean(result.get("target_host"), 80).casefold().rstrip(".")
        if target_host and not (
            target_host == "auth.openai.com" or target_host.endswith(".auth.openai.com")
        ):
            target_host = ""
        safe: dict[str, Any] = {"ok": bool(result.get("ok")), "stage": stage or "transport"}
        try:
            status = int(result.get("status"))
        except (TypeError, ValueError):
            status = 0
        if 100 <= status <= 599:
            safe["status"] = status
        if reason:
            safe["reason"] = reason
        if target_host:
            safe["target_host"] = target_host
        return safe
    except Exception as exc:
        return {"ok": False, "stage": "transport", "reason": type(exc).__name__}
    finally:
        try:
            driver.set_script_timeout(max(20, int(timeout or 90)))
        except Exception:
            pass


__all__ = ["submit_email_via_browser_nextauth"]
