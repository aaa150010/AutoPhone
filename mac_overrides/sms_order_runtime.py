"""SMS order cancellation, cleanup persistence, and cost accounting."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import threading
import time
from typing import Any, Callable
import urllib.request
import xml.etree.ElementTree as ET

try:
    from .sms_provider_runtime import normalize_sms_provider_name
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from sms_provider_runtime import normalize_sms_provider_name  # type: ignore[no-redef]


ECB_DAILY_URL = "https://www.ecb.europa.eu/stats/eurofxref/eurofxref-daily.xml"
_CANCEL_RECEIPT_KEYS = frozenset(
    {"cancel_state", "provider_response", "provider_status", "refund_status"}
)


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def _safe_provider_token(value: Any) -> str:
    if isinstance(value, dict):
        value = next(
            (
                value.get(key)
                for key in (
                    "status",
                    "response",
                    "result",
                    "message",
                    "error",
                    "title",
                    "code",
                )
                if value.get(key) not in (None, "")
            ),
            "",
        )
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    text = str(value or "").strip()
    if text.startswith("{") or "{" in text:
        candidate = text[text.find("{") :]
        try:
            parsed = json.loads(candidate)
        except (TypeError, ValueError, json.JSONDecodeError):
            parsed = None
        if isinstance(parsed, dict):
            return _safe_provider_token(parsed)
    text = text.upper()
    return re.sub(r"[^A-Z0-9_.:-]+", "_", text)[:80]


def _provider_exception_text(error: BaseException) -> str:
    parts = [str(error or "")]
    reader = getattr(error, "read", None)
    if callable(reader):
        try:
            body = reader()
            if isinstance(body, bytes):
                body = body.decode("utf-8", "replace")
            parts.append(str(body or ""))
        except Exception:
            pass
    return " ".join(part for part in parts if part)


def _herosms_min_cancel_seconds(value: Any, default: int = 120) -> int:
    if isinstance(value, dict):
        info = value.get("info")
        if isinstance(info, dict):
            value = info.get("minActivationTime") or info.get("min_activation_time")
        else:
            value = value.get("minActivationTime") or value.get("min_activation_time")
    try:
        return max(1, min(600, int(value)))
    except (TypeError, ValueError):
        return int(default)


class HeroSmsCancellationDeferred(RuntimeError):
    """Signal that provider cancellation must resume after its protection window."""

    def __init__(self, retry_after_seconds: float, minimum_seconds: int) -> None:
        self.retry_after_seconds = max(1.0, float(retry_after_seconds))
        self.minimum_seconds = max(1, int(minimum_seconds))
        super().__init__(
            f"herosms_cancel_deferred:retry_after={int(self.retry_after_seconds)}"
        )


def herosms_cancel_delay_seconds(
    leased_at: Any,
    minimum_seconds: Any = 120,
    *,
    now_fn: Callable[[], float] = time.time,
) -> float:
    try:
        started = float(leased_at)
    except (TypeError, ValueError):
        started = float(now_fn())
    minimum = _herosms_min_cancel_seconds(minimum_seconds)
    elapsed = max(0.0, float(now_fn()) - started)
    return max(1.0, float(minimum) - elapsed + 1.0)


def safe_cancel_receipt(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, str] = {}
    for key in _CANCEL_RECEIPT_KEYS:
        token = _safe_provider_token(value.get(key))
        if token:
            result[key] = (
                token.lower()
                if key in {"cancel_state", "refund_status"}
                else token
            )
    return result


def confirm_herosms_cancellation(
    provider: Any,
    activation_id: Any,
    *,
    now_fn: Callable[[], float] = time.time,
    sleep_fn: Callable[[float], None] = time.sleep,
    on_wait: Callable[[float], None] | None = None,
    leased_at: float | None = None,
    defer_early: bool = False,
) -> dict[str, str]:
    """Cancel one HeroSMS activation using its documented refund contract."""
    api = getattr(provider, "_api", None)
    activation = str(activation_id or "").strip()
    if not callable(api) or not activation:
        raise RuntimeError("herosms_cancel_confirmation_unavailable")
    started = float(leased_at) if leased_at is not None else float(now_fn())
    response = ""
    minimum_seconds = 120
    for attempt in range(3):
        try:
            raw_response = api(
                {"action": "setStatus", "status": "8", "id": activation}
            )
            response = _safe_provider_token(raw_response)
            minimum_seconds = _herosms_min_cancel_seconds(
                raw_response, minimum_seconds
            )
        except Exception as exc:
            raw_response = _provider_exception_text(exc)
            response = _safe_provider_token(raw_response)
            if response != "EARLY_CANCEL_DENIED":
                raise RuntimeError(
                    f"herosms_cancel_request_failed:{type(exc).__name__}"
                ) from exc

        if response == "ACCESS_CANCEL":
            break
        if response != "EARLY_CANCEL_DENIED":
            raise RuntimeError(
                f"herosms_cancel_rejected:{response or 'EMPTY_RESPONSE'}"
            )
        if attempt >= 2:
            raise RuntimeError("herosms_cancel_early_denied_after_retry")
        wait_seconds = herosms_cancel_delay_seconds(
            started,
            minimum_seconds,
            now_fn=now_fn,
        )
        if callable(on_wait):
            try:
                on_wait(wait_seconds)
            except Exception:
                pass
        if defer_early:
            raise HeroSmsCancellationDeferred(wait_seconds, minimum_seconds)
        sleep_fn(wait_seconds)

    try:
        provider_status = _safe_provider_token(
            api({"action": "getStatus", "id": activation})
        )
    except Exception:
        provider_status = "STATUS_CHECK_UNAVAILABLE"
    return {
        "cancel_state": "confirmed",
        "provider_response": response,
        "provider_status": provider_status or "STATUS_CHECK_EMPTY",
        "refund_status": "provider_refund_accepted",
    }


class SmsCleanupQueue:
    """Persist failed activation cancellations without exposing them publicly."""

    def __init__(
        self,
        path: Path,
        *,
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        self.path = Path(path)
        self.now_fn = now_fn
        self.lock = threading.RLock()
        self.condition = threading.Condition(self.lock)
        self.process_lock = threading.Lock()
        self.worker: threading.Thread | None = None
        self.worker_stop = threading.Event()
        self.worker_handler: Callable[[dict[str, Any]], bool] | None = None

    @staticmethod
    def _entry_id(platform: Any, activation_id: Any) -> str:
        value = f"{normalize_sms_provider_name(platform)}:{activation_id}"
        return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:20]

    def _read_payload_locked(
        self,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            return [], []
        if isinstance(value, dict):
            rows = value.get("pending")
            if not isinstance(rows, list):
                rows = value.get("items")
            confirmed = value.get("confirmed")
        else:
            rows = value
            confirmed = []
        return (
            [dict(row) for row in rows or [] if isinstance(row, dict)],
            [dict(row) for row in confirmed or [] if isinstance(row, dict)],
        )

    def _read_locked(self) -> list[dict[str, Any]]:
        rows, _confirmed = self._read_payload_locked()
        return rows

    def _write_locked(
        self,
        rows: list[dict[str, Any]],
        confirmed: list[dict[str, Any]] | None = None,
    ) -> None:
        if confirmed is None:
            _pending, confirmed = self._read_payload_locked()
        confirmed = list(confirmed or [])[-500:]
        if not rows and not confirmed and not self.path.exists():
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(
                {
                    "version": 3,
                    "items": rows,
                    "pending": rows,
                    "confirmed": confirmed,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        temporary.replace(self.path)

    def enqueue(
        self,
        *,
        platform: Any,
        key_fingerprint: Any,
        activation_id: Any,
        delay_seconds: float = 15.0,
        error_code: Any = "provider_cancel_failed",
        leased_at: Any = None,
        task_id: Any = "",
    ) -> str:
        platform_name = normalize_sms_provider_name(platform)
        activation = str(activation_id or "").strip()
        fingerprint = str(key_fingerprint or "").strip()[:20]
        if not platform_name or not activation or not fingerprint:
            return ""
        entry_id = self._entry_id(platform_name, activation)
        now = float(self.now_fn())
        with self.lock:
            rows, confirmed = self._read_payload_locked()
            if any(row.get("id") == entry_id for row in confirmed):
                return entry_id
            existing = next((row for row in rows if row.get("id") == entry_id), None)
            if existing is None:
                rows.append(
                    {
                        "id": entry_id,
                        "platform": platform_name,
                        "key_fingerprint": fingerprint,
                        "activation_id": activation,
                        "due_at": now + max(0.0, float(delay_seconds)),
                        "leased_at": float(leased_at or now),
                        "task_id": str(task_id or "").strip()[:80],
                        "attempts": 0,
                        "error_code": _safe_provider_token(error_code).lower(),
                    }
                )
            else:
                existing["due_at"] = min(
                    float(existing.get("due_at") or now),
                    now + max(0.0, float(delay_seconds)),
                )
                if not existing.get("task_id") and task_id:
                    existing["task_id"] = str(task_id).strip()[:80]
                if not existing.get("leased_at") and leased_at:
                    existing["leased_at"] = float(leased_at)
            self._write_locked(rows, confirmed)
            self.condition.notify_all()
        return entry_id

    def process(
        self,
        handler: Callable[[dict[str, Any]], bool],
        *,
        limit: int = 20,
    ) -> dict[str, int]:
        with self.process_lock:
            current = float(self.now_fn())
            with self.lock:
                rows = self._read_locked()
                due = [
                    row
                    for row in rows
                    if float(row.get("due_at") or 0) <= current
                ][: max(1, int(limit))]
            completed: set[str] = set()
            updates: dict[str, dict[str, Any]] = {}
            for row in due:
                entry_id = str(row.get("id") or "")
                try:
                    confirmed = bool(handler(dict(row)))
                except Exception as exc:
                    confirmed = False
                    error_code = type(exc).__name__.lower()
                    raw_retry_after = float(
                        getattr(exc, "retry_after_seconds", 0) or 0
                    )
                    retry_after = (
                        max(1.0, raw_retry_after) if raw_retry_after else 0.0
                    )
                else:
                    error_code = "provider_cancel_unconfirmed"
                    retry_after = 0.0
                if confirmed:
                    completed.add(entry_id)
                    continue
                attempt = max(0, int(row.get("attempts") or 0)) + 1
                retry_delay = retry_after or min(
                    1800, 30 * (2 ** min(attempt, 5))
                )
                updates[entry_id] = {
                    "attempts": attempt,
                    "due_at": current + retry_delay,
                    "error_code": _safe_provider_token(error_code).lower(),
                }
            with self.lock:
                rows, confirmed_rows = self._read_payload_locked()
                confirmed_by_id = {
                    str(row.get("id") or ""): dict(row)
                    for row in confirmed_rows
                    if str(row.get("id") or "")
                }
                kept: list[dict[str, Any]] = []
                for row in rows:
                    entry_id = str(row.get("id") or "")
                    if entry_id in completed:
                        confirmed_by_id[entry_id] = {
                            "id": entry_id,
                            "platform": normalize_sms_provider_name(
                                row.get("platform")
                            ),
                            "key_fingerprint": str(
                                row.get("key_fingerprint") or ""
                            )[:20],
                            "task_id": str(row.get("task_id") or "")[:80],
                            "attempts": max(0, int(row.get("attempts") or 0)) + 1,
                            "confirmed_at": int(current),
                            "cancel_state": "confirmed",
                            "refund_status": "provider_refund_accepted",
                        }
                        continue
                    if entry_id in updates:
                        row.update(updates[entry_id])
                    kept.append(row)
                confirmed_rows = list(confirmed_by_id.values())[-500:]
                self._write_locked(kept, confirmed_rows)
                self.condition.notify_all()
        return {
            "processed": len(due),
            "completed": len(completed),
            "remaining": len(kept),
            "confirmed": len(confirmed_rows),
        }

    def start_worker(self, handler: Callable[[dict[str, Any]], bool]) -> None:
        with self.condition:
            self.worker_handler = handler
            if self.worker is not None and self.worker.is_alive():
                self.condition.notify_all()
                return
            self.worker_stop.clear()
            self.worker = threading.Thread(
                target=self._worker_loop,
                name="sms-cancel-cleanup",
                daemon=True,
            )
            self.worker.start()

    def _worker_loop(self) -> None:
        while not self.worker_stop.is_set():
            handler = self.worker_handler
            if callable(handler):
                try:
                    self.process(handler)
                except Exception:
                    pass
            with self.condition:
                if self.worker_stop.is_set():
                    return
                rows = self._read_locked()
                now = float(self.now_fn())
                due_times = [float(row.get("due_at") or now) for row in rows]
                wait_seconds = (
                    max(0.1, min(60.0, min(due_times) - now))
                    if due_times
                    else 60.0
                )
                self.condition.wait(timeout=wait_seconds)

    def stop_worker(self) -> None:
        self.worker_stop.set()
        with self.condition:
            self.condition.notify_all()


class ExchangeRateCache:
    def __init__(
        self,
        path: Path,
        *,
        fetcher: Callable[[], bytes] | None = None,
        now_fn: Callable[[], float] = time.time,
        ttl_seconds: int = 86400,
        fallback_rate: float = 7.20,
    ) -> None:
        self.path = Path(path)
        self.fetcher = fetcher or self._fetch_ecb
        self.now_fn = now_fn
        self.ttl_seconds = ttl_seconds
        self.fallback_rate = fallback_rate
        self.lock = threading.Lock()

    @staticmethod
    def _fetch_ecb() -> bytes:
        with urllib.request.urlopen(ECB_DAILY_URL, timeout=5) as response:
            return response.read(262144)

    @staticmethod
    def parse_ecb(payload: bytes) -> tuple[float, str]:
        root = ET.fromstring(payload)
        usd = None
        cny = None
        rate_date = ""
        for element in root.iter():
            if element.attrib.get("time"):
                rate_date = element.attrib["time"]
            currency = element.attrib.get("currency")
            if currency == "USD":
                usd = _as_float(element.attrib.get("rate"), 0)
            elif currency == "CNY":
                cny = _as_float(element.attrib.get("rate"), 0)
        if not usd or not cny:
            raise ValueError("ECB 汇率响应缺少 USD 或 CNY")
        return cny / usd, rate_date

    def _read(self) -> dict[str, Any]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return value if isinstance(value, dict) else {}

    def _write(self, value: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(value, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        temporary.replace(self.path)

    def get_rate(self) -> dict[str, Any]:
        with self.lock:
            now = self.now_fn()
            cached = self._read()
            fetched_at = _as_float(cached.get("fetched_at"), 0)
            cached_rate = _as_float(cached.get("rate"), 0)
            if cached_rate > 0 and now - fetched_at < self.ttl_seconds:
                return {**cached, "source": "cache"}
            try:
                rate, rate_date = self.parse_ecb(self.fetcher())
                value = {
                    "rate": round(rate, 6),
                    "date": rate_date,
                    "fetched_at": int(now),
                    "source": "ecb",
                }
                self._write(value)
                return value
            except Exception:
                if cached_rate > 0:
                    return {**cached, "source": "stale_cache"}
                return {
                    "rate": self.fallback_rate,
                    "date": time.strftime("%Y-%m-%d", time.localtime(now)),
                    "fetched_at": int(now),
                    "source": "fallback",
                }


class SmsCostLedger:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.orders: dict[str, dict[str, dict[str, Any]]] = {}

    def clear(self) -> None:
        with self.lock:
            self.orders.clear()

    @staticmethod
    def _activation_key(activation_id: Any) -> str:
        return hashlib.sha256(
            str(activation_id or "").encode("utf-8")
        ).hexdigest()[:12]

    @staticmethod
    def _candidate_value(candidate: Any, name: str, default: Any = None) -> Any:
        if isinstance(candidate, dict):
            return candidate.get(name, default)
        return getattr(candidate, name, default)

    def record_lease(self, task_id: str, lease: Any) -> None:
        meta = lease.meta if isinstance(getattr(lease, "meta", None), dict) else {}
        candidate = meta.get("candidate")
        price = meta.get("price_usd")
        if price is None:
            price = self._candidate_value(candidate, "price")
        activation_key = self._activation_key(getattr(lease, "activation_id", ""))
        order = {
            "activation": activation_key,
            "platform": meta.get("platform")
            or meta.get("provider")
            or self._candidate_value(candidate, "pool", ""),
            "key_index": meta.get("key_index"),
            "key_fingerprint": meta.get("key_fingerprint") or "",
            "country": self._candidate_value(candidate, "country", ""),
            "provider_id": self._candidate_value(candidate, "provider_id", ""),
            "price_usd": None if price is None else round(_as_float(price), 4),
            "status": "leased",
            "code_received": False,
            "leased_at": int(time.time()),
        }
        with self.lock:
            self.orders.setdefault(task_id, {})[activation_key] = order

    def mark_code_received(self, task_id: str, activation_id: Any) -> None:
        activation_key = self._activation_key(activation_id)
        with self.lock:
            order = self.orders.get(task_id, {}).get(activation_key)
            if order is not None:
                order["code_received"] = True
                order["status"] = "code_received"
                order["code_received_at"] = int(time.time())

    def mark_state(self, task_id: str, activation_id: Any, state: str) -> None:
        allowed = {
            "leased",
            "submitted",
            "ready",
            "waiting",
            "code_received",
            "completed",
            "cancel_pending",
            "cancelled",
            "cancel_failed",
        }
        value = str(state or "").strip()
        if value not in allowed:
            return
        activation_key = self._activation_key(activation_id)
        with self.lock:
            order = self.orders.get(task_id, {}).get(activation_key)
            if order is not None:
                order["status"] = value
                order[f"{value}_at"] = int(time.time())

    def mark_finished(
        self,
        task_id: str,
        activation_id: Any,
        status: str,
        reason: str = "",
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        activation_key = self._activation_key(activation_id)
        with self.lock:
            order = self.orders.get(task_id, {}).get(activation_key)
            if order is not None:
                order["status"] = status
                if reason:
                    order["reason"] = reason
                safe_details = safe_cancel_receipt(details)
                if safe_details:
                    order["cancel_receipt"] = safe_details
                order["finished_at"] = int(time.time())

    def summary(
        self,
        task_id: str,
        exchange: ExchangeRateCache,
        *,
        pop: bool = True,
    ) -> dict[str, Any]:
        with self.lock:
            task_orders = (
                self.orders.pop(task_id, {})
                if pop
                else dict(self.orders.get(task_id, {}))
            )
            outcomes = [dict(order) for order in task_orders.values()]
        paid = [
            order
            for order in outcomes
            if order.get("code_received") and order.get("price_usd") is not None
        ]
        if not paid:
            return {
                "sms_cost_usd": None,
                "sms_cost_cny": None,
                "sms_exchange_rate": None,
                "sms_exchange_date": "",
                "sms_order_outcomes": outcomes,
            }
        usd = round(sum(float(order["price_usd"]) for order in paid), 4)
        rate_info = exchange.get_rate()
        rate = float(rate_info["rate"])
        return {
            "sms_cost_usd": usd,
            "sms_cost_cny": round(usd * rate, 2),
            "sms_exchange_rate": round(rate, 6),
            "sms_exchange_date": str(rate_info.get("date") or ""),
            "sms_exchange_source": str(rate_info.get("source") or ""),
            "sms_order_outcomes": outcomes,
        }
