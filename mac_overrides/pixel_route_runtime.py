"""Request parsing and batch retry orchestration for Pixel upload routes."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import inspect
import re
from typing import Any, Callable, Iterable
import uuid


PIXEL_ENQUEUE_NODE = "pixel_enqueue"
PIXEL_ENQUEUE_LABEL = "Pixel 重传入队"


class PixelBatchRetryError(RuntimeError):
    def __init__(
        self,
        message: str,
        status_code: int,
        error_code: str,
        *,
        summary: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.public_message = message
        self.status_code = status_code
        self.error_code = error_code
        self.summary = dict(summary or {})


def _safe_identifier(value: Any) -> str:
    text = str(value or "").strip()
    if re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", text):
        return text
    if not text:
        return ""
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _safe_error(value: Any) -> str:
    text = str(value or "")[:2048]
    text = re.sub(
        r"(?i)(access[_ -]?token|refresh[_ -]?token|id[_ -]?token|authorization|"
        r"api[_ -]?key|sms[_ -]?key|password|passwd|secret|cookie|session)"
        r"(?:\\?[\"'])?\s*[:=]\s*(?:\\?[\"'])?[^\s,;}\]\"']+",
        lambda match: f"{match.group(1)}=********",
        text,
    )
    text = re.sub(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+", "Bearer ********", text)
    text = re.sub(r"(?i)(https?://)[^/@\s]+@", r"\1********@", text)
    text = re.sub(r"(?i)(https?://[^?\s,;]+)\?[^\s,;]+", r"\1?[redacted]", text)
    text = re.sub(r"(?i)\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b", r"***@\1", text)
    text = re.sub(r"(?<![A-Za-z0-9])\+?\d{10,15}(?![A-Za-z0-9])", "********", text)
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()[:500]


def _accepts_keyword(callable_value: Callable[..., Any], keyword: str) -> bool:
    try:
        parameters = inspect.signature(callable_value).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(
        parameter.name == keyword or parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in parameters
    )


def _retry_record(
    queue: Any,
    record_id: str,
    target_ids: list[str],
    upload_attempt_id: str,
) -> Any:
    retry = queue.retry
    if _accepts_keyword(retry, "upload_attempt_id"):
        return retry(record_id, target_ids, upload_attempt_id=upload_attempt_id)
    return retry(record_id, target_ids)


def _emit_summary(
    log_fn: Callable[[str, str], None] | None,
    summary: Mapping[str, Any],
) -> None:
    if log_fn is None:
        return
    if int(summary.get("failed") or 0) > 0:
        level = "error"
    else:
        level = "info"
    message = (
        "[Pixel 批量重传入队/pixel_retry_enqueued] "
        f"批次 {_safe_identifier(summary.get('batch_id'))}，"
        f"上传尝试 {_safe_identifier(summary.get('upload_attempt_id'))}："
        f"本地队列 accepted={int(summary.get('accepted') or 0)}，"
        f"skipped={int(summary.get('skipped') or 0)}，"
        f"failed={int(summary.get('failed') or 0)}"
    )
    if int(summary.get("accepted") or 0) > 0:
        message += "；仅表示已入队，远端结果尚未确认"
    try:
        log_fn(message, level)
    except Exception:
        pass


def account_ids_from(data: Mapping[str, Any]) -> list[Any]:
    values = data.get("account_ids")
    if values is None:
        values = data.get("accountIds")
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        return []
    return list(values)


def target_ids_from(data: Mapping[str, Any]) -> list[str] | None:
    values: Any = None
    for key in ("target_ids", "targetIds"):
        if key in data:
            values = data.get(key)
            break
    if values is None:
        for key in ("target_id", "targetId"):
            if key in data:
                values = [data.get(key)]
                break
    if values is None:
        return None
    if isinstance(values, (str, bytes)):
        values = [values]
    if not isinstance(values, Sequence):
        return []
    result: list[str] = []
    for value in values:
        target_id = str(value or "").strip()
        if target_id and target_id not in result:
            result.append(target_id)
    return result


def _record_targets(record: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    targets = record.get("targets")
    if isinstance(targets, Mapping):
        return [
            {**dict(value), "target_id": target_id}
            for target_id, value in targets.items()
            if isinstance(value, Mapping)
        ]
    if isinstance(targets, Sequence) and not isinstance(targets, (str, bytes)):
        return [value for value in targets if isinstance(value, Mapping)]
    return []


def retry_batch_targets(
    queue: Any,
    batch_id: Any,
    target_ids: Iterable[Any] | None,
    *,
    allowed_targets: Iterable[str],
    log_fn: Callable[[str, str], None] | None = None,
) -> dict[str, Any]:
    """Retry every currently retryable record for selected targets in one batch."""
    identifier = _safe_identifier(batch_id)
    requested = list(dict.fromkeys(str(value or "").strip() for value in target_ids or ()))
    requested = [value for value in requested if value]
    allowed = frozenset(str(value) for value in allowed_targets)
    if not identifier:
        raise PixelBatchRetryError("Pixel 批次 ID 无效", 400, "pixel_batch_id_invalid")
    if not requested:
        raise PixelBatchRetryError("请选择要批量重传的 Pixel 目标", 400, "pixel_target_missing")
    if any(value not in allowed for value in requested):
        raise PixelBatchRetryError(
            "Pixel 重传只能选择 pixel-2 至 pixel-7",
            400,
            "pixel_target_invalid",
        )

    candidates: list[tuple[str, list[str]]] = []
    seen_records: set[str] = set()
    page = 1
    while True:
        payload = queue.batch_records(identifier, page=page, page_size=100, status="")
        items = payload.get("items") if isinstance(payload, Mapping) else []
        for record in items if isinstance(items, Sequence) else ():
            if not isinstance(record, Mapping):
                continue
            record_id = str(record.get("record_id") or record.get("recordId") or "").strip()
            if not record_id or record_id in seen_records:
                continue
            selected = []
            for target in _record_targets(record):
                target_id = str(target.get("target_id") or target.get("targetId") or "").strip()
                if target_id in requested and target.get("retryable") is True:
                    selected.append(target_id)
            seen_records.add(record_id)
            if selected:
                candidates.append((record_id, selected))
        try:
            pages = max(1, int(payload.get("pages") or 1))
        except (AttributeError, TypeError, ValueError):
            pages = 1
        if page >= pages:
            break
        page += 1

    if not candidates:
        raise PixelBatchRetryError(
            "当前批次的所选 Pixel 目标没有可重传记录",
            409,
            "pixel_batch_retry_unavailable",
        )

    upload_attempt_id = f"upload-{uuid.uuid4().hex}"
    accepted_records = 0
    accepted_deliveries = 0
    skipped_records = 0
    skipped_deliveries = 0
    failed_records = 0
    failed_deliveries = 0
    failures: list[dict[str, Any]] = []
    for record_id, selected in candidates:
        try:
            _retry_record(queue, record_id, selected, upload_attempt_id)
        except Exception as exc:
            try:
                status = int(getattr(exc, "status_code", 500) or 500)
            except (TypeError, ValueError):
                status = 500
            if status == 409:
                skipped_records += 1
                skipped_deliveries += len(selected)
                continue
            failed_records += 1
            failed_deliveries += len(selected)
            failures.append({
                "record_id": _safe_identifier(record_id),
                "status_code": status if 400 <= status <= 599 else 500,
                "error": _safe_error(
                    getattr(exc, "public_message", "") or exc
                ) or "服务端未返回错误详情",
            })
            continue
        accepted_records += 1
        accepted_deliveries += len(selected)
    summary = {
        "batch_id": identifier,
        "upload_attempt_id": upload_attempt_id,
        "target_ids": requested,
        "accepted": accepted_deliveries,
        "skipped": skipped_deliveries,
        "failed": failed_deliveries,
        "accepted_records": accepted_records,
        "skipped_records": skipped_records,
        "failed_records": failed_records,
        "queued_records": accepted_records,
        "queued_deliveries": accepted_deliveries,
        "failures": failures,
    }
    _emit_summary(log_fn, summary)
    if accepted_records == 0 and failed_records:
        raise PixelBatchRetryError(
            "当前批次的所选 Pixel 目标全部重传失败",
            502,
            "pixel_batch_retry_failed",
            summary=summary,
        )
    if accepted_records == 0:
        raise PixelBatchRetryError(
            "当前批次的所选 Pixel 目标状态已变化，请刷新后重试",
            409,
            "pixel_batch_retry_stale",
            summary=summary,
        )
    return summary


def batch_retry_failure(exc: Exception) -> tuple[dict[str, Any], int]:
    message = str(getattr(exc, "public_message", "") or "").strip()
    try:
        status = int(getattr(exc, "status_code", 500) or 500)
    except (TypeError, ValueError):
        status = 500
    if not 400 <= status <= 599:
        status = 500
    error_code = str(getattr(exc, "error_code", "") or "pixel_batch_retry_failed")
    if (
        len(error_code) > 64
        or not error_code
        or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_" for character in error_code)
    ):
        error_code = "pixel_batch_retry_failed"
    cause = message or "服务端未返回错误详情"
    payload = {
        "ok": False,
        "code": error_code,
        "node_code": PIXEL_ENQUEUE_NODE,
        "node_label": PIXEL_ENQUEUE_LABEL,
        "error": f"{PIXEL_ENQUEUE_LABEL}失败：{cause}",
    }
    summary = getattr(exc, "summary", None)
    if isinstance(summary, Mapping):
        payload.update({
            key: summary[key]
            for key in (
                "batch_id",
                "upload_attempt_id",
                "target_ids",
                "accepted",
                "skipped",
                "failed",
                "accepted_records",
                "skipped_records",
                "failed_records",
                "queued_records",
                "queued_deliveries",
                "failures",
            )
            if key in summary
        })
    return payload, status
