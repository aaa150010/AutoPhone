"""Result-path normalization and post-persistence metadata updates."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


AtomicWriteJson = Callable[[Path, Mapping[str, Any]], Any]
FailureSanitizer = Callable[..., str]
LogFn = Callable[[str, str], Any]


def resolve_results_dir(
    settings: Mapping[str, Any] | None,
    data_dir: str | Path,
) -> Path:
    """Resolve the configured results directory relative to importer data."""

    data_root = Path(data_dir).resolve(strict=False)
    raw = str((settings or {}).get("results_dir") or "").strip()
    root = Path(raw) if raw else data_root / "results"
    if not root.is_absolute():
        root = data_root / root
    return root.resolve(strict=False)


def settings_with_absolute_results_dir(
    settings: Mapping[str, Any] | None,
    data_dir: str | Path,
) -> dict[str, Any]:
    """Copy settings and make ``results_dir`` safe for recovered persistence."""

    copied = dict(settings or {})
    copied["results_dir"] = str(resolve_results_dir(copied, data_dir))
    return copied


def result_json_path(
    settings: Mapping[str, Any] | None,
    data_dir: str | Path,
    task_id: Any,
    email: Any,
) -> Path:
    """Return the result path used by the recovered importer."""

    filename = f"{task_id}_{str(email or '').replace('@', '_at_')}.json"
    return resolve_results_dir(settings, data_dir) / filename


def _nonnegative_int(value: Any) -> int:
    try:
        return max(int(value or 0), 0)
    except (TypeError, ValueError, OverflowError):
        return 0


def _sanitize(
    sanitizer: FailureSanitizer,
    value: Any,
    *,
    secrets: Sequence[Any],
    limit: int,
) -> str:
    try:
        return str(sanitizer(value, secrets=secrets, limit=limit) or "")
    except Exception:
        return type(value).__name__ if isinstance(value, BaseException) else ""


def _log_update_failure(
    logger: LogFn | None,
    sanitizer: FailureSanitizer,
    task_id: Any,
    error: BaseException,
    *,
    secrets: Sequence[Any],
) -> None:
    if logger is None:
        return
    detail = _sanitize(sanitizer, error, secrets=secrets, limit=500)
    try:
        logger(
            f"{task_id} [保存任务结果/finalizing_save] 结构化诊断写入失败："
            f"{detail or '未返回错误详情'}",
            "error",
        )
    except Exception:
        return


def apply_result_json_metadata(
    settings: Mapping[str, Any] | None,
    data_dir: str | Path,
    task_id: Any,
    email: Any,
    *,
    timing: Mapping[str, Any] | None = None,
    batch_id: Any = "",
    batch_started_at: Any = 0,
    failure: Mapping[str, Any] | None = None,
    status: Any = "",
    account_banned_detail: Any = "",
    account_banned_message: Any = "",
    secrets: Sequence[Any] = (),
    atomic_write_json: AtomicWriteJson,
    sanitize_failure_detail: FailureSanitizer,
    logger: LogFn | None = None,
) -> bool:
    """Apply all post-persistence metadata with one atomic JSON write.

    The recovered writer creates the initial result. This helper only augments
    that file and deliberately preserves every unrelated top-level and nested
    field.
    """

    normalized_batch_id = str(batch_id or "").strip()[:80]
    normalized_status = str(status or "").strip().lower()
    has_timing = isinstance(timing, Mapping)
    has_failure = isinstance(failure, Mapping)
    has_banned_detail = normalized_status == "account_banned" and bool(
        account_banned_detail
    )
    if not (has_timing or normalized_batch_id or has_failure or has_banned_detail):
        return False

    target = result_json_path(settings, data_dir, task_id, email)
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            return False

        nested = payload.get("result")
        if has_timing:
            timing_value = copy.deepcopy(dict(timing))
            payload["timing"] = timing_value
            if isinstance(nested, dict):
                nested["timing"] = copy.deepcopy(timing_value)

        if normalized_batch_id:
            started_at = _nonnegative_int(batch_started_at)
            payload["batch_id"] = normalized_batch_id
            payload["batch_started_at"] = started_at
            if isinstance(nested, dict):
                nested["batch_id"] = normalized_batch_id
                nested["batch_started_at"] = started_at

        if has_failure:
            failure_value = copy.deepcopy(dict(failure))
            payload["failure"] = failure_value
            payload["error"] = failure_value.get("public_message", "")
            payload["technical_error"] = failure_value.get("technical_summary", "")
            if isinstance(nested, dict):
                nested["failure"] = copy.deepcopy(failure_value)

        if has_banned_detail:
            message = str(account_banned_message or "")
            payload["error"] = message
            payload["technical_error"] = message
            payload["account_banned_local_diagnostic"] = (
                _sanitize(
                    sanitize_failure_detail,
                    account_banned_detail,
                    secrets=secrets,
                    limit=1000,
                )
                or message
            )

        atomic_write_json(target, payload)
        return True
    except Exception as exc:
        _log_update_failure(
            logger,
            sanitize_failure_detail,
            task_id,
            exc,
            secrets=secrets,
        )
        return False


__all__ = [
    "apply_result_json_metadata",
    "resolve_results_dir",
    "result_json_path",
    "settings_with_absolute_results_dir",
]
