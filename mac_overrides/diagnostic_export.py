"""Incident search and redacted JSON/markdown export for the diagnostic store."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

try:
    from .diagnostic_contract import SCHEMA_VERSION
    from .diagnostic_summary import _safe_text
except ImportError:  # pragma: no cover
    from diagnostic_contract import SCHEMA_VERSION  # type: ignore[no-redef]
    from diagnostic_summary import _safe_text  # type: ignore[no-redef]


def _search_bound(value: Any, *, end_of_day: bool = False) -> str:
    """Normalize date/time-only filters to UTC ISO bounds."""
    text = _safe_text(value, 40)
    if not text:
        return ""
    local_zone = datetime.now().astimezone().tzinfo or timezone.utc
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
            parsed = datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=local_zone)
            if end_of_day:
                parsed += timedelta(days=1, milliseconds=-1)
            return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        if re.fullmatch(r"\d{1,2}:\d{2}(?::\d{2})?", text):
            parts = [int(part) for part in text.split(":")]
            now = datetime.now(local_zone)
            parsed = now.replace(hour=parts[0], minute=parts[1], second=parts[2] if len(parts) > 2 else 0, microsecond=0)
            return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError):
        return text
    return text


class DiagnosticExportMixin:
    """Mixin providing incident search and redacted export for ``DiagnosticStore``."""

    def search_task_incidents(self, task_ids: Sequence[str], batch_ids: Mapping[str, str] | None = None) -> dict[str, str]:
        """Return ``task_id -> newest matching incident_id`` for many tasks.

        Winners replicate the per-task ``search({"task_id": ..., "limit": 1})``
        selection exactly: failure outcomes outrank other outcomes, then the
        most recent ``updated_at`` wins. When ``batch_ids`` supplies a task's
        batch, the batch-scoped winner is preferred and the unscoped winner
        only serves as the legacy fallback, mirroring the historical two-step
        lookup in one pair of indexed queries.
        """
        unique_ids: list[str] = []
        seen: set[str] = set()
        for task_id in task_ids:
            value = _safe_text(task_id, 500)
            if value and value not in seen:
                seen.add(value)
                unique_ids.append(value)
        if not unique_ids:
            return {}
        placeholders = ",".join("?" for _ in unique_ids)
        rank = "CASE WHEN i.outcome IN ('error','failed','failure') THEN 0 ELSE 1 END, i.updated_at DESC"
        scoped: dict[str, dict[str, str]] = {}
        unscoped: dict[str, str] = {}
        with self._lock, self._connection() as db:
            rows = db.execute(
                "SELECT task_id, batch_id, incident_id FROM ("
                "SELECT i.task_id AS task_id, i.batch_id AS batch_id, i.incident_id AS incident_id, "
                f"ROW_NUMBER() OVER (PARTITION BY i.task_id, i.batch_id ORDER BY {rank}) AS rn "
                f"FROM diagnostic_incidents i WHERE i.task_id IN ({placeholders})"
                ") WHERE rn=1",
                unique_ids,
            ).fetchall()
            for row in rows:
                scoped.setdefault(str(row[0] or ""), {})[str(row[1] or "")] = str(row[2] or "")
            rows = db.execute(
                "SELECT task_id, incident_id FROM ("
                "SELECT i.task_id AS task_id, i.incident_id AS incident_id, "
                f"ROW_NUMBER() OVER (PARTITION BY i.task_id ORDER BY {rank}) AS rn "
                f"FROM diagnostic_incidents i WHERE i.task_id IN ({placeholders})"
                ") WHERE rn=1",
                unique_ids,
            ).fetchall()
            for row in rows:
                unscoped[str(row[0] or "")] = str(row[1] or "")
        winners: dict[str, str] = {}
        for task_id in unique_ids:
            wanted_batch = str((batch_ids or {}).get(task_id) or "")
            if wanted_batch:
                winner = scoped.get(task_id, {}).get(wanted_batch)
                if winner:
                    winners[task_id] = winner
                    continue
            winner = unscoped.get(task_id)
            if winner:
                winners[task_id] = winner
        return winners

    def search_task_nodes(self, task_ids: Sequence[str], node_code: str) -> dict[str, str]:
        """Return ``task_id -> incident_id`` for the newest matching incident.

        State projections previously re-ran ``search`` per task to enrich
        missing incident ids; this batch variant answers all tasks with one
        indexed query instead.
        """
        normalized_node = _safe_text(node_code, 180)
        unique_ids: list[str] = []
        seen: set[str] = set()
        for task_id in task_ids:
            value = _safe_text(task_id, 180)
            if value and value not in seen:
                seen.add(value)
                unique_ids.append(value)
        if not normalized_node or not unique_ids:
            return {}
        placeholders = ",".join("?" for _ in unique_ids)
        with self._lock, self._connection() as db:
            rows = db.execute(
                f"""
                SELECT i.task_id, i.incident_id
                FROM diagnostic_incidents i
                JOIN (
                    SELECT task_id, MAX(created_at) AS latest_created, MAX(updated_at) AS latest_updated
                    FROM diagnostic_incidents
                    WHERE task_id IN ({placeholders}) AND first_node_code=?
                    GROUP BY task_id
                ) latest
                  ON i.task_id=latest.task_id
                 AND i.created_at=latest.latest_created
                 AND i.updated_at=latest.latest_updated
                """,
                [*unique_ids, normalized_node],
            ).fetchall()
        matches: dict[str, str] = {}
        for row in rows:
            incident_id = _safe_text(row["incident_id"], 80).upper()
            task_id = _safe_text(row["task_id"], 180)
            if incident_id and task_id:
                matches.setdefault(task_id, incident_id)
        return matches

    def search(self, query: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        query = query or {}
        clauses: list[str] = []
        params: list[Any] = []
        exact = _safe_text(query.get("incident_id"), 80).upper()
        if exact:
            clauses.append("i.incident_id=?")
            params.append(exact)
        for key in (() if exact else ("task_id", "batch_id", "run_id", "chain", "workflow", "driver", "status", "outcome", "first_node_code")):
            value = _safe_text(query.get(key), 180)
            if value:
                if key == "outcome" and value == "open":
                    column = "i.status"
                else:
                    column = {"first_node_code": "i.first_node_code"}.get(key, f"i.{key}")
                clauses.append(f"{column}=?")
                params.append(value)
        subject = _safe_text(query.get("subject") or query.get("email") or query.get("account"), 500)
        if subject and not exact:
            ref = self.fingerprint(subject)
            clauses.append("(i.subject_ref=? OR EXISTS (SELECT 1 FROM diagnostic_aliases a WHERE a.incident_id=i.incident_id AND a.alias_ref=?))")
            params.extend((ref, ref))
        time_point = _safe_text(query.get("time_point") or query.get("time"), 40)
        if time_point and not exact and re.fullmatch(r"\d{1,2}:\d{2}(?::\d{2})?", time_point):
            try:
                center = datetime.fromisoformat(_search_bound(time_point).replace("Z", "+00:00"))
                start_bound = (center - timedelta(minutes=30)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                end_bound = (center + timedelta(minutes=30)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                clauses.append(
                    "((i.updated_at>=? AND i.updated_at<=?) OR EXISTS ("
                    "SELECT 1 FROM diagnostic_events et WHERE et.incident_id=i.incident_id "
                    "AND et.occurred_at>=? AND et.occurred_at<=?))"
                )
                params.extend((start_bound, end_bound, start_bound, end_bound))
            except (TypeError, ValueError, OverflowError):
                pass
        date_only = _safe_text(query.get("date"), 40)
        if date_only and not exact and not time_point and not query.get("from") and not query.get("to"):
            start_bound = _search_bound(date_only)
            end_bound = _search_bound(date_only, end_of_day=True)
            clauses.append(
                "((i.updated_at>=? AND i.updated_at<=?) OR EXISTS ("
                "SELECT 1 FROM diagnostic_events ed WHERE ed.incident_id=i.incident_id "
                "AND ed.occurred_at>=? AND ed.occurred_at<=?))"
            )
            params.extend((start_bound, end_bound, start_bound, end_bound))
        from_value = query.get("from")
        to_value = query.get("to")
        if from_value and to_value and not exact and not time_point:
            start_bound = _search_bound(from_value)
            end_bound = _search_bound(to_value, end_of_day=True)
            clauses.append(
                "((i.updated_at>=? AND i.updated_at<=?) OR EXISTS ("
                "SELECT 1 FROM diagnostic_events ef WHERE ef.incident_id=i.incident_id "
                "AND ef.occurred_at>=? AND ef.occurred_at<=?))"
            )
            params.extend((start_bound, end_bound, start_bound, end_bound))
        elif from_value and not exact and not time_point:
            start_bound = _search_bound(from_value)
            clauses.append("(i.updated_at>=? OR EXISTS (SELECT 1 FROM diagnostic_events ef WHERE ef.incident_id=i.incident_id AND ef.occurred_at>=?))")
            params.extend((start_bound, start_bound))
        elif to_value and not exact and not time_point:
            end_bound = _search_bound(to_value, end_of_day=True)
            clauses.append("(i.updated_at<=? OR EXISTS (SELECT 1 FROM diagnostic_events et WHERE et.incident_id=i.incident_id AND et.occurred_at<=?))")
            params.extend((end_bound, end_bound))
        limit_value = query.get("limit") or 100
        try:
            limit = min(max(int(limit_value), 1), 500)
        except (TypeError, ValueError):
            limit = 100
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock, self._connection() as db:
            rows = db.execute(f"SELECT i.* FROM diagnostic_incidents i {where} ORDER BY CASE WHEN i.outcome IN ('error','failed','failure') THEN 0 ELSE 1 END, i.updated_at DESC LIMIT ?", (*params, limit)).fetchall()
            results = [self._row(row) for row in rows]
            basis: list[str] = []
            if exact:
                basis.append("日志 ID 精确匹配")
            for key, label in (("task_id", "任务 ID"), ("batch_id", "批次 ID"), ("run_id", "运行 ID"), ("chain", "链路"), ("workflow", "工作流"), ("driver", "驱动"), ("subject", "账号 HMAC 指纹"), ("email", "邮箱 HMAC 指纹"), ("account", "账号 HMAC 指纹"), ("date", "日期全天"), ("from", "开始时间"), ("to", "结束时间"), ("time_point", "时间点 ±30 分钟")):
                if query.get(key):
                    basis.append(label)
            time_center: datetime | None = None
            if time_point:
                # The ±30min anchor is identical for every result row; parse
                # it once instead of per row.
                try:
                    time_center = datetime.fromisoformat(_search_bound(time_point).replace("Z", "+00:00"))
                except (TypeError, ValueError, OverflowError):
                    time_center = None
            for result in results:
                result["match_basis"] = basis or ["最近发生时间"]
                if time_point:
                    if time_center is None:
                        result["time_distance_seconds"] = None
                        continue
                    try:
                        updated = datetime.fromisoformat(str(result.get("updated_at") or "").replace("Z", "+00:00"))
                        result["time_distance_seconds"] = abs((updated - time_center).total_seconds())
                    except (TypeError, ValueError, OverflowError):
                        result["time_distance_seconds"] = None
            return results

    def export(self, incident_ids: Sequence[str], fmt: str = "json") -> str:
        bulk = getattr(self, "incidents_bulk", None)
        if callable(bulk):
            # One grouped read + verify per table instead of two full
            # incident loads per selected log id.
            incidents = bulk(incident_ids)
        else:
            rows = [self.incident(value) for value in incident_ids]
            incidents = [row for row in rows if row is not None]
        if str(fmt).lower() != "markdown":
            return json.dumps({
                "schema_version": SCHEMA_VERSION,
                "redaction_applied": True,
                "incidents": incidents,
                "facts": "仅包含本地诊断索引中已记录的脱敏事件。",
                "analysis": "首个真实失败节点按事件链和节点优先级归纳；不代表未记录的外部事实。",
                "unknowns": "保留策略清理、写入前丢失或未接入统一契约的历史事件无法恢复。",
                "redaction_removed": ["邮箱原文", "手机号", "密码", "Token", "Cookie", "验证码", "TOTP 秘密", "代理凭据"],
            }, ensure_ascii=False, indent=2)
        lines = ["# GPTPhone 脱敏日志诊断", "", "> 仅包含本地诊断索引中的脱敏事件；事实、归因和未知项分开。", ""]
        for incident in incidents:
            lines.extend([
                f"## 1. 日志 ID\n{incident['incident_id']}",
                "", "## 2. 查询和匹配依据",
                f"- 任务 ID：{incident.get('task_id') or '-'}；批次 ID：{incident.get('batch_id') or '-'}",
                f"- 账号显示：{incident.get('subject_display') or '-'}；链路：{incident.get('chain') or '-'} / {incident.get('driver') or '-'}",
                "", "## 3. 已确认事实",
                f"- 状态：{incident.get('status') or incident.get('outcome') or '-'}；事件数：{incident.get('event_count') or 0}",
                f"- 首个失败节点：{incident.get('first_node_label') or '-'} ({incident.get('first_node_code') or '-'})",
                "", "## 4. 首个真实失败",
                f"- 错误代码：{incident.get('first_error_code') or '-'}；可重试：{'是' if incident.get('retryable') else '否'}；HTTP 状态：{incident.get('failure', {}).get('http_status') or '-'}；Provider Code：{incident.get('failure', {}).get('provider_code') or '-'}",
                "", "## 5. 关键时间线",
            ])
            for event in incident.get("events") or []:
                lines.append(f"- {event.get('occurred_at')} [{event.get('outcome')}] {event.get('node_label') or event.get('node_code') or '-'}：{event.get('message') or '-'}")
            lines.extend([
                "", "## 6. 重试和连带错误", "- 事件中的 attempt、attempt_group 和后续清理事件仅作为关联记录，不覆盖首因。",
                "", "## 7. 脱敏环境摘要", f"- 工作流：{incident.get('workflow') or '-'}；运行标识：{incident.get('run_id') or '-'}",
                "", "## 8. 完整性校验结果", f"- {incident.get('integrity_status') or '-'}",
                "", "## 9. 当前最可能根因", f"- {incident.get('failure', {}).get('public_message') or incident.get('failure', {}).get('technical_summary') or '当前证据不足以进一步归因。'}",
                "", "## 10. 未确认信息", "- 仅根据当前诊断索引判断；被保留策略清理、写入前丢失或未接入契约的历史事件无法恢复。",
                "", "## 11. 建议下一步", f"- {incident.get('failure', {}).get('action_hint') or '按首个真实失败节点继续排查，并保留本日志 ID。'}",
                "", "## 12. 已移除的敏感字段", "- 邮箱原文、手机号、密码、Token、Cookie、验证码、TOTP 秘密、代理凭据。", "",
            ])
        return "\n".join(lines)


__all__ = ["DiagnosticExportMixin"]
