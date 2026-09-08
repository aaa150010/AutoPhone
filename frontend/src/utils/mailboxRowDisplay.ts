/**
 * Mailbox row display mappers.
 *
 * Pure row-level projections extracted verbatim from MailboxTable.vue so the
 * table component keeps only wiring. All functions are free of component
 * state: they map a MailboxRow (or quota window) to display text or tag tone.
 */
import type { MailboxRow } from '../types/api'
import {
  ACCOUNT_BANNED_DISPLAY_MESSAGE,
  isCurrentAccountBanned,
} from './freeFailure'
import { formatDateTime, formatDateTimeZh, formatShortDateTime, parseTimestamp } from './datetime'

export function createdText(row: MailboxRow) {
  return formatDateTime(row.created_at)
}

export function costLabel(row: MailboxRow) {
  return row.sms_cost_cny == null ? '暂无' : `¥${Number(row.sms_cost_cny).toFixed(2)}`
}

export function costDetail(row: MailboxRow) {
  if (row.sms_cost_cny == null) return ''
  const usd = row.sms_cost_usd == null ? '暂无' : `$${Number(row.sms_cost_usd).toFixed(4)}`
  const rate = row.sms_exchange_rate == null ? '暂无' : Number(row.sms_exchange_rate).toFixed(4)
  return `美元报价 ${usd} · USD/CNY ${rate} · ${row.sms_exchange_date || '未知日期'}`
}

export function sub2Value(row: MailboxRow) {
  return row.sub2_status || (row as { sub2?: MailboxRow['sub2_status'] }).sub2 || null
}

export function sub2Code(row: MailboxRow) {
  const value = sub2Value(row)
  const code = Number(value?.status_code ?? value?.code)
  return Number.isFinite(code) && code > 0 ? code : null
}

export function sub2Label(row: MailboxRow) {
  const value = sub2Value(row)
  if (!value) return '未测试'
  if (value.label) return value.label
  if (value.linked === false || ['unlinked', 'not_linked'].includes(String(value.kind || value.status))) return '未关联'
  if (String(value.kind || value.status) === 'not_ready') return value.label || '未上传'
  const code = sub2Code(row)
  if (code === 200) return '200 健康'
  if (code === 401) return '401 Token失效'
  if (code === 429) return '429 额度受限'
  if (code === 404) return '404 账号不存在'
  const kind = String(value.kind || value.status || '').toLowerCase()
  if (kind === 'timeout') return '超时'
  if (kind === 'network_error') return '网络错误'
  if (kind === 'protocol_error') return '协议错误'
  return kind && kind !== 'untested' ? kind : '未测试'
}

export function sub2Tone(row: MailboxRow): 'success' | 'warning' | 'danger' | 'info' {
  const value = sub2Value(row)
  const code = sub2Code(row)
  if (code === 200) return 'success'
  if (code === 429) return 'warning'
  if (value?.is_test_failure || value?.needs_rerun || [401, 404].includes(Number(code))) return 'danger'
  if (value?.is_error || value?.is_abnormal) return 'danger'
  return 'info'
}

const MAILBOX_SUCCESS_STATUSES = new Set([
  'success', 'succeeded', 'complete', 'completed', 'partial', 'partial_success',
  'ok', 'uploaded', 'consumed',
])
const MAILBOX_ACTIVE_STATUSES = new Set(['queued', 'pending', 'running', 'active'])

/**
 * Resolve the current mailbox outcome before applying the shared ban display
 * rule. Pool rows use `consumed`, while task results use `success`/`uploaded`;
 * treating both as success prevents an older banned failure from resurfacing
 * after a retry has completed.
 */
export function mailboxBanStatus(row: MailboxRow): string {
  const taskStatus = String(row.task_status || '').trim().toLowerCase()
  const poolStatus = String(row.status || '').trim().toLowerCase()
  const status = taskStatus || poolStatus
  return MAILBOX_SUCCESS_STATUSES.has(status) ? 'success' : status
}

export function isMailboxAccountBanned(row: MailboxRow): boolean {
  const taskStatus = String(row.task_status || '').trim().toLowerCase()
  const poolStatus = String(row.status || '').trim().toLowerCase()
  const outcomeStatus = mailboxBanStatus(row)
  if (MAILBOX_SUCCESS_STATUSES.has(outcomeStatus)) return false
  if (taskStatus === 'account_banned' || poolStatus === 'account_banned') return true
  if (String(row.reason || '').trim().toLowerCase() === 'account_banned') return true
  // A live retry can retain the original failure object while its task is
  // running. It must not be presented as a new terminal ban.
  if (MAILBOX_ACTIVE_STATUSES.has(taskStatus)) return false
  return isCurrentAccountBanned(outcomeStatus, row.failure)
}

export function statusTagType(row: MailboxRow) {
  if (isMailboxAccountBanned(row)) return 'danger'
  return row.status === 'consumed'
    ? 'success'
    : row.status === 'failed'
      ? 'danger'
      : row.status === 'running'
        ? 'warning'
        : 'info'
}

export function statusLabel(row: MailboxRow) {
  return isMailboxAccountBanned(row)
    ? ACCOUNT_BANNED_DISPLAY_MESSAGE
    : (row.status_label || row.status)
}

export function explanation(row: MailboxRow) {
  if (isMailboxAccountBanned(row)) return ACCOUNT_BANNED_DISPLAY_MESSAGE
  const value = String(row.error || row.reason || '').trim()
  return value === 'sub2_uploaded' ? '-' : value || '-'
}

export function sub2Detail(row: MailboxRow) {
  const value = sub2Value(row)
  if (!value) return '尚未测试'
  const parts = [sub2Label(row)]
  if (value.summary) parts.push(String(value.summary))
  if (value.tested_at) {
    const date = parseTimestamp(value.tested_at)
    if (date) parts.push(formatDateTimeZh(value.tested_at))
  }
  return parts.join(' · ')
}

export function batchLabel(row: MailboxRow) {
  const value = Number(row.batch_started_at || 0)
  if (!value) return '-'
  return formatShortDateTime(value)
}

export function batchDetail(row: MailboxRow) {
  const label = batchLabel(row)
  return row.batch_id ? `${label} · ${row.batch_id}` : label
}

export function quotaLabel(value: MailboxRow['quota_5h'], status?: MailboxRow['quota_status']) {
  if (value?.remaining_percent == null) return status === 'ok' ? '-' : status === 'error' ? '失败' : '未查询'
  return `${Number(value.remaining_percent).toFixed(1)}%`
}

export function quotaDetail(
  value: MailboxRow['quota_5h'],
  status?: MailboxRow['quota_status'],
  error?: string,
) {
  if (status === 'error') {
    const parts = [error || 'OpenAI 额度查询失败']
    if (value?.remaining_percent != null) parts.push(`当前显示最近一次成功结果 ${quotaLabel(value, status)}`)
    return parts.join(' · ')
  }
  if (!value) {
    if (status === 'ok') return 'OpenAI 本次未返回该额度窗口'
    if (status === 'error') return 'OpenAI 额度查询失败'
    return '尚未查询 OpenAI 额度'
  }
  if (value.reset_at) {
    const date = new Date(Number(value.reset_at) * 1000)
    if (!Number.isNaN(date.getTime())) return `${quotaLabel(value, status)} · 重置 ${date.toLocaleString('zh-CN', { hour12: false })}`
  }
  return quotaLabel(value, status)
}
