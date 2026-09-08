/** Pure display helpers for the Free mailbox pool table (live/plan columns).

Mirrors ``freeTaskDisplay`` for the mailbox-pool row shape: every function is
a pure projection over a ``FreeMailboxRow``.
*/

import type { FreeMailboxRow } from '../types/free'
import { formatDateTime } from './datetime'
import {
  ACCOUNT_BANNED_DISPLAY_MESSAGE,
  freeFailureCause,
  freeFailureDetails,
  freeFailureNodeIdentity,
  isAccountBannedFailure,
  isCurrentAccountBanned,
  isRetryResolved,
  selectCurrentFreeFailure,
  type FreeFailureNodeIdentity,
} from './freeFailure'
import { freeStageDetail, freeStageLabel, freeStageType } from './freeStage'

export function isHistoricalMailboxDriver(row: FreeMailboxRow | null | undefined): boolean {
  const driver = String(row?.driver || '').trim().toLowerCase()
  return Boolean(driver) && driver !== 'protocol' && driver !== 'camoufox'
}

export function mailboxDriverLabel(row: FreeMailboxRow | null | undefined): string {
  const driver = String(row?.driver || '').trim().toLowerCase()
  if (driver === 'camoufox') return 'Camoufox'
  if (driver === 'protocol') return '全协议'
  if (!driver) return '未运行'
  return '历史链路'
}

export function mailboxCreatedText(row: FreeMailboxRow | null | undefined): string {
  return formatDateTime(row?.created_at)
}

export function mailboxRowClass(row: FreeMailboxRow | null | undefined): string {
  return ['failed', 'partial_success'].includes(String(row?.status || '')) && !isRetryResolved(row?.retry_resolved)
    ? 'is-danger-row'
    : ''
}

export function mailboxCurrentFailure(row: FreeMailboxRow | null | undefined) {
  return selectCurrentFreeFailure(row?.failure, row?.live_check_failure, row?.live_check_status)
}

export function mailboxFailureCause(row: FreeMailboxRow | null | undefined): string {
  return freeFailureCause(mailboxCurrentFailure(row), { retryResolved: row?.retry_resolved })
}

export function mailboxFailureDetails(row: FreeMailboxRow | null | undefined): string[] {
  return freeFailureDetails(mailboxCurrentFailure(row), { includeNode: true })
}

export function mailboxFailureNode(row: FreeMailboxRow | null | undefined): FreeFailureNodeIdentity {
  return freeFailureNodeIdentity(mailboxCurrentFailure(row))
}

export function mailboxIsAccountBanned(row: FreeMailboxRow | null | undefined): boolean {
  if (isCurrentAccountBanned(row?.status, row?.failure, row?.retry_resolved)) return true
  const liveStatus = String(row?.live_check_status || '').trim().toLowerCase()
  // A completed registration can later be disabled during a live check. That
  // is current account state, unlike a retained registration failure.
  return ['deactivated', 'failed'].includes(liveStatus)
    && isAccountBannedFailure(row?.live_check_failure)
}

export function liveStatusLabel(status = ''): string {
  return ({ queued: '排队', running: '测活中', live: '正常', deactivated: '已停用', token_expired: 'Token 失效', free_live_proxy_blocked: '出口/反爬拒绝', free_live_session_rejected: 'Session 被拒绝', free_live_rate_limited: '触发限流', free_live_upstream_error: '上游异常', free_live_network_error: '网络异常', free_live_password_required: '需要真实密码', failed: '失败' } as Record<string, string>)[status] || '未测活'
}

export function liveStatusType(status = ''): string {
  return status === 'live' ? 'success' : status === 'deactivated' || status === 'failed' ? 'danger' : status === 'token_expired' || status === 'free_live_proxy_blocked' || status === 'free_live_session_rejected' || status === 'free_live_rate_limited' || status === 'free_live_upstream_error' || status === 'free_live_network_error' || status === 'free_live_password_required' ? 'warning' : 'info'
}

export function mailboxPlanLabel(row: FreeMailboxRow | null | undefined): string {
  const plan = String(row?.subscription_plan || row?.plan_type || '').trim()
  const normalized = plan.toLowerCase()
  const status = String(row?.plan_check_status || '').toLowerCase()
  if (status === 'failed') return '查询失败'
  if (['queued', 'running'].includes(status)) return '查询中'
  if (!plan) return '未查询'
  const hasPerk = Boolean(row?.plus_trial_eligible) || normalized.includes('plus') || normalized.includes('pro') || normalized.includes('team')
  return hasPerk ? '有优惠' : '无优惠'
}

export function mailboxPlanTagType(row: FreeMailboxRow | null | undefined): string {
  const plan = String(row?.subscription_plan || row?.plan_type || '').toLowerCase()
  const status = String(row?.plan_check_status || '').toLowerCase()
  if (status === 'failed') return 'danger'
  if (['queued', 'running'].includes(status)) return 'warning'
  if (!plan) return 'info'
  const hasPerk = Boolean(row?.plus_trial_eligible) || plan.includes('plus') || plan.includes('pro') || plan.includes('team')
  return hasPerk ? 'success' : 'info'
}

export function mailboxStageLabel(row: FreeMailboxRow | null | undefined): string {
  if (mailboxIsAccountBanned(row)) return ACCOUNT_BANNED_DISPLAY_MESSAGE
  const remaining = Number(row?.cooldown_remaining || 0)
  if (remaining > 0) return `限流冷却 ${Math.ceil(remaining / 60)} 分钟`
  return freeStageLabel(row?.stage || row?.status, '可用', row?.status)
}

export function mailboxStageType(row: FreeMailboxRow | null | undefined): string {
  if (mailboxIsAccountBanned(row)) return 'danger'
  if (row?.cooldown_remaining) return 'warning'
  if (['live', 'available'].includes(String(row?.live_check_status || '').toLowerCase())) return 'success'
  return freeStageType(row?.stage || row?.status, row?.status)
}

export function mailboxStageTooltip(row: FreeMailboxRow | null | undefined): string {
  return freeStageDetail(row?.stage || row?.status, mailboxStageLabel(row), row?.status)
}
