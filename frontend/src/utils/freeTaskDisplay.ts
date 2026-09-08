/** Pure display helpers for Free registration task rows. */

import type { FreeTaskRow } from '../types/free'
import { formatDateTime } from './datetime'
import { ACCOUNT_BANNED_DISPLAY_MESSAGE, isCurrentAccountBanned, isRetryResolved } from './freeFailure'

export function taskDriverLabel(driver: unknown): string {
  const value = String(driver || '').trim().toLowerCase()
  if (value === 'camoufox') return 'Camoufox'
  if (value === 'protocol') return '全协议'
  return value ? '历史链路' : '全协议'
}

export function isHistoricalDriver(task: FreeTaskRow | null | undefined): boolean {
  const value = String(task?.driver || '').trim().toLowerCase()
  return Boolean(value) && value !== 'protocol' && value !== 'camoufox'
}

export function taskCreatedText(task: FreeTaskRow | null | undefined): string {
  if (!task?.created_at) return ''
  return formatDateTime(task.created_at)
}

export function taskIncidentId(task: FreeTaskRow | null | undefined): string {
  return String(task?.incident_id || task?.failure?.incident_id || '').trim()
}

export function taskStatusLabel(status: string): string {
  return ({ queued: '排队', running: '运行中', success: '成功', partial_success: '部分成功', failed: '失败', pending_rerun: '待重跑', stopped: '已停止', twofa_pending: '2FA 待重试', account_banned: ACCOUNT_BANNED_DISPLAY_MESSAGE } as Record<string, string>)[status] || status || '-'
}

export function displayTaskStatus(task: FreeTaskRow | null | undefined): string {
  if (isCurrentAccountBanned(task?.status, task?.failure, task?.retry_resolved)) {
    return ACCOUNT_BANNED_DISPLAY_MESSAGE
  }
  return isRetryResolved(task?.retry_resolved) ? '已由重试解决' : taskStatusLabel(String(task?.status || ''))
}

export function taskStatusType(status: string): 'success' | 'warning' | 'danger' | 'info' {
  return ['success'].includes(status)
    ? 'success'
    : ['partial_success', 'pending_rerun', 'twofa_pending'].includes(status)
      ? 'warning'
      : ['failed', 'account_banned'].includes(status)
        ? 'danger'
        : status === 'stopped' ? 'info' : 'warning'
}

export function taskPlanLabel(task: FreeTaskRow | null | undefined): string {
  const plan = String(task?.result?.subscription_plan || task?.result?.plan_type || '').trim()
  const status = String(task?.result?.plan_check_status || '').toLowerCase()
  if (status === 'failed') return '查询失败'
  if (['queued', 'running'].includes(status)) return '查询中'
  if (!plan) return '未查询'
  const hasPerk = Boolean(task?.result?.plus_trial_eligible) || plan.includes('plus') || plan.includes('pro') || plan.includes('team') || plan.includes('go')
  return hasPerk ? '有优惠' : '无优惠'
}

export function taskPlanType(task: FreeTaskRow | null | undefined): 'success' | 'warning' | 'info' | 'danger' {
  const plan = String(task?.result?.subscription_plan || task?.result?.plan_type || '').toLowerCase()
  const status = String(task?.result?.plan_check_status || '').toLowerCase()
  if (status === 'failed') return 'danger'
  if (['queued', 'running'].includes(status)) return 'warning'
  if (!plan) return 'info'
  const hasPerk = Boolean(task?.result?.plus_trial_eligible) || plan.includes('plus') || plan.includes('pro') || plan.includes('team') || plan.includes('go')
  return hasPerk ? 'success' : 'info'
}

export function taskTwofaLabel(task: FreeTaskRow | null | undefined): string {
  const status = String(task?.result?.twofa_status || '').toLowerCase()
  if (task?.result?.has_totp || task?.result?.totp_secret) return '已启用'
  if (['queued', 'running'].includes(String(task?.status || '').toLowerCase())) return '处理中'
  if (['pending', 'failed'].includes(status)) return '待重试'
  return '未启用'
}

export function taskTwofaType(task: FreeTaskRow | null | undefined): 'success' | 'warning' | 'info' {
  const status = String(task?.result?.twofa_status || '').toLowerCase()
  if (task?.result?.has_totp || task?.result?.totp_secret) return 'success'
  if (['queued', 'running'].includes(String(task?.status || '').toLowerCase())) return 'warning'
  return ['pending', 'failed'].includes(status) ? 'warning' : 'info'
}

export function taskPasswordLabel(task: FreeTaskRow | null | undefined): string {
  const status = String(task?.result?.password_status || '').toLowerCase()
  const flow = String(task?.result?.account_flow || '').toLowerCase()
  if (task?.result?.has_password || status === 'enabled') return '已设置'
  if (status === 'pending') return '待重试'
  if (status === 'disabled' && flow === 'signup') return '未设置（可补设）'
  return '未设置'
}

export function taskPasswordType(task: FreeTaskRow | null | undefined): 'success' | 'warning' | 'info' {
  const status = String(task?.result?.password_status || '').toLowerCase()
  const flow = String(task?.result?.account_flow || '').toLowerCase()
  if (task?.result?.has_password || status === 'enabled') return 'success'
  if (status === 'pending' || (status === 'disabled' && flow === 'signup')) return 'warning'
  return 'info'
}

export function taskRowClass({ row }: { row: FreeTaskRow }): string {
  return ['failed', 'partial_success'].includes(String(row?.status || '')) && !isRetryResolved(row?.retry_resolved)
    ? 'is-danger-row'
    : ''
}

export function canRetryPassword(task: FreeTaskRow | null | undefined): boolean {
  if (isHistoricalDriver(task)) return false
  const status = String(task?.result?.password_status || '').toLowerCase()
  const accountFlow = String(task?.result?.account_flow || '').toLowerCase()
  if (accountFlow === 'existing_login') return false
  const taskStatus = String(task?.status || '')
  return ['success', 'partial_success', 'twofa_pending', 'failed', 'pending_rerun'].includes(taskStatus)
    && (status === 'pending' || (status === 'disabled' && accountFlow === 'signup'))
}

export function automaticOtpRemaining(task: FreeTaskRow | null | undefined, nowSeconds: number): number {
  const verification = task?.mailbox_verification
  if (verification?.phase !== 'automatic') return 0
  return Math.max(0, Math.floor(Number(verification.deadline_at || 0) - nowSeconds))
}

export function taskNeedsExistingPassword(task: FreeTaskRow | null | undefined): boolean {
  return String(task?.failure?.error_code || '').trim().toLowerCase() === 'free_existing_login_password_missing'
}
