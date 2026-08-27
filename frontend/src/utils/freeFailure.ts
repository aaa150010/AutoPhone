import type { TaskFailure } from '../types/api'

/** Stable, user-facing copy for a terminal OpenAI account ban. */
export const ACCOUNT_BANNED_DISPLAY_MESSAGE = 'OpenAI账号已被封禁'

/**
 * The diagnostic index contains both incident rows and timeline events. Keep
 * this small structural type independent from the API types so the display
 * mapping also works for older records with only a nested failure object.
 */
export interface DiagnosticNodeLike {
  status?: unknown
  outcome?: unknown
  node_code?: unknown
  node_label?: unknown
  first_node_code?: unknown
  first_node_label?: unknown
  first_error_code?: unknown
  error_code?: unknown
  provider_code?: unknown
  failure?: {
    node_code?: unknown
    error_code?: unknown
    provider_code?: unknown
  } | null
}

/** Outcomes that indicate the recorded operation reached a successful end. */
export function isSuccessfulDiagnosticOutcome(value: unknown): boolean {
  return ['success', 'succeeded', 'complete', 'completed', 'partial', 'partial_success']
    .includes(String(value || '').trim().toLowerCase())
}

export interface FreeFailureNodeIdentity {
  label: string
  code: string
  showCode: boolean
}

export function freeFailureNodeIdentity(failure?: TaskFailure | null): FreeFailureNodeIdentity {
  const label = String(failure?.node_label || '').trim()
  const code = String(failure?.node_code || '').trim()
  return { label, code, showCode: Boolean(label && code && code.toLowerCase() !== label.toLowerCase()) }
}

export function isAccountBannedFailure(failure?: TaskFailure | null): boolean {
  if (!failure) return false
  const values = [failure.node_code, failure.error_code, failure.provider_code]
    .map(value => String(value || '').trim().toLowerCase())
  return values.includes('account_banned')
}

/** Normalize the persisted retry marker across current and legacy payloads. */
export function isRetryResolved(value: unknown): boolean {
  return value === true || String(value || '').trim().toLowerCase() === 'true'
}

/**
 * A retry can retain its first failure for audit purposes after it succeeds.
 * Do not let that historical failure replace the task's current result.
 */
export function isCurrentAccountBanned(
  status?: unknown,
  failure?: TaskFailure | null,
  retryResolved?: unknown,
): boolean {
  const resolved = isRetryResolved(retryResolved)
  if (resolved) return false
  const normalizedStatus = String(status || '').trim().toLowerCase()
  return normalizedStatus === 'account_banned'
    || (!isSuccessfulDiagnosticOutcome(normalizedStatus) && isAccountBannedFailure(failure))
}

/** Return true when a diagnostic row/event explicitly identifies a ban. */
export function isAccountBannedDiagnostic(value?: DiagnosticNodeLike | null): boolean {
  if (!value) return false
  const failure = value.failure
  return [
    value.status,
    value.node_code,
    value.first_node_code,
    value.first_error_code,
    value.error_code,
    value.provider_code,
    failure?.node_code,
    failure?.error_code,
    failure?.provider_code,
  ].some(candidate => String(candidate || '').trim().toLowerCase() === 'account_banned')
}

/** Resolve a diagnostic node label without rewriting its stable node code. */
export function diagnosticNodeLabel(value?: DiagnosticNodeLike | null, fallback = '未命名节点'): string {
  if (isAccountBannedDiagnostic(value)) return ACCOUNT_BANNED_DISPLAY_MESSAGE
  const label = String(value?.first_node_label || value?.node_label || '').trim()
  const code = String(value?.first_node_code || value?.node_code || '').trim()
  return label || code || fallback
}

/**
 * Resolve an incident's first-failure label without turning a historical ban
 * into the current status after a later retry succeeds.
 */
export function diagnosticIncidentNodeLabel(value?: DiagnosticNodeLike | null, fallback = '-'): string {
  const successful = isSuccessfulDiagnosticOutcome(value?.status) || isSuccessfulDiagnosticOutcome(value?.outcome)
  if (!successful && isAccountBannedDiagnostic(value)) return ACCOUNT_BANNED_DISPLAY_MESSAGE
  const label = String(value?.first_node_label || value?.first_node_code || '').trim()
  return label || fallback
}

/** Resolve a timeline label while preserving successful historical events. */
export function diagnosticEventNodeLabel(value?: DiagnosticNodeLike | null, fallback = '未命名节点'): string {
  if (!isSuccessfulDiagnosticOutcome(value?.outcome) && isAccountBannedDiagnostic(value)) {
    return ACCOUNT_BANNED_DISPLAY_MESSAGE
  }
  const label = String(value?.node_label || value?.node_code || '').trim()
  return label || fallback
}

export function freeFailureCause(
  failure?: TaskFailure | null,
  options: { retryResolved?: unknown } = {},
): string {
  const retryResolved = options.retryResolved === true
    || String(options.retryResolved || '').trim().toLowerCase() === 'true'
  if (retryResolved) return '已由重试解决'
  if (!failure) return '-'
  if (isAccountBannedFailure(failure)) return ACCOUNT_BANNED_DISPLAY_MESSAGE
  const message = String(failure.public_message || '').trim()
  const label = String(failure.node_label || '').trim()
  const code = String(failure.node_code || '').trim()
  if (!message) return '-'
  const identity = label && code ? `${label} [${label}/${code}]` : ''
  for (const prefix of [
    identity ? `${identity}：` : '',
    identity ? `${identity}:` : '',
    label ? `${label}失败：` : '',
    label ? `${label}失败:` : '',
    label ? `${label}：` : '',
    label ? `${label}:` : '',
  ]) {
    if (prefix && message.startsWith(prefix)) return message.slice(prefix.length).trim() || '-'
  }
  return message
}

export function selectCurrentFreeFailure(
  registrationFailure?: TaskFailure | null,
  liveCheckFailure?: TaskFailure | null,
  liveCheckStatus = '',
): TaskFailure | null {
  const status = String(liveCheckStatus || '').trim().toLowerCase()
  const liveFailureIsCurrent = Boolean(liveCheckFailure)
    && ['deactivated', 'token_expired', 'failed', 'free_live_proxy_blocked', 'free_live_session_rejected', 'free_live_rate_limited', 'free_live_upstream_error', 'free_live_network_error', 'free_live_password_required'].includes(status)
  return liveFailureIsCurrent ? liveCheckFailure || null : registrationFailure || null
}

export function freeFailureDetails(
  failure?: TaskFailure | null,
  options: { includeNode?: boolean } = {},
): string[] {
  if (!failure) return []
  const page = safeFailurePage(failure.safe_page)
  const rebuilds = failure.session_rebuilds
  const node = freeFailureNodeIdentity(failure)
  return [
    options.includeNode && (node.label || node.code)
      ? `节点：${node.label || node.code}${node.showCode ? ` · ${node.code}` : ''}`
      : '',
    failure.http_status ? `HTTP 状态：${failure.http_status}` : '',
    failure.provider_code ? `服务端代码：${failure.provider_code}` : '',
    failure.error_code ? `错误代码：${failure.error_code}` : '',
    failure.page_type ? `页面类型：${failure.page_type}` : '',
    page ? `安全页面：${page}` : '',
    failure.content_type ? `响应类型：${failure.content_type}` : '',
    rebuilds !== undefined && rebuilds !== null ? `会话重建：${rebuilds} 次` : '',
    failure.technical_summary ? `技术摘要：${failure.technical_summary}` : '',
    failure.action_hint ? `处理建议：${failure.action_hint}` : '',
  ].filter(Boolean)
}

function safeFailurePage(value?: string): string {
  const raw = String(value || '').trim()
  if (!raw) return ''
  if (raw.startsWith('/')) return raw.replace(/[?#].*$/, '')
  try {
    const parsed = new URL(raw)
    return `${parsed.protocol}//${parsed.host}${parsed.pathname || '/'}`
  } catch {
    return '[页面地址已隐藏]'
  }
}
