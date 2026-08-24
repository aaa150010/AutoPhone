import type { TaskFailure } from '../types/api'

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

export function freeFailureCause(failure?: TaskFailure | null): string {
  if (!failure) return '-'
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
    && ['deactivated', 'token_expired', 'failed'].includes(status)
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
