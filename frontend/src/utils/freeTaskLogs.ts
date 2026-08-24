import type { FreeLogEntry } from '../types/api'

export type FreeLogLevelFilter = 'all' | 'error' | 'warn' | 'success' | 'info' | 'debug'

export interface IndexedFreeLog {
  index: number
  row: FreeLogEntry
}

export const FREE_LOG_WINDOW_SIZE = 250

export function normalizeFreeLogLevel(value?: string): Exclude<FreeLogLevelFilter, 'all'> {
  const level = String(value || '').trim().toLowerCase()
  if (['error', 'fatal', 'failed', 'failure'].includes(level)) return 'error'
  if (['warn', 'warning'].includes(level)) return 'warn'
  if (['success', 'ok', 'completed'].includes(level)) return 'success'
  if (['debug', 'trace'].includes(level)) return 'debug'
  return 'info'
}

export function freeLogNodeCode(row: FreeLogEntry): string {
  return String(row.node_code || row.stage || '').trim()
}

export function freeLogNodeLabel(row: FreeLogEntry): string {
  return String(row.node_label || row.stage_label || '').trim()
}

export function shouldShowFreeLogNodeCode(row: FreeLogEntry): boolean {
  const code = freeLogNodeCode(row)
  const label = freeLogNodeLabel(row)
  return Boolean(label && code && code.toLowerCase() !== label.toLowerCase())
}

export function freeLogLevelLabel(value?: string): string {
  return ({ error: '错误', warn: '警告', success: '成功', info: '信息', debug: '调试' } as const)[normalizeFreeLogLevel(value)]
}

export function effectiveFreeLogLevel(row: FreeLogEntry): Exclude<FreeLogLevelFilter, 'all'> {
  const outcome = String(row.outcome || '').trim().toLowerCase()
  if (
    normalizeFreeLogLevel(row.level) === 'error'
    || ['error', 'failed', 'failure'].includes(outcome)
    || Boolean(row.error_code)
  ) return 'error'
  return normalizeFreeLogLevel(row.level)
}

export function isFreeLogError(row: FreeLogEntry): boolean {
  return effectiveFreeLogLevel(row) === 'error'
}

export function safeFreeLogPage(value?: string): string {
  const raw = String(value || '').trim()
  if (!raw) return ''
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) && !raw.startsWith('/')) {
    if (looksLikeUnschemedProxy(raw)) return '[代理地址已隐藏]'
    return redactFreeLogCredentials(raw.replace(/[?#].*$/, ''))
  }
  try {
    const parsed = new URL(raw, 'http://local.invalid')
    const pathname = parsed.pathname || '/'
    return parsed.host === 'local.invalid' && raw.startsWith('/') ? pathname : `${parsed.protocol}//${parsed.host}${pathname}`
  } catch {
    return redactFreeLogCredentials(raw.replace(/[?#].*$/, ''))
  }
}

function redactFreeLogCredentials(value: string): string {
  return value.replace(/(^|\/\/)[^/\s@]+@(?=[^/\s]+)/g, '$1***@')
}

function looksLikeUnschemedProxy(value: string): boolean {
  const address = value.replace(/[/?#].*$/, '')
  if (/^[^@\s]+@[^@\s]+$/.test(address) && address.includes(':')) return true
  return /^(?:\[[^\]]+\]|[^:\s]+):\d+:[^:\s]+:.+$/.test(address)
}

export function freeLogContextText(row: FreeLogEntry): string {
  const page = safeFreeLogPage(row.safe_page || row.page)
  const rebuilds = row.session_rebuilds
  return [
    row.duration_ms ? `${row.duration_ms}ms` : '',
    row.page_type ? `页面 ${row.page_type}` : '',
    page,
    row.content_type ? `响应 ${row.content_type}` : '',
    row.http_status ? `HTTP ${row.http_status}` : '',
    rebuilds !== undefined && rebuilds !== null ? `会话重建 ${rebuilds} 次` : '',
    row.attempt ? `第 ${row.attempt} 次` : '',
    row.outcome ? String(row.outcome) : '',
    row.result ? `结果 ${redactFreeLogCredentials(String(row.result))}` : '',
    row.retryable !== undefined ? `可重试 ${row.retryable ? '是' : '否'}` : '',
  ].filter(Boolean).join(' · ')
}

export function filterFreeLogs(
  rows: FreeLogEntry[],
  level: FreeLogLevelFilter = 'all',
  nodeCode = '',
): IndexedFreeLog[] {
  return rows.reduce<IndexedFreeLog[]>((result, row, index) => {
    if (level !== 'all' && effectiveFreeLogLevel(row) !== level) return result
    if (nodeCode && freeLogNodeCode(row) !== nodeCode) return result
    result.push({ row, index })
    return result
  }, [])
}

export function clampFreeLogWindowStart(total: number, requested: number, windowSize = FREE_LOG_WINDOW_SIZE): number {
  const safeTotal = Math.max(0, Math.trunc(total))
  const safeSize = Math.max(1, Math.trunc(windowSize))
  const maxStart = safeTotal ? Math.floor((safeTotal - 1) / safeSize) * safeSize : 0
  return Math.min(maxStart, Math.max(0, Math.trunc(requested) || 0))
}

export function latestFreeLogWindowStart(total: number, windowSize = FREE_LOG_WINDOW_SIZE): number {
  return containingFreeLogWindowStart(Math.max(0, total - 1), total, windowSize)
}

export function containingFreeLogWindowStart(position: number, total: number, windowSize = FREE_LOG_WINDOW_SIZE): number {
  const safeSize = Math.max(1, Math.trunc(windowSize))
  const requested = Math.floor(Math.max(0, position) / safeSize) * safeSize
  return clampFreeLogWindowStart(total, requested, safeSize)
}
