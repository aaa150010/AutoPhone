import type { MailboxOperationKind, MailboxRow, Sub2MailboxStatus } from '../types/api'

const NETWORK_KINDS = new Set(['network_error', 'remote_disconnected', 'timeout'])
const FAILED_TASK_STATUSES = new Set(['failed', 'email_damaged', 'account_banned'])
const NON_FAILED_TASK_STATUSES = new Set([
  'queued',
  'pending',
  'running',
  'active',
  'success',
  'succeeded',
  'completed',
  'stopped',
  'stopped_before_start',
  'cancelled',
  'canceled',
])
const NON_NETWORK_PATTERN = /(?:\b(?:401|404|429)\b|unauthori[sz]ed|not[_ -]?found|rate[_ -]?limit|协议|限流|token\s*失效|账号不存在|额度受限)/i
const NETWORK_PATTERN = /(?:openai_quota_(?:probe_)?network_error|network[_ -]?error|remote[_ -]?disconnected|\btimeout\b|timed\s*out|网络(?:请求)?(?:失败|错误|异常|中断|断开|超时)|连接(?:已)?(?:中断|断开|失败|重置|超时)|请求超时|connection\s+(?:reset|closed|aborted|failed|timed\s*out))/i

function statusCode(status: Sub2MailboxStatus | null | undefined) {
  const code = Number(status?.status_code ?? status?.code)
  return Number.isFinite(code) ? code : null
}

export function isSub2TestFailure(status: Sub2MailboxStatus | null | undefined) {
  if (!status || status.linked === false) return false
  const code = statusCode(status)
  if (code === 200 || code === 401 || code === 429) return false
  if (status.is_test_failure != null) return Boolean(status.is_test_failure)
  if (code === 404) return true
  const kind = String(status.kind || status.status || '').toLowerCase()
  if (['untested', 'unlinked', 'not_linked', 'not_ready', 'rate_limited', 'healthy', 'unauthorized'].includes(kind)) return false
  return Boolean(status.is_error || code)
}

export function needsSub2Rerun(status: Sub2MailboxStatus | null | undefined) {
  const code = statusCode(status)
  if (code === 429) return false
  return Boolean(status?.needs_rerun) || code === 401 || code === 404
}

export function isMailboxNetworkDisconnected(row: MailboxRow) {
  const openaiStatus = row.sub2_status
  const openaiKind = String(openaiStatus?.kind || openaiStatus?.status || '').trim().toLowerCase()
  const openaiCode = statusCode(openaiStatus)
  if (![401, 404, 429].includes(Number(openaiCode)) && NETWORK_KINDS.has(openaiKind)) return true

  if (row.quota_status !== 'error') return false
  const quotaDetail = [
    (row as any).quota_error_code,
    (row as any).quota_code,
    row.quota_error,
  ].filter(Boolean).join(' ')
  return Boolean(quotaDetail && !NON_NETWORK_PATTERN.test(quotaDetail) && NETWORK_PATTERN.test(quotaDetail))
}

export function mailboxBatchCandidates(rows: MailboxRow[], kind: MailboxOperationKind) {
  if (kind === 'openai_test') return rows
  return rows.filter(row => row.status === 'consumed' && Boolean(row.task_id))
}

export function latestMailboxBatchId(rows: MailboxRow[]) {
  const batches = new Map<string, number>()
  for (const row of rows) {
    const batchId = String(row.batch_id || '').trim()
    const startedAt = Number(row.batch_started_at || 0)
    if (!batchId || !Number.isFinite(startedAt) || startedAt <= 0) continue
    batches.set(batchId, Math.max(batches.get(batchId) || 0, startedAt))
  }
  let latestId = ''
  let latestStartedAt = 0
  for (const [batchId, startedAt] of batches) {
    if (startedAt > latestStartedAt || (startedAt === latestStartedAt && batchId > latestId)) {
      latestId = batchId
      latestStartedAt = startedAt
    }
  }
  return latestId
}

export interface MailboxBatchOption {
  batchId: string
  startedAt: number
}

export function mailboxBatchOptions(rows: MailboxRow[]): MailboxBatchOption[] {
  const batches = new Map<string, number>()
  for (const row of rows) {
    const batchId = String(row.batch_id || '').trim()
    if (!batchId) continue
    const startedAt = Number(row.batch_started_at || 0)
    batches.set(batchId, Math.max(batches.get(batchId) || 0, Number.isFinite(startedAt) ? startedAt : 0))
  }
  return [...batches.entries()]
    .map(([batchId, startedAt]) => ({ batchId, startedAt }))
    .sort((left, right) => right.startedAt - left.startedAt || right.batchId.localeCompare(left.batchId))
}

export function isLatestMailboxBatchFailure(row: MailboxRow) {
  const status = String(row.task_status || '').trim().toLowerCase()
  if (NON_FAILED_TASK_STATUSES.has(status)) return false
  if (FAILED_TASK_STATUSES.has(status)) return true
  return Boolean(row.failure && typeof row.failure === 'object')
}

export interface MailboxViewFilters {
  status: string
  batchId?: string
  sub2: string
  quota: string
  search: string
  latestBatchId: string
}

export function matchesMailboxView(row: MailboxRow, filters: MailboxViewFilters) {
  if (row.status === 'draft') return false
  const inLatestBatch = Boolean(filters.latestBatchId && row.batch_id === filters.latestBatchId)
  const matchesBatch = !filters.batchId || filters.batchId === 'all' || row.batch_id === filters.batchId
  const matchesStatus = filters.status === 'all'
    || (filters.status === 'latest_batch' && inLatestBatch)
    || (filters.status === 'latest_batch_failed' && inLatestBatch && isLatestMailboxBatchFailure(row))
    || (filters.status === 'not_consumed' ? row.status !== 'consumed' : row.status === filters.status)
  const sub2Status = row.sub2_status || (row as any).sub2
  const matchesSub2 = filters.sub2 === 'all'
    || (filters.sub2 === 'test_failure' && isSub2TestFailure(sub2Status))
    || (filters.sub2 === 'needs_rerun' && needsSub2Rerun(sub2Status))
    || (filters.sub2 === 'network_disconnected' && isMailboxNetworkDisconnected(row))
  const hasRemainingQuota = [row.quota_5h, row.quota_7d].some(window => (
    window?.remaining_percent != null && Number(window.remaining_percent) > 0
  ))
  const matchesQuota = filters.quota === 'all'
    || (filters.quota === 'remaining' && hasRemainingQuota)
    || (filters.quota === 'queried' && ['ok', 'error'].includes(String(row.quota_status || '')))
  const query = filters.search.trim().toLowerCase()
  const haystack = [
    row.email, row.status, row.status_label, row.task_status, row.progress?.label,
    row.error, row.reason, sub2Status?.label, sub2Status?.summary, row.batch_id,
  ].join(' ').toLowerCase()
  return matchesBatch && matchesStatus && matchesSub2 && matchesQuota && (!query || haystack.includes(query))
}
