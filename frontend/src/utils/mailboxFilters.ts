import type { MailboxRow, Sub2MailboxStatus } from '../types/api'

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

export function isLatestMailboxBatchFailure(row: MailboxRow) {
  const status = String(row.task_status || '').trim().toLowerCase()
  if (NON_FAILED_TASK_STATUSES.has(status)) return false
  if (FAILED_TASK_STATUSES.has(status)) return true
  return Boolean(row.failure && typeof row.failure === 'object')
}
