import type {
  MailboxOperationRowUpdate,
  MailboxRow,
  OpenAIQuotaWindow,
} from '../types/api'

export interface MailboxQuotaResult {
  row_id: string
  line_no: number
  status: string
  error?: string
  queried_at?: number | null
  quota_5h?: OpenAIQuotaWindow | null
  quota_7d?: OpenAIQuotaWindow | null
}

function rowKey(value: { row_id: string; line_no: number }) {
  return `${String(value.row_id).toLowerCase()}\u0000${Number(value.line_no)}`
}

function timestamp(value: unknown) {
  const numeric = Number(value || 0)
  return Number.isFinite(numeric) ? numeric : 0
}

export function canSetMailboxRowsUnavailable(rows: MailboxRow[]) {
  return rows.length > 0 && rows.every(row => row.status !== 'running')
}

export function mergeMailboxQuotaResults(
  rows: MailboxRow[],
  results: MailboxQuotaResult[],
): MailboxRow[] {
  const byRow = new Map(results.map(result => [rowKey(result), result]))
  return rows.map((row) => {
    const result = byRow.get(rowKey(row))
    if (!result) return row
    return {
      ...row,
      quota_status: result.status,
      quota_error: result.error || '',
      quota_queried_at: result.queried_at || Math.floor(Date.now() / 1000),
      quota_5h: result.quota_5h ?? null,
      quota_7d: result.quota_7d ?? null,
    }
  })
}

export function mergeMailboxOperationUpdates(
  rows: MailboxRow[],
  updates: MailboxOperationRowUpdate[],
): MailboxRow[] {
  const byRow = new Map(updates.map(update => [rowKey(update), update]))
  return rows.map((row) => {
    const update = byRow.get(rowKey(row))
    if (!update) return row
    let merged = row
    if (
      update.quota_status
      && timestamp(update.quota_queried_at) >= timestamp(row.quota_queried_at)
    ) {
      merged = {
        ...merged,
        quota_status: update.quota_status,
        quota_error: update.quota_error || '',
        quota_queried_at: update.quota_queried_at ?? null,
        quota_5h: update.quota_5h ?? null,
        quota_7d: update.quota_7d ?? null,
      }
    }
    if (
      update.sub2_status
      && timestamp(update.sub2_status.tested_at) >= timestamp(row.sub2_status?.tested_at)
    ) {
      merged = { ...merged, sub2_status: update.sub2_status }
    }
    return merged
  })
}
