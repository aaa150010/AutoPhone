import type {
  ApiErrorPayload,
  AppState,
  MailboxBatchOperation,
  MailboxOperationKind,
  MailboxPayload,
  MailboxUrlTestResult,
  PixelAccountPage,
  PixelBulkOperationResponse,
  PixelBatchPage,
  PixelBatchRecordPage,
  PixelOverview,
  PixelUploadRecord,
  NvOverview,
  NvUploadBatchPage,
  NvUploadBatch,
  NvUploadRecordPage,
  NvUploadRecord,
  BatchUploadManifest,
  ManualVerificationAccepted,
  ManualVerificationSubmission,
  SmsKeyStatus,
} from '../types/api'

export class ApiError extends Error {
  status: number
  payload: ApiErrorPayload

  constructor(message: string, status: number, payload: ApiErrorPayload = {}) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.payload = payload
  }
}

export async function api<T = any>(path: string, body?: unknown): Promise<T> {
  const options: RequestInit = body === undefined
    ? { cache: 'no-store' }
    : {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        cache: 'no-store',
      }
  const response = await fetch(path, options)
  const payload = await response.json().catch(() => ({}))
  if (!response.ok || payload.ok === false) {
    throw new ApiError(payload.error || '操作失败', response.status, payload)
  }
  return payload
}

export const getState = () => api<{ state: AppState }>('/api/state')
export const getLocalConfig = () => api<{ config: Record<string, any> }>('/api/local-config')
export const getSecret = (id: string) => api<{ value: any }>('/api/local-config/secret', { id })
export const saveConfig = (data: Record<string, any>) => api('/api/config', data)
export const updateOpenAIConnectivityGuard = (enabled: boolean) => api<{
  ok: true
  enabled: boolean
  settings?: Record<string, any>
  state?: AppState
}>('/api/openai-connectivity-guard', { enabled })
export const preflightRun = (data: Record<string, any>) => api('/api/preflight', data)
export const startExistingRun = (data: Record<string, any>) => api('/api/start-existing', data)
export const stopRun = () => api('/api/stop', {})
export const getMailboxes = () => api<MailboxPayload>('/api/mailboxes')
export const importMailboxes = (poolContent: string) => api<{
  ok: true
  imported: number
  skipped: number
  mailboxes?: MailboxPayload
  state?: AppState
  mailboxes_refresh_required?: boolean
  state_refresh_required?: boolean
}>('/api/mailboxes/import', { pool_content: poolContent })
export const queryMailboxQuotas = (rows: Array<{ row_id: string; line_no: number }>) => (
  api<{
    ok: true
    results: Array<{
      row_id: string
      line_no: number
      status: 'ok' | 'error' | string
      quota_5h?: import('../types/api').OpenAIQuotaWindow | null
      quota_7d?: import('../types/api').OpenAIQuotaWindow | null
      queried_at?: number | null
      error?: string
    }>
    queried?: number
    failed?: number
    skipped?: number
  }>('/api/mailboxes/quota', { rows })
)
export const startMailboxBatchOperation = (
  kind: MailboxOperationKind,
  rows: Array<{ row_id: string; line_no: number }>,
) => api<{
  ok: true
  background: true
  created: boolean
  operation: MailboxBatchOperation
}>(kind === 'quota' ? '/api/mailboxes/quota' : '/api/mailboxes/openai-test', {
  background: true,
  rows,
})
export const retryMailboxPixel = (rows: Array<{ row_id: string; line_no: number }>) => (
  api('/api/mailboxes/pixel-retry', { rows })
)
export const setMailboxRowsUnavailable = (rows: Array<{ row_id: string; line_no: number }>) => (
  api<{ ok: true; unavailable: number; mailboxes?: MailboxPayload; state?: AppState }>(
    '/api/mailboxes/unavailable',
    { rows, line_nos: rows.map(row => row.line_no) },
  )
)
export const moveMailboxRowsToDraft = (rows: Array<{ row_id: string; line_no: number }>) => (
  api<{ ok: true; drafted: number; mailboxes?: MailboxPayload; state?: AppState }>(
    '/api/mailboxes/draft',
    { rows, line_nos: rows.map(row => row.line_no) },
  )
)
export const restoreMailboxDraftRows = (rows: Array<{ row_id: string; line_no: number }>) => (
  api<{ ok: true; restored: number; mailboxes?: MailboxPayload; state?: AppState }>(
    '/api/mailboxes/draft/restore',
    { rows, line_nos: rows.map(row => row.line_no) },
  )
)
export const markMailboxRowsManualUsed = (rows: Array<{ row_id: string; line_no: number }>) => (
  api<{ ok: true; used: number; mailboxes?: MailboxPayload; state?: AppState }>(
    '/api/mailboxes/manual-used',
    { rows, line_nos: rows.map(row => row.line_no) },
  )
)
export const restoreMailboxRowsManualUsed = (rows: Array<{ row_id: string; line_no: number }>) => (
  api<{ ok: true; restored: number; mailboxes?: MailboxPayload; state?: AppState }>(
    '/api/mailboxes/manual-unused',
    { rows, line_nos: rows.map(row => row.line_no) },
  )
)
export const exportMailboxSub2 = (rows: Array<{ row_id: string; line_no: number }>) => (
  api<{ count: number; skipped?: number; filename: string; export: Record<string, any> }>(
    '/api/mailboxes/sub2-export',
    { rows },
  )
)
export const exportMailboxSource = (rows: Array<{ row_id: string; line_no: number }>) => (
  api<{ ok: true; count: number; filename: string; content: string }>(
    '/api/mailboxes/source-export',
    { rows },
  )
)
export const getMailboxTotp = (row: { row_id: string; line_no: number }) => (
  api<{ ok: true; kind: 'totp'; code: string; remaining: number }>('/api/mailboxes/totp', row)
)
export const getMailboxUrl = (row: { row_id: string; line_no: number }) => (
  api<{ ok: true; mailbox_url: string }>('/api/mailboxes/url', row)
)
export const getRuntimeTaskMailboxUrl = (taskId: string) => (
  api<{ ok: true; mailbox_url: string }>('/api/runtime/tasks/mailbox-url', { task_id: taskId })
)
export const submitManualVerification = (data: ManualVerificationSubmission) => (
  api<ManualVerificationAccepted>('/api/runtime/tasks/manual-verification', data)
)
export const reloginMailboxRows = (rows: Array<{ row_id: string; line_no: number }>) => (
  api<{ ok: true; run_mode: 'relogin'; started: number; mailboxes?: MailboxPayload; state?: any }>(
    '/api/mailboxes/relogin',
    { rows },
  )
)
export const importWebsiteMailboxes = () => (
  api<{
    ok: true
    batch_id: string
    submitted: number
    created: number
    updated: number
    duplicates: number
    rejected: number
    skipped: number
    local_duplicates: number
    manager_url: string
  }>('/api/mailboxes/website-import', {})
)
export const testMailboxUrl = (value: string) => (
  api<MailboxUrlTestResult>('/api/mailbox-url-test', { value })
)
export const testEmailNotification = (data: Record<string, any>) => api('/api/notifications/email/test', data)
export const querySmsBalances = (data: Record<string, any>) => (
  api<{ ok: true; queried_at: number; sms_key_statuses: SmsKeyStatus[] }>('/api/sms/balances', data)
)

export const getPixelTargets = () => api<Record<string, any>>('/api/pixel/targets')
export const getPixelAccounts = (
  targetId: string,
  page: number,
  pageSize: number,
  search = '',
  status = '',
) => {
  const params = new URLSearchParams({
    page: String(page),
    page_size: String(pageSize),
    pageSize: String(pageSize),
  })
  if (search) params.set('search', search)
  if (status) params.set('status', status)
  return api<PixelAccountPage>(`/api/pixel/targets/${encodeURIComponent(targetId)}/accounts?${params}`)
}
export const testPixelAccounts = (targetId: string, accountIds: number[]) => (
  api<PixelBulkOperationResponse>(`/api/pixel/targets/${encodeURIComponent(targetId)}/accounts/bulk-test`, {
    account_ids: accountIds,
    accountIds,
  })
)
export const sharePixelAccounts = (targetId: string, accountIds: number[]) => (
  api<PixelBulkOperationResponse>(`/api/pixel/targets/${encodeURIComponent(targetId)}/accounts/bulk-update`, {
    account_ids: accountIds,
    accountIds,
    share_mode: 'public',
    shareMode: 'public',
    makePublic: true,
  })
)
export const reloginPixelTarget = (targetId: string) => (
  api(`/api/pixel/targets/${encodeURIComponent(targetId)}/relogin`, {})
)
export const shareAllPixelAccounts = (targetIds: string[]) => api<Record<string, any>>('/api/pixel/share-all', {
  target_ids: targetIds,
  targetIds,
})
export const getPixelUploadRecords = () => (
  api<{ records?: PixelUploadRecord[]; items?: PixelUploadRecord[] }>('/api/pixel/upload-records')
)
export const getPixelOverview = () => api<PixelOverview>('/api/pixel/overview')
export const getPixelUploadBatches = (page = 1, pageSize = 20) => {
  const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) })
  return api<PixelBatchPage>(`/api/pixel/upload-batches?${params}`)
}
export const getPixelBatchRecords = (
  batchId: string,
  page = 1,
  pageSize = 50,
  status = '',
) => {
  const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) })
  if (status) params.set('status', status)
  return api<PixelBatchRecordPage>(
    `/api/pixel/upload-batches/${encodeURIComponent(batchId)}/records?${params}`,
  )
}
export const retryPixelUpload = (recordId: string, targetId?: string) => (
  api(`/api/pixel/upload-records/${encodeURIComponent(recordId)}/retry`, targetId
    ? { target_id: targetId, targetId, target_ids: [targetId], targetIds: [targetId] }
    : {})
)
export const retryPixelBatchTarget = (batchId: string, targetId: string) => (
  api<{ queued_records: number; queued_deliveries: number; skipped_records: number }>(
    `/api/pixel/upload-batches/${encodeURIComponent(batchId)}/retry`,
    { target_id: targetId },
  )
)
export const getNvOverview = () => api<NvOverview>('/api/nv/overview')
export const getNvUploadBatches = (page = 1, pageSize = 20) => {
  const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) })
  return api<NvUploadBatchPage>(`/api/nv/upload-batches?${params}`)
}
export const getNvUploadRecords = (page = 1, pageSize = 50) => {
  const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) })
  return api<NvUploadRecordPage>(`/api/nv/upload-records?${params}`)
}
export const retryNvUpload = (recordId: string) => (
  api(`/api/nv/upload-records/${encodeURIComponent(recordId)}/retry`, {})
)
export const getBatchUploadManifests = (limit = 100) => (
  api<{ records: BatchUploadManifest[]; total: number }>(`/api/upload-manifests?limit=${limit}`)
)
export const retryBatchUploadManifest = (batchId: string, platform: 'pixel' | 'nv') => (
  api<{ manifest: BatchUploadManifest }>(
    `/api/upload-manifests/${encodeURIComponent(batchId)}/retry`,
    { platform },
  )
)
