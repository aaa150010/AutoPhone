import type {
  ApiErrorPayload,
  AppState,
  MailboxPayload,
  MailboxUrlTestResult,
  PixelAccountPage,
  PixelBulkOperationResponse,
  PixelUploadRecord,
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
export const preflightRun = (data: Record<string, any>) => api('/api/preflight', data)
export const startExistingRun = (data: Record<string, any>) => api('/api/start-existing', data)
export const stopRun = () => api('/api/stop', {})
export const getMailboxes = () => api<MailboxPayload>('/api/mailboxes')
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
export const retryMailboxPixel = (rows: Array<{ row_id: string; line_no: number }>) => (
  api('/api/mailboxes/pixel-retry', { rows })
)
export const exportMailboxSub2 = (rows: Array<{ row_id: string; line_no: number }>) => (
  api<{ count: number; skipped?: number; filename: string; export: Record<string, any> }>(
    '/api/mailboxes/sub2-export',
    { rows },
  )
)
export const getMailboxTotp = (row: { row_id: string; line_no: number }) => (
  api<{ ok: true; kind: 'totp'; code: string; remaining: number }>('/api/mailboxes/totp', row)
)
export const getMailboxUrl = (row: { row_id: string; line_no: number }) => (
  api<{ ok: true; mailbox_url: string }>('/api/mailboxes/url', row)
)
export const reloginMailboxRows = (rows: Array<{ row_id: string; line_no: number }>) => (
  api<{ ok: true; run_mode: 'relogin'; started: number; mailboxes?: MailboxPayload; state?: any }>(
    '/api/mailboxes/relogin',
    { rows },
  )
)
export const testMailboxUrl = (value: string) => (
  api<MailboxUrlTestResult>('/api/mailbox-url-test', { value })
)
export const testEmailNotification = (data: Record<string, any>) => api('/api/notifications/email/test', data)

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
export const retryPixelUpload = (recordId: string, targetId?: string) => (
  api(`/api/pixel/upload-records/${encodeURIComponent(recordId)}/retry`, targetId
    ? { target_id: targetId, targetId, target_ids: [targetId], targetIds: [targetId] }
    : {})
)
