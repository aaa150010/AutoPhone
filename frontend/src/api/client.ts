import type {
  ApiErrorPayload,
  AppState,
  MailboxBatchOperation,
  MailboxOperationKind,
  MailboxPayload,
  MailboxUrlTestResult,
  ManualVerificationAccepted,
  ManualVerificationSubmission,
  SmsKeyStatus,
  OpenAIConnectivityDiagnostic,
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
export const runOpenAIConnectivityDiagnostics = () => api<{
  ok: true
  diagnostic: OpenAIConnectivityDiagnostic
}>('/api/openai-connectivity-diagnostics', {})
export const preflightRun = (data: Record<string, any>) => api('/api/preflight', data)
export const startExistingRun = (data: Record<string, any>) => api('/api/start-existing', data)
export const stopRun = () => api('/api/stop', {})
export const getMailboxes = () => api<MailboxPayload>('/api/mailboxes')
export interface FreeMailboxRow {
  row_id: string
  line_no: number
  email: string
  status: string
  stage?: string
  proxy_masked?: string
  proxy_fingerprint?: string
  exit_ip?: string
  plan_type?: string
  plus_trial_eligible?: boolean
  twofa_status?: string
  twofa_error?: string
  has_access_token?: boolean
  has_password?: boolean
  has_totp?: boolean
  has_credential?: boolean
  credential_line?: string
  task_id?: string
  error?: string
}
export const getFreeMailboxes = () => api<{ ok: true; pool: 'free'; rows: FreeMailboxRow[] }>('/api/free/mailboxes')
export const importFreeMailboxes = (poolContent: string) => api<{ ok: true; imported: number; skipped: number; rows: FreeMailboxRow[] }>(
  '/api/free/mailboxes/import',
  { pool_content: poolContent },
)
export const deleteFreeMailboxes = (rowIds: string[]) => api<{ ok: true; deleted: number; rows: FreeMailboxRow[] }>(
  '/api/free/mailboxes/delete',
  { row_ids: rowIds },
)
export const importFreeProxies = (proxyContent: string) => api<{ ok: true; imported: number }>(
  '/api/free/proxies/import',
  { proxy_content: proxyContent },
)
export const getFreeSecret = (kind: 'token' | 'password' | 'totp' | 'proxy' | 'credential', ids: { task_ids?: string[]; row_ids?: string[] }) => api<{ ok: true; kind: string; value: string }>(
  '/api/free/secrets',
  { kind, ...ids },
)
export const retryFreeTwofa = (id: string) => api<{ ok: true; task: any; state?: AppState }>(
  '/api/free/2fa/retry',
  { task_id: id, row_id: id },
)
export const importMailboxes = (poolContent: string) => api<{
  ok: true
  imported: number
  skipped: number
  mailboxes?: MailboxPayload
  state?: AppState
  mailboxes_refresh_required?: boolean
  state_refresh_required?: boolean
  joined_current_batch?: number
  queued_current_batch?: number
  next_batch?: number
  append_node_code?: string
  append_node_label?: string
  append_reason?: string
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
    deactivated_deleted?: number
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
export const getRuntimeTaskMailboxPassword = (taskId: string) => (
  api<{ ok: true; password: string }>('/api/runtime/tasks/mailbox-password', { task_id: taskId })
)
export const getRuntimeTaskMailboxTotp = (taskId: string) => (
  api<{ ok: true; kind: 'totp'; code: string; remaining: number }>('/api/runtime/tasks/mailbox-totp', { task_id: taskId })
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
