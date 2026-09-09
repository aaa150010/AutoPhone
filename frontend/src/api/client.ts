import type {
  ApiErrorPayload,
  AppState,
  MailboxBatchOperation,
  MailboxOperationKind,
  MailboxPayload,
  MailboxUrlTestResult,
  ManualVerificationAccepted,
  ManualVerificationSubmission,
  FreeLogEntry,
  TaskFailure,
  SmsKeyStatus,
  OpenAIConnectivityDiagnostic,
  MailboxParserSample,
  MailboxParserSampleHealth,
  MailboxParserSampleReparse,
  RuntimeTask,
} from '../types/api'
import type {
  FreeConfig,
  FreeState,
  FreeTaskRow,
  FreeProxyPool,
  RemailProject,
  RemailWallet,
  FreeConfigSavePayload,
  FreeCamoufoxDebugCloseResult,
  DiagnosticIncident,
  FreeMailboxRow,
  RemailOrder,
  FreeLiveCheckState,
  FreePlanCheckState,
  FreeProxyPreflightResult,
} from '../types/free'
export type {
  FreeConfig,
  FreeState,
  FreeCamoufoxDebugSession,
  FreeCamoufoxDebugState,
  FreeProxyRow,
  FreeProxyPool,
  FreeProxySummary,
  FreeConfigSavePayload,
  FreeCamoufoxDebugCloseResult,
  DiagnosticIncident,
  DiagnosticEvent,
  FreeMailboxRow,
  RemailOrder,
  RemailProject,
  RemailWallet,
  RemailProjectProduct,
  FreeLiveCheckState,
  FreePlanCheckState,
  FreeProxyPreflightRow,
  FreeProxyPreflightResult,
  FreeTaskRow,
} from '../types/free'

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

export async function api<T = unknown>(path: string, body?: unknown): Promise<T> {
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

// ---------------------------------------------------------------------------
// Runtime tasks & config (SMS / OAuth chain)
// ---------------------------------------------------------------------------

export const getState = () => api<{ state: AppState }>('/api/state')
export const getLocalConfig = () => api<{ config: Record<string, unknown> }>('/api/local-config')
export const getSecret = (id: string) => api<{ value: unknown }>('/api/local-config/secret', { id })
export const saveConfig = (data: Record<string, unknown>) => api<{ state?: AppState; settings?: Record<string, unknown> }>('/api/config', data)
export const updateOpenAIConnectivityGuard = (enabled: boolean) => api<{
  ok: true
  enabled: boolean
  settings?: Record<string, unknown>
  state?: AppState
}>('/api/openai-connectivity-guard', { enabled })
export const runOpenAIConnectivityDiagnostics = () => api<{
  ok: true
  diagnostic: OpenAIConnectivityDiagnostic
}>('/api/openai-connectivity-diagnostics', {})
export const preflightRun = (data: Record<string, unknown>) => api<{ state?: AppState; sms_key_statuses?: SmsKeyStatus[] }>('/api/preflight', data)
export const startExistingRun = (data: Record<string, unknown>) => api<{ state?: AppState }>('/api/start-existing', data)
export const stopRun = () => api<{ state?: AppState }>('/api/stop', {})
export const getMailboxes = () => api<MailboxPayload>('/api/mailboxes')
// ---------------------------------------------------------------------------
// Free registration chain (protocol / Camoufox)
// ---------------------------------------------------------------------------

export const getFreeConfig = () => api<{ ok: true; config: FreeConfig; state: FreeState }>('/api/free/config')
export const saveFreeConfig = (config: FreeConfigSavePayload) => api<{ ok: true; config: FreeConfig; state: FreeState; proxies?: FreeProxyPool }>('/api/free/config', config)
export const getFreeState = () => api<{ ok: true; state: FreeState; config: FreeConfig }>('/api/free/state')
export const closeFreeCamoufoxDebug = (sessionId = '') => api<FreeCamoufoxDebugCloseResult>('/api/free/camoufox/debug/close', { session_id: sessionId })
export const preflightFree = (config?: Partial<FreeConfig> & { proxy_content?: string }) => api<{
  ok: true
  result: FreeProxyPreflightResult
  state: FreeState
  config: FreeConfig
  incident_id?: string
  failure?: TaskFailure | null
}>('/api/free/preflight', config || {})
export const startFree = (config?: Partial<FreeConfig> & { proxy_content?: string; row_ids?: string[] }) => api<{ ok: true; batch_id: string; async_start?: boolean; batch?: { batch_id: string; members?: string[] }; state: FreeState }>('/api/free/start', config || {})
export const rerunFreeTask = (taskId: string) => api<{ ok: true; batch_id: string; task?: FreeTaskRow; batch?: { batch_id: string; members?: string[] }; state: FreeState }>('/api/free/rerun', { task_id: taskId })
export const stopFree = () => api<{ ok: true; state: FreeState }>('/api/free/stop', {})
export const getFreeLogs = (taskId = '') => api<{ ok: true; task_id?: string; logs: FreeLogEntry[] }>(`/api/free/logs${taskId ? `?task_id=${encodeURIComponent(taskId)}` : ''}`)
// ---------------------------------------------------------------------------
// Diagnostics / log center
// ---------------------------------------------------------------------------

export const searchDiagnostics = (query: Record<string, unknown>) => api<{ ok: true; results: DiagnosticIncident[] }>('/api/diagnostics/search', query)
export const getDiagnosticIncident = (incidentId: string) => api<{ ok: true; incident: DiagnosticIncident }>(`/api/diagnostics/incidents/${encodeURIComponent(incidentId)}`)
export const exportDiagnostics = (incidentIds: string[], format: 'json' | 'markdown' = 'markdown') => api<{ ok: true; format: string; content: string; redaction_applied: boolean }>('/api/diagnostics/export', { incident_ids: incidentIds, format })
export const deleteDiagnostics = (incidentIds: string[]) => api<{ ok: true; deleted: number }>('/api/diagnostics/delete', { incident_ids: incidentIds })
export const clearDiagnostics = () => api<{ ok: true; deleted: number }>('/api/diagnostics/clear-all', {})
export const getDiagnosticsHealth = () => api<{ ok: true; health: Record<string, unknown> }>('/api/diagnostics/health')
// ---------------------------------------------------------------------------
// Free mailbox pool
// ---------------------------------------------------------------------------

export const getFreeMailboxes = () => api<{ ok: true; pool: 'free'; rows: FreeMailboxRow[]; state?: FreeState }>('/api/free/mailboxes')
// ---------------------------------------------------------------------------
// Remail purchase & orders
// ---------------------------------------------------------------------------

export const getRemailProjects = () => api<{ ok: true; projects: RemailProject[] | { items?: RemailProject[] } }>('/api/remail/projects')
export const getRemailWallet = () => api<{ ok: true; wallet: RemailWallet }>('/api/remail/wallet')
export const getRemailOrders = (query: { page?: number; page_size?: number; imported?: boolean | 'all'; search?: string; include_failed?: boolean } = {}) => api<{ ok: true; orders: RemailOrder[]; remote_count?: number; total: number; page: number; page_size: number; has_more: boolean }>(`/api/remail/orders?${new URLSearchParams(Object.entries(query).filter(([, value]) => value !== undefined && value !== '').map(([key, value]) => [key, String(value)]))}`)
export const purchaseRemail = (data: { project_id: number; email_suffix: string; quantity: number; supply?: string }) => api<{ ok: true; result: Record<string, unknown>; imported?: Array<{ order_no: string; row_id: string }>; skipped?: Array<{ order_no: string; reason: string }>; state?: FreeState }>('/api/remail/purchase', data)
export const importRemailOrders = (order_nos: string[]) => api<{ ok: true; imported: Array<{ order_no: string; row_id: string }>; skipped: Array<{ order_no: string; reason: string }> }>('/api/remail/orders/import', { order_nos })
export const hideRemailOrders = (order_nos: string[]) => api<{ ok: true; hidden: number }>('/api/remail/orders/hide', { order_nos })
export const getRemailConfig = () => api<{ ok: true; config: FreeConfig['remail']; state: FreeState }>('/api/remail/config')
export const saveRemailConfig = (config: Partial<NonNullable<FreeConfig['remail']>>) => api<{ ok: true; config: FreeConfig['remail']; state: FreeState }>('/api/remail/config', config)
export const importFreeMailboxes = (poolContent: string, joinCurrentBatch = false) => api<{ ok: true; imported: number; skipped: number; queued?: number; active_batch_joined?: number; next_batch?: number; reason?: string; skipped_items?: Array<{ row_id: string; reason: string }>; state?: FreeState; rows: FreeMailboxRow[] }>(
  '/api/free/mailboxes/import',
  { pool_content: poolContent, join_current_batch: joinCurrentBatch },
)
export const deleteFreeMailboxes = (rowIds: string[]) => api<{ ok: true; deleted: number; rows: FreeMailboxRow[] }>(
  '/api/free/mailboxes/delete',
  { row_ids: rowIds },
)
export const deleteFreeTasks = (taskIds: string[]) => api<{ ok: true; deleted: number; state: FreeState }>(
  '/api/free/tasks/delete',
  { task_ids: taskIds },
)
export const setFreeMailboxStatus = (status: 'available' | 'unavailable' | 'draft', rowIds: string[]) => api<{ ok: true; updated: number; rows: FreeMailboxRow[] }>(
  `/api/free/mailboxes/${status === 'available' ? 'restore' : status}`,
  { row_ids: rowIds },
)
export const getFreeMailboxUrl = (rowId: string) => api<{ ok: true; mailbox_url: string }>('/api/free/mailboxes/url', { row_id: rowId })
export const getFreeMailboxLatestCode = (rowId: string) => api<{ ok: true; kind: 'email'; code: string; message: string; fetched_at?: number }>('/api/free/mailboxes/latest-code', { row_id: rowId })
export const getFreeTaskLatestCode = (taskId: string) => api<{ ok: true; kind: 'email'; code: string; message: string; fetched_at?: number }>('/api/free/tasks/latest-code', { task_id: taskId })
export const freeBatchRetry = (taskIds: string[]) => api<{ ok: true; accepted: Array<{ task_id: string; retry_task: FreeTaskRow }>; accepted_count: number; skipped: Array<{ task_id: string; reason: string }>; skipped_count: number; rejected: Array<{ task_id: string; reason: string }>; rejected_count: number; state?: FreeState }>('/api/free/retry/batch', { task_ids: taskIds })
// ---------------------------------------------------------------------------
// Free live/plan checks
// ---------------------------------------------------------------------------

export const startFreeLiveCheck = (mode: 'fast' | 'deep', rowIds: string[]) => api<{
  ok: true
  accepted_count: number
  skipped_count: number
  skipped: Array<{ row_id: string; reason: string }>
  state: FreeLiveCheckState
  rows: FreeMailboxRow[]
}>('/api/free/live-check', { mode, row_ids: rowIds })
export const getFreeLiveCheckState = () => api<{ ok: true; state: FreeLiveCheckState; rows: FreeMailboxRow[] }>('/api/free/live-check/state')
export const startFreePlanCheck = (rowIds: string[]) => api<{
  ok: true
  accepted_count: number
  skipped_count: number
  skipped: Array<{ row_id: string; reason: string }>
  state: FreePlanCheckState
  rows: FreeMailboxRow[]
}>('/api/free/plan-check', { row_ids: rowIds })
export const exportFreeResults = (rowIds: string[] = []) => api<{ ok: true; count: number; filename: string; content: string }>('/api/free/mailboxes/export', { row_ids: rowIds })
export const formatFreeMailboxes = (mode: 'mailbox' | 'full', rowIds: string[]) => api<{
  ok: true
  mode: 'mailbox' | 'full'
  content: string
  prepared: number
  skipped: number
  skipped_items: Array<{ row_id: string; email?: string; reason: string }>
}>('/api/free/mailboxes/format', { mode, row_ids: rowIds })
export const transferFreeMailboxes = (rowIds: string[]) => api<{
  ok: true
  imported: number
  skipped: number
  prepared: number
  skipped_items: Array<{ row_id: string; email?: string; reason: string }>
  ordinary_mailboxes_refresh_required?: boolean
}>('/api/free/mailboxes/transfer', { row_ids: rowIds })
// ---------------------------------------------------------------------------
// Free proxy pool & secrets
// ---------------------------------------------------------------------------

export const preflightFreeProxies = (proxyContent: string, proxyProbeUrl?: string, options: { driver?: string; scheme?: string; proxy_tls_verify?: boolean; proxy_tls_compat_fallback?: boolean; proxy_socks5_dns_mode?: string; layered_probe?: boolean } = {}) => api<{
  ok: true
  result: FreeProxyPreflightResult
  incident_id?: string
  failure?: TaskFailure | null
}>('/api/free/proxies/preflight', { proxy_content: proxyContent, proxy_probe_url: proxyProbeUrl, ...options })
export const getFreeProxies = () => api<{ ok: true; proxies: FreeProxyPool }>('/api/free/proxies')
export const getFreeSecret = (kind: 'token' | 'password' | 'totp' | 'proxy' | 'credential' | 'email', ids: { task_ids?: string[]; row_ids?: string[] }) => api<{ ok: true; kind: string; value: string }>(
  '/api/free/secrets',
  { kind, ...ids },
)
export const getFreeTotp = (ids: { task_id?: string; row_id?: string; task_ids?: string[]; row_ids?: string[] }) => api<{
  ok: true
  kind: 'totp'
  code: string
  remaining: number
}>('/api/free/totp', ids)

export const retryFreeTwofa = (id: string) => api<{ ok: true; task: FreeTaskRow | RuntimeTask; state?: AppState }>(
  '/api/free/2fa/retry',
  { task_id: id, row_id: id },
)
export const retryFreePassword = (id: string) => api<{ ok: true; task: FreeTaskRow | RuntimeTask; state?: FreeState }>(
  '/api/free/password/retry',
  { task_id: id, row_id: id },
)
// ---------------------------------------------------------------------------
// Normal mailbox operations
// ---------------------------------------------------------------------------

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
  api<{ count: number; skipped?: number; filename: string; export: Record<string, unknown> }>(
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
export const getMailboxLatestCode = (row: { row_id: string; line_no: number }) => (
  api<{ ok: true; kind: 'email'; code: string; message: string; fetched_at?: number }>('/api/mailboxes/latest-code', row)
)
export const getRuntimeTaskMailboxUrl = (taskId: string) => (
  api<{ ok: true; mailbox_url: string }>('/api/runtime/tasks/mailbox-url', { task_id: taskId })
)
export const getRuntimeTaskLatestCode = (taskId: string) => (
  api<{ ok: true; kind: 'email'; code: string; message: string; fetched_at?: number }>('/api/runtime/tasks/latest-code', { task_id: taskId })
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
  api<{ ok: true; run_mode: 'relogin'; started: number; mailboxes?: MailboxPayload; state?: AppState }>(
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
export const getMailboxParserSamples = (query: Record<string, unknown> = {}) => {
  const params = new URLSearchParams()
  Object.entries(query).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') params.set(key, String(value))
  })
  const suffix = params.toString() ? `?${params.toString()}` : ''
  return api<{ ok: true; samples: MailboxParserSample[]; total: number; offset: number; limit: number; health: Record<string, MailboxParserSampleHealth> }>(`/api/mailbox-parser-samples${suffix}`)
}
export const getMailboxParserSample = (sampleId: string, scope = '') => api<{ ok: true; sample: MailboxParserSample }>(`/api/mailbox-parser-samples/${encodeURIComponent(sampleId)}${scope ? `?scope=${encodeURIComponent(scope)}` : ''}`)
export const revealMailboxParserSample = (sampleId: string, scope = '') => api<{ ok: true; sample: MailboxParserSample; raw_access: true }>(`/api/mailbox-parser-samples/${encodeURIComponent(sampleId)}/reveal${scope ? `?scope=${encodeURIComponent(scope)}` : ''}`, { confirm_raw: true })
export const reparseMailboxParserSample = (sampleId: string, scope = '') => api<{ ok: true; sample_id: string; parser_version: string; reparse: MailboxParserSampleReparse }>(`/api/mailbox-parser-samples/${encodeURIComponent(sampleId)}/reparse${scope ? `?scope=${encodeURIComponent(scope)}` : ''}`, {})
export const updateMailboxParserSampleStatus = (sampleIds: string[], status: string, scope = '') => api<{ ok: true; updated: number }>('/api/mailbox-parser-samples/status', { sample_ids: sampleIds, status, scope })
export const deleteMailboxParserSamples = (sampleIds: string[], scope = '') => api<{ ok: true; deleted: number }>('/api/mailbox-parser-samples/delete', { sample_ids: sampleIds, scope })
export const cleanupMailboxParserSamples = () => api<{ ok: true; deleted: number; health: Record<string, MailboxParserSampleHealth> }>('/api/mailbox-parser-samples/cleanup', {})
export const exportMailboxParserSample = (sampleId: string, format: 'sanitized' | 'fixture' = 'sanitized', scope = '') => api<{ ok: true; format: string; content: string; redaction_applied: boolean }>(
  '/api/mailbox-parser-samples/export', { sample_id: sampleId, format, scope, ...(format === 'fixture' ? { confirm_raw: true } : {}) },
)
export const testEmailNotification = (data: Record<string, unknown>) => api<{ state?: AppState }>('/api/notifications/email/test', data)
export const querySmsBalances = (data: Record<string, unknown>) => (
  api<{ ok: true; queried_at: number; sms_key_statuses: SmsKeyStatus[] }>('/api/sms/balances', data)
)
