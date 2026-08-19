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
export interface FreeConfig {
  version?: number
  driver: 'protocol' | 'roxybrowser'
  target_count: number
  concurrency: number
  email_code_timeout: number
  auto_set_2fa: boolean
  proxy_probe_url: string
  proxy_default_scheme?: 'http' | 'https' | 'socks4' | 'socks5' | 'socks5h' | string
  proxy_failure_threshold?: number
  proxy_quarantine_seconds?: number
  proxy_retry_count?: number
  roxy_circuit_failure_threshold?: number
  roxy_circuit_recovery_seconds?: number
  proxy_selection?: {
    protocol?: { country?: string; group?: string }
    roxybrowser?: { country?: string; group?: string }
  }
  protocol: { node_runner: string; sentinel_timeout: number }
  roxybrowser: {
    api_base: string
    api_key?: string
    workspace_id: string
    project_id: string
    workspace_list_path: string
    create_path: string
    open_path: string
    close_path: string
    delete_path: string
    headless: boolean
    keep_browser_open: boolean
    one_profile_per_account: boolean
    delete_profile_after_run: boolean
    random_os: boolean
    os_choices: string[]
    random_profile_name: boolean
    profile_name_prefix: string
    proxy_check_channel: string
    selenium_timeout: number
    api_retries: number
    api_retry_delay: number
    humanize_delay: boolean
    humanize_factor: number
    humanize_browser_actions: boolean
    existing_account_login: boolean
    post_registration_dwell_min: number
    post_registration_dwell_max: number
  }
}
export interface FreeState {
  running: boolean
  batch_id?: string
  driver?: 'protocol' | 'roxybrowser' | string
  tasks?: any[]
  pool?: { total?: number; available?: number; proxies?: number }
  scheduler?: { concurrency?: number; active_slots?: number; queued_slots?: number; roxy_circuit_open?: boolean; roxy_failures?: number; roxy_circuit_opened_at?: number | null }
  summary?: { total?: number; active?: number; success?: number; failed?: number; stopped?: number }
}
export interface FreeProxyRow {
  proxy_id: string
  index?: number
  masked: string
  fingerprint: string
  scheme: string
  country: string
  group: string
  enabled: boolean
  status: string
  lease_until?: number | null
  last_checked_at?: number | null
  last_exit_ip?: string
  latency_ms?: number | null
  consecutive_failures?: number
}
export interface FreeProxySummary {
  country: string
  group?: string
  total: number
  enabled: number
  available: number
  leased?: number
  quarantined: number
  schemes?: string[]
}
export const getFreeConfig = () => api<{ ok: true; config: FreeConfig; state: FreeState }>('/api/free/config')
export type FreeConfigSavePayload = Partial<FreeConfig> & {
  proxy_content?: string
  proxy_country?: string
  proxy_group?: string
  proxy_scheme?: string
}
export const saveFreeConfig = (config: FreeConfigSavePayload) => api<{ ok: true; config: FreeConfig; state: FreeState; proxies?: any }>('/api/free/config', config)
export const getFreeState = () => api<{ ok: true; state: FreeState; config: FreeConfig }>('/api/free/state')
export const preflightFree = (config?: Partial<FreeConfig> & { proxy_content?: string }) => api<{ ok: true; result: any; state: FreeState; config: FreeConfig }>('/api/free/preflight', config || {})
export const startFree = (config?: Partial<FreeConfig> & { proxy_content?: string; row_ids?: string[] }) => api<{ ok: true; batch_id: string; batch?: any; state: FreeState }>('/api/free/start', config || {})
export const rerunFreeTask = (taskId: string) => api<{ ok: true; batch_id: string; batch?: any; state: FreeState }>('/api/free/rerun', { task_id: taskId })
export const stopFree = () => api<{ ok: true; state: FreeState }>('/api/free/stop', {})
export const getFreeLogs = (taskId = '') => api<{ ok: true; task_id?: string; logs: Array<{ time?: string; level?: string; message?: string; task_id?: string; stage?: string; stage_label?: string }> }>(`/api/free/logs${taskId ? `?task_id=${encodeURIComponent(taskId)}` : ''}`)
export const getFreeRoxyWorkspaces = () => api<{ ok: true; items: Array<{ workspace_id: string; workspace_name: string; project_id: string; project_name: string; label: string }> }>('/api/free/roxy/workspaces')
export interface FreeMailboxRow {
  row_id: string
  line_no: number
  email: string
  status: string
  stage?: string
  driver?: 'protocol' | 'roxybrowser' | string
  proxy_masked?: string
  proxy_fingerprint?: string
  proxy_scheme?: string
  proxy_country?: string
  proxy_group?: string
  exit_ip?: string
  expected_exit_ip?: string
  registration_ip?: string
  plan_type?: string
  subscription_plan?: string
  plan_check_status?: string
  plus_trial_eligible?: boolean
  live_check_status?: 'queued' | 'running' | 'live' | 'deactivated' | 'token_expired' | 'failed' | string
  live_check_mode?: 'fast' | 'deep' | string
  live_check_task_id?: string
  live_checked_at?: number | string
  live_check_ip?: string
  live_check_token_refreshed?: boolean
  live_check_http_status?: number | null
  live_check_failure?: {
    node_code?: string
    node_label?: string
    error_code?: string
    public_message?: string
    retryable?: boolean
    http_status?: number | string | null
  } | null
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
export const deleteFreeTasks = (taskIds: string[]) => api<{ ok: true; deleted: number; state: FreeState }>(
  '/api/free/tasks/delete',
  { task_ids: taskIds },
)
export const setFreeMailboxStatus = (status: 'available' | 'unavailable' | 'draft', rowIds: string[]) => api<{ ok: true; updated: number; rows: FreeMailboxRow[] }>(
  `/api/free/mailboxes/${status === 'available' ? 'restore' : status}`,
  { row_ids: rowIds },
)
export const getFreeMailboxUrl = (rowId: string) => api<{ ok: true; mailbox_url: string }>('/api/free/mailboxes/url', { row_id: rowId })
export interface FreeLiveCheckState {
  running: boolean
  workers: number
  queue_limit: number
  active: number
  jobs: Array<{
    task_id: string
    row_id: string
    email: string
    mode: 'fast' | 'deep' | string
    status: string
    stage?: string
    stage_label?: string
    live_check_ip?: string
    checked_at?: number
    failure?: FreeMailboxRow['live_check_failure']
  }>
}
export const startFreeLiveCheck = (mode: 'fast' | 'deep', rowIds: string[]) => api<{
  ok: true
  accepted_count: number
  skipped_count: number
  skipped: Array<{ row_id: string; reason: string }>
  state: FreeLiveCheckState
  rows: FreeMailboxRow[]
}>('/api/free/live-check', { mode, row_ids: rowIds })
export const getFreeLiveCheckState = () => api<{ ok: true; state: FreeLiveCheckState; rows: FreeMailboxRow[] }>('/api/free/live-check/state')
export const exportFreeResults = (rowIds: string[] = []) => api<{ ok: true; count: number; filename: string; content: string }>('/api/free/mailboxes/export', { row_ids: rowIds })
export const importFreeProxies = (proxyContent: string, country?: string, group?: string, scheme?: string) => api<{ ok: true; imported: number; proxies?: any }>(
  '/api/free/proxies/import',
  { proxy_content: proxyContent, country, group, scheme },
)
export const preflightFreeProxies = (proxyContent: string, proxyProbeUrl?: string, options: { driver?: string; country?: string; group?: string; scheme?: string } = {}) => api<{
  ok: true
  result: { proxies: number; exit_ips: number; rows: Array<{ index: number; masked: string; fingerprint: string; exit_ip: string; scheme?: string; country?: string; group?: string }> }
}>('/api/free/proxies/preflight', { proxy_content: proxyContent, proxy_probe_url: proxyProbeUrl, ...options })
export const getFreeProxies = () => api<{ ok: true; proxies: { count: number; rows: FreeProxyRow[]; groups: FreeProxySummary[]; countries: FreeProxySummary[] } }>('/api/free/proxies')
export const updateFreeProxyGroup = (payload: { country: string; group: string; new_country?: string; new_group?: string; enabled?: boolean }) => api<{ ok: true; result: any; proxies: any }>('/api/free/proxies/group', payload)
export const deleteFreeProxyGroup = (country: string, group: string) => api<{ ok: true; deleted: number; proxies: any }>('/api/free/proxies/group/delete', { country, group })
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
