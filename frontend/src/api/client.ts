import type {
  ApiErrorPayload,
  AppState,
  MailboxBatchOperation,
  MailboxOperationKind,
  MailboxPayload,
  MailboxUrlTestResult,
  ManualVerificationAccepted,
  ManualVerificationRequest,
  ManualVerificationSubmission,
  FreeLogEntry,
  TaskFailure,
  SmsKeyStatus,
  OpenAIConnectivityDiagnostic,
  MailboxParserSample,
  MailboxParserSampleHealth,
  MailboxParserSampleReparse,
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
  driver: 'protocol' | 'camoufox'
  flow_profile?: 'reference_20260823' | 'legacy' | string
  proxy_allocation_mode?: 'healthy_random' | string
  target_count: number
  concurrency: number
  email_code_timeout: number
  mailbox_network_mode: 'local_proxy' | 'direct'
  mailbox_proxy_url: string
  mailbox_request_retries: number
  mailbox_retry_backoff_seconds: number
  /** Registration password; the Free config endpoint masks this as `********`. */
  account_password: string
  auto_set_password: boolean
  auto_set_2fa: boolean
  twofa_auto_retry_attempts?: number
  proxy_probe_url: string
  proxy_default_scheme?: 'http' | 'https' | 'socks4' | 'socks5' | 'socks5h' | string
  proxy_socks5_dns_mode?: 'auto' | 'declared' | 'local' | 'remote' | string
  proxy_tls_verify?: boolean
  proxy_tls_compat_fallback?: boolean
  proxy_failure_threshold?: number
  proxy_quarantine_seconds?: number
  proxy_health_probe_ttl_seconds?: number
  proxy_retry_count?: number
  /** @deprecated retained only for loading pre-v6 config responses. */
  proxy_selection?: {
    protocol?: { country?: string; group?: string }
    camoufox?: { country?: string; group?: string }
  }
  protocol: {
    node_runner: string
    sentinel_version?: string
    sentinel_timeout: number
    network_timeout?: number
    network_preflight_retries?: number
    security_challenge_wait_seconds?: number
    anonymous_warmup?: boolean
    authenticated_warmup?: boolean
  }
  camoufox: {
    debug_mode?: boolean
    headless: boolean
    pool_size: number
    max_contexts_per_browser: number
    context_start_interval_ms: number
    startup_concurrency: number
    block_images: boolean
    registration_timeout_seconds: number
    context_close_timeout_seconds: number
    browser_recycle_timeout_seconds: number
    browser_recycle_drain_timeout_seconds: number
    max_registrations_per_browser: number
    browser_launch_attempts: number
    existing_account_login: boolean
  }
  remail?: {
    enabled: boolean
    base_url: string
    api_key: string
    project_id: string
    supply_policy: 'private_first' | 'public_only' | string
    request_timeout_seconds: number
    catalog_cache_seconds: number
    order_sync_enabled: boolean
    order_sync_interval_minutes: number
    auto_import_new_purchase_orders: boolean
  }
}
export interface FreeState {
  runtime_version?: string
  otp_parser_revision?: string
  running: boolean
  batch_id?: string
  driver?: 'protocol' | 'camoufox' | string
  tasks?: any[]
  pool?: { total?: number; available?: number; proxies?: number }
  scheduler?: { concurrency?: number; active_slots?: number; queued_slots?: number }
  camoufox_debug?: FreeCamoufoxDebugState
  summary?: { total?: number; active?: number; success?: number; failed?: number; stopped?: number }
}
export interface FreeCamoufoxDebugSession {
  session_id: string
  task_id?: string
  node_code?: string
  node_label?: string
  error_code?: string
  page_type?: string
  safe_page?: string
  proxy_fingerprint?: string
  artifact_id?: string
  incident_id?: string
  created_at?: number | string
}
export interface FreeCamoufoxDebugState {
  enabled?: boolean
  headless?: boolean
  capacity?: number
  used?: number
  available?: number
  open_contexts?: number
  closing_contexts?: number
  closing_sessions?: string[]
  browser_count?: number
  pool_count?: number
  sessions?: FreeCamoufoxDebugSession[]
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
  last_probe_mode?: 'strict' | 'compat' | string
  last_probe_ok?: boolean | null
  source_label?: string
  effective_scheme?: string
  declared_scheme?: string
  probe_attempts?: number
  probe_successes?: number
  probe_success_rate?: number | null
  p50_latency_ms?: number | null
  p95_latency_ms?: number | null
  last_chatgpt_login_checked_at?: number | null
  last_chatgpt_login_status?: number
  last_chatgpt_login_probe_mode?: 'strict' | 'compat' | string
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
  proxy_scheme?: string
  proxy_source_label?: string
}
export const saveFreeConfig = (config: FreeConfigSavePayload) => api<{ ok: true; config: FreeConfig; state: FreeState; proxies?: any }>('/api/free/config', config)
export const getFreeState = () => api<{ ok: true; state: FreeState; config: FreeConfig }>('/api/free/state')
export const getFreeCamoufoxDebugState = () => api<{ ok: true; camoufox_debug: FreeCamoufoxDebugState; state: FreeState }>('/api/free/camoufox/debug')
export interface FreeCamoufoxDebugCloseResult {
  ok: true
  session_id?: string
  closed_pools?: number
  closed_contexts?: number
  closed_sessions?: number
  retained_contexts?: number
  remaining_contexts?: number
  remaining_sessions?: number
  state: FreeState
  camoufox_debug?: FreeCamoufoxDebugState
}
export const closeFreeCamoufoxDebug = (sessionId = '') => api<FreeCamoufoxDebugCloseResult>('/api/free/camoufox/debug/close', { session_id: sessionId })
export const preflightFree = (config?: Partial<FreeConfig> & { proxy_content?: string }) => api<{
  ok: true
  result: any
  state: FreeState
  config: FreeConfig
  incident_id?: string
  failure?: TaskFailure | null
}>('/api/free/preflight', config || {})
export const startFree = (config?: Partial<FreeConfig> & { proxy_content?: string; row_ids?: string[] }) => api<{ ok: true; batch_id: string; batch?: any; state: FreeState }>('/api/free/start', config || {})
export const rerunFreeTask = (taskId: string) => api<{ ok: true; batch_id: string; task?: any; batch?: any; state: FreeState }>('/api/free/rerun', { task_id: taskId })
export const stopFree = () => api<{ ok: true; state: FreeState }>('/api/free/stop', {})
export const getFreeLogs = (taskId = '') => api<{ ok: true; task_id?: string; logs: FreeLogEntry[] }>(`/api/free/logs${taskId ? `?task_id=${encodeURIComponent(taskId)}` : ''}`)
export interface DiagnosticIncident {
  incident_id: string
  created_at?: string
  updated_at?: string
  chain?: string
  workflow?: string
  driver?: string
  run_id?: string
  batch_id?: string
  task_id?: string
  subject_kind?: string
  subject_ref?: string
  subject_display?: string
  outcome?: string
  status?: string
  first_node_code?: string
  first_node_label?: string
  first_error_code?: string
  retryable?: boolean | number
  failure?: Record<string, any>
  event_count?: number
  integrity_status?: string
  match_basis?: string[]
  time_distance_seconds?: number | null
  events?: DiagnosticEvent[]
}
export interface DiagnosticEvent {
  event_id: string
  incident_id?: string
  occurred_at?: string
  received_at?: string
  chain?: string
  workflow?: string
  driver?: string
  task_id?: string
  batch_id?: string
  stage_group?: string
  node_code?: string
  node_label?: string
  sequence?: number
  attempt?: number
  attempt_group?: string
  outcome?: string
  parent_event_id?: string
  root_cause_event_id?: string
  elapsed_ms?: number | null
  failure?: Record<string, any>
  transport?: Record<string, any>
  message?: string
  redaction_applied?: boolean
}
export const searchDiagnostics = (query: Record<string, any>) => api<{ ok: true; results: DiagnosticIncident[] }>('/api/diagnostics/search', query)
export const getDiagnosticIncident = (incidentId: string) => api<{ ok: true; incident: DiagnosticIncident }>(`/api/diagnostics/incidents/${encodeURIComponent(incidentId)}`)
export const exportDiagnostics = (incidentIds: string[], format: 'json' | 'markdown' = 'markdown') => api<{ ok: true; format: string; content: string; redaction_applied: boolean }>('/api/diagnostics/export', { incident_ids: incidentIds, format })
export const deleteDiagnostics = (incidentIds: string[]) => api<{ ok: true; deleted: number }>('/api/diagnostics/delete', { incident_ids: incidentIds })
export const clearDiagnostics = () => api<{ ok: true; deleted: number }>('/api/diagnostics/clear-all', {})
export const getDiagnosticsHealth = () => api<{ ok: true; health: Record<string, any> }>('/api/diagnostics/health')
export interface FreeMailboxRow {
  created_at?: number | string
  row_id: string
  line_no: number
  email: string
  email_masked?: string
  source?: string
  mailbox_url?: string
  subject_ref_fingerprint?: string
  status: string
  cooldown_until?: number | null
  cooldown_remaining?: number
  stage?: string
  driver?: 'protocol' | 'camoufox' | string
  proxy_masked?: string
  proxy_fingerprint?: string
  proxy_scheme?: string
  proxy_country?: string
  proxy_group?: string
  plan_type?: string
  subscription_plan?: string
  plan_check_status?: string
  plan_check_task_id?: string
  plan_source?: string
  plan_retry_after_until?: number | null
  plus_trial_eligible?: boolean
  live_check_status?: 'queued' | 'running' | 'live' | 'deactivated' | 'token_expired' | 'free_live_proxy_blocked' | 'free_live_session_rejected' | 'free_live_rate_limited' | 'free_live_upstream_error' | 'free_live_network_error' | 'free_live_password_required' | 'failed' | string
  live_check_mode?: 'fast' | 'deep' | string
  live_check_task_id?: string
  live_checked_at?: number | string
  live_check_token_refreshed?: boolean
  live_check_http_status?: number | null
  live_check_failure?: TaskFailure | null
  twofa_status?: string
  twofa_error?: string
  has_access_token?: boolean
  has_password?: boolean
  has_totp?: boolean
  has_credential?: boolean
  credential_line?: string
  rebind_email?: string
  rebind_task_id?: string
  rebind_status?: string
  rebind_plan_type?: string
  rebind_plus_trial_eligible?: boolean
  task_id?: string
  retry_resolved?: boolean | string
  error?: string
  failure?: TaskFailure | null
}
export const getFreeMailboxes = () => api<{ ok: true; pool: 'free'; rows: FreeMailboxRow[]; state?: FreeState }>('/api/free/mailboxes')
export interface RemailOrder {
  order_no: string
  status: string
  delivery_email_masked?: string
  imported: boolean
  pool_row_id?: string
  payload?: Record<string, any>
  created_at?: string
  updated_at?: string
}
export const getRemailProfile = () => api<{ ok: true; profile: any }>('/api/remail/profile')
export const getRemailProjects = () => api<{ ok: true; projects: any }>('/api/remail/projects')
export const getRemailWallet = () => api<{ ok: true; wallet: any }>('/api/remail/wallet')
export const getRemailOrders = (query: { page?: number; page_size?: number; imported?: boolean | 'all'; search?: string } = {}) => api<{ ok: true; orders: RemailOrder[]; remote_count?: number; total: number; page: number; page_size: number; has_more: boolean }>(`/api/remail/orders?${new URLSearchParams(Object.entries(query).filter(([, value]) => value !== undefined && value !== '').map(([key, value]) => [key, String(value)]))}`)
export const purchaseRemail = (data: { project_id: number; email_suffix: string; quantity: number; supply?: string }) => api<{ ok: true; result: any }>('/api/remail/purchase', data)
export const importRemailOrders = (order_nos: string[]) => api<{ ok: true; imported: Array<{ order_no: string; row_id: string }>; skipped: Array<{ order_no: string; reason: string }> }>('/api/remail/orders/import', { order_nos })
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
export const getFreeRebindMailboxLatestCode = (rowId: string) => api<{ ok: true; kind: 'email'; code: string; message: string; fetched_at?: number }>('/api/free/rebind/mailboxes/latest-code', { row_id: rowId })
export const getFreeTaskLatestCode = (taskId: string) => api<{ ok: true; kind: 'email'; code: string; message: string; fetched_at?: number }>('/api/free/tasks/latest-code', { task_id: taskId })
export const freeBatchRetry = (taskIds: string[]) => api<{ ok: true; accepted: Array<{ task_id: string; retry_task: any }>; accepted_count: number; skipped: Array<{ task_id: string; reason: string }>; skipped_count: number; rejected: Array<{ task_id: string; reason: string }>; rejected_count: number; state?: FreeState }>('/api/free/retry/batch', { task_ids: taskIds })
export interface FreeLiveCheckState {
  running: boolean
  workers: number
  queue_limit: number
  active: number
  jobs: Array<{
    task_id: string
    row_id: string
    email: string
    email_masked?: string
    subject_ref_fingerprint?: string
    mode: 'fast' | 'deep' | string
    status: string
    stage?: string
    stage_label?: string
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
export interface FreePlanCheckState {
  running: boolean
  workers: number
  queue_limit: number
  active: number
  jobs: Array<{
    task_id: string
    row_id: string
    email: string
    email_masked?: string
    subject_ref_fingerprint?: string
    status: string
    created_at?: number
    updated_at?: number
    checked_at?: number
    retry_after_until?: number
    http_status?: number
    source?: string
    failure?: TaskFailure | null
  }>
}
export const startFreePlanCheck = (rowIds: string[]) => api<{
  ok: true
  accepted_count: number
  skipped_count: number
  skipped: Array<{ row_id: string; reason: string }>
  state: FreePlanCheckState
  rows: FreeMailboxRow[]
}>('/api/free/plan-check', { row_ids: rowIds })
export const getFreePlanCheckState = () => api<{ ok: true; state: FreePlanCheckState; rows: FreeMailboxRow[] }>('/api/free/plan-check/state')
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
export const importFreeProxies = (proxyContent: string, _country?: string, _group?: string, scheme?: string) => api<{ ok: true; imported: number; proxies?: any }>(
  '/api/free/proxies/import',
  { proxy_content: proxyContent, scheme },
)
export interface FreeProxyPreflightRow {
  index: number
  masked: string
  fingerprint: string
  scheme?: string
  declared_scheme?: string
  effective_scheme?: string
  available?: boolean
  http_status?: number | null
  provider_status?: number | null
  provider_code?: string
  local_to_proxy_ms?: number | null
  proxy_to_target_ms?: number | null
  failure_node?: string
  failure_reason?: string
  failure?: TaskFailure | null
  incident_id?: string
  layered_probe?: Record<string, any>
}

export interface FreeProxyPreflightResult {
  proxies: number
  rows: FreeProxyPreflightRow[]
  failure_count?: number
  health_write_failures?: number
  incident_id?: string
  failure?: TaskFailure | null
}

export const preflightFreeProxies = (proxyContent: string, proxyProbeUrl?: string, options: { driver?: string; scheme?: string; proxy_tls_verify?: boolean; proxy_tls_compat_fallback?: boolean; proxy_socks5_dns_mode?: string; layered_probe?: boolean } = {}) => api<{
  ok: true
  result: FreeProxyPreflightResult
  incident_id?: string
  failure?: TaskFailure | null
}>('/api/free/proxies/preflight', { proxy_content: proxyContent, proxy_probe_url: proxyProbeUrl, ...options })
export const getFreeProxies = () => api<{ ok: true; proxies: { count: number; rows: FreeProxyRow[]; groups: FreeProxySummary[]; countries: FreeProxySummary[] } }>('/api/free/proxies')
export const updateFreeProxyGroup = (payload: { country: string; group: string; new_country?: string; new_group?: string; enabled?: boolean }) => api<{ ok: true; result: any; proxies: any }>('/api/free/proxies/group', payload)
export const deleteFreeProxyGroup = (country: string, group: string) => api<{ ok: true; deleted: number; proxies: any }>('/api/free/proxies/group/delete', { country, group })
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

export interface FreeRebindMailboxRow {
  created_at?: number | string
  row_id: string
  line_no: number
  email: string
  status: string
  task_id?: string
  error?: string
  failure?: TaskFailure | null
}

export interface FreeRebindSourceRow {
  row_id: string
  email: string
  driver?: string
  status?: string
  plan_type?: string
  plus_trial_eligible?: boolean
  has_password: boolean
  has_totp: boolean
  proxy_masked?: string
  rebind_email?: string
  rebind_status?: string
}

export interface FreeRebindTask {
  task_id: string
  source_row_id: string
  source_email: string
  target_row_id: string
  target_email: string
  new_bound_email?: string
  status: string
  stage?: string
  stage_label?: string
  created_at?: number
  updated_at?: number
  proxy_masked?: string
  plan_type?: string
  subscription_plan?: string
  plus_trial_eligible?: boolean
  plan_check_status?: string
  error?: string
  failure?: TaskFailure | null
}

export interface FreeRebindState {
  running: boolean
  tasks: FreeRebindTask[]
  sources: FreeRebindSourceRow[]
  mailboxes: FreeRebindMailboxRow[]
  summary?: { total?: number; active?: number; success?: number; failed?: number; stopped?: number }
}

export const getFreeRebindState = () => api<{ ok: true } & FreeRebindState>('/api/free/rebind/state')
export const getFreeRebindMailboxes = () => api<{ ok: true; pool: 'free_rebind'; rows: FreeRebindMailboxRow[] }>('/api/free/rebind/mailboxes')
export const getFreeRebindMailboxUrl = (rowId: string) => api<{ ok: true; mailbox_url: string }>('/api/free/rebind/mailboxes/url', { row_id: rowId })
export const importFreeRebindMailboxes = (poolContent: string) => api<{ ok: true; imported: number; skipped: number; rows: FreeRebindMailboxRow[] }>(
  '/api/free/rebind/mailboxes/import',
  { pool_content: poolContent },
)
export const deleteFreeRebindMailboxes = (rowIds: string[]) => api<{ ok: true; deleted: number; rows: FreeRebindMailboxRow[] }>(
  '/api/free/rebind/mailboxes/delete',
  { row_ids: rowIds },
)
export const setFreeRebindMailboxStatus = (status: 'available' | 'unavailable', rowIds: string[]) => api<{ ok: true; updated: number; rows: FreeRebindMailboxRow[] }>(
  `/api/free/rebind/mailboxes/${status}`,
  { row_ids: rowIds },
)
export const startFreeRebind = (sourceRowId: string, targetRowId: string) => api<{ ok: true; task: FreeRebindTask; state: FreeRebindState }>(
  '/api/free/rebind/start',
  { source_row_id: sourceRowId, target_row_id: targetRowId },
)
export const retryFreeRebind = (taskId: string) => api<{ ok: true; task: FreeRebindTask; state: FreeRebindState }>(
  '/api/free/rebind/retry',
  { task_id: taskId },
)
export const stopFreeRebind = () => api<{ ok: true; state: FreeRebindState }>('/api/free/rebind/stop', {})
export const retryFreeTwofa = (id: string) => api<{ ok: true; task: any; state?: AppState }>(
  '/api/free/2fa/retry',
  { task_id: id, row_id: id },
)
export const retryFreePassword = (id: string) => api<{ ok: true; task: any; state?: FreeState }>(
  '/api/free/password/retry',
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
export const openManualVerification = (data: { task_id: string; input_kind?: ManualVerificationSubmission['input_kind']; generation?: number }) => (
  api<ManualVerificationRequest>('/api/runtime/tasks/manual-verification/open', data)
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
export const getMailboxParserSamples = (query: Record<string, any> = {}) => {
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
export const getMailboxParserSampleHealth = () => api<{ ok: true; health: Record<string, MailboxParserSampleHealth> }>('/api/mailbox-parser-samples/health')
export const testEmailNotification = (data: Record<string, any>) => api('/api/notifications/email/test', data)
export const querySmsBalances = (data: Record<string, any>) => (
  api<{ ok: true; queried_at: number; sms_key_statuses: SmsKeyStatus[] }>('/api/sms/balances', data)
)

export interface PaymentToolConfig {
  mode: 'local' | 'manual' | 'cdk' | 'http' | 'pay153' | string
  workers: number
  timeout_seconds: number
  country: string
  currency: string
  plan: string
  channel: string
  apply_checkout_update: boolean
  checkout_proxy: string
  update_proxy: string
  cdk_base_url: string
  cdk: string
  http_endpoint: string
  http_api_token: string
  pay153_url: string
  pay153_headless: boolean
}
export interface PaymentTask {
  task_id: string
  source: string
  row_id?: string
  email?: string
  mode: string
  channel: string
  plan: string
  country: string
  currency: string
  status: string
  stage: string
  target_domain?: string
  confirmed?: boolean
  created_at?: number
  updated_at?: number
  retry_count?: number
  logs_count?: number
  result_summary?: { has_result?: boolean; result_kind?: string; result_host?: string }
  failure?: { node_code?: string; node_label?: string; public_message?: string; retryable?: boolean } | null
}
export const getPaymentConfig = () => api<{ ok: true; config: PaymentToolConfig; state: { tasks: PaymentTask[]; summary: Record<string, number> } }>('/api/tools/payment/config')
export const savePaymentConfig = (config: Partial<PaymentToolConfig>) => api<{ ok: true; config: PaymentToolConfig }>('/api/tools/payment/config', config)
export const getPaymentTasks = () => api<{ ok: true; tasks: PaymentTask[]; summary: Record<string, number> }>('/api/tools/payment/tasks')
export const createPaymentTasks = (payload: Record<string, any>) => api<{ ok: true; tasks: PaymentTask[]; requires_confirmation?: boolean }>('/api/tools/payment/tasks', payload)
export const getPaymentTaskLogs = (taskId: string) => api<{ ok: true; task_id: string; logs: Array<{ time?: number; stage?: string; level?: string; message?: string }> }>(`/api/tools/payment/tasks/${encodeURIComponent(taskId)}/logs`)
export const confirmPaymentTask = (taskId: string, targetDomain: string) => api<{ ok: true; task?: PaymentTask }>(`/api/tools/payment/tasks/${encodeURIComponent(taskId)}/confirm`, { target_domain: targetDomain })
export const cancelPaymentTask = (taskId: string) => api<{ ok: true; task?: PaymentTask }>(`/api/tools/payment/tasks/${encodeURIComponent(taskId)}/cancel`, {})
export const retryPaymentTask = (taskId: string) => api<{ ok: true; task?: PaymentTask }>(`/api/tools/payment/tasks/${encodeURIComponent(taskId)}/retry`, {})
export const getPaymentSecret = (taskId: string) => api<{ ok: true; value: string }>(`/api/tools/payment/tasks/${encodeURIComponent(taskId)}/secret`)

export interface NetworkProxyRow {
  created_at?: number | string
  proxy_id: string
  fingerprint?: string
  masked: string
  scheme: string
  country: string
  group: string
  enabled: boolean
  status: string
  latency_ms?: number | null
  consecutive_failures?: number
  last_checked_at?: number | null
  last_failure?: string | null
}
export interface NetworkToolGroup {
  country: string
  group: string
  total: number
  enabled: number
  available: number
  leased: number
  quarantined: number
  schemes: string[]
}
export const getNetworkTools = () => api<{ ok: true; rows: NetworkProxyRow[]; groups: NetworkToolGroup[]; total: number; config: Record<string, any> }>('/api/tools/proxies')
export const saveNetworkToolsConfig = (config: Record<string, any>) => api<{ ok: true; config: Record<string, any> }>('/api/tools/proxies/config', config)
export const importNetworkProxies = (payload: { proxy_content: string; country?: string; group?: string; scheme?: string }) => api<{ ok: true; imported: number; skipped: number; rows: NetworkProxyRow[]; groups: NetworkToolGroup[] }>('/api/tools/proxies/import', payload)
export const importNetworkSubscription = (payload: { subscription_url: string; content: string; country?: string; group?: string }) => api<{ ok: true; subscription_id: string; node_count: number; imported: number; rows: NetworkProxyRow[]; groups: NetworkToolGroup[] }>('/api/tools/proxies/subscriptions', payload)
export const testNetworkSubscription = (payload: { subscription_id: string; target_url?: string; exit_url?: string }) => api<{ ok: true; tested: boolean; available: boolean; message?: string; proxy_to_target_ms?: number }>('/api/tools/proxies/subscriptions/test', payload)
export const testNetworkProxy = (payload: { proxy_id: string; mode: 'quick' | 'deep'; target_url?: string; exit_url?: string }) => api<{ ok: true; result?: any; proxy_id?: string; local_to_proxy_ms?: number; proxy_to_target_ms?: number }>('/api/tools/proxies/test', payload)
export const updateNetworkGroup = (payload: { country: string; group: string; action: string; new_group?: string; enabled?: boolean }) => api<{ ok: true; rows: NetworkProxyRow[]; groups: NetworkToolGroup[] }>('/api/tools/proxies/group', payload)
export const deleteNetworkGroup = (country: string, group: string) => api<{ ok: true; rows: NetworkProxyRow[]; groups: NetworkToolGroup[] }>('/api/tools/proxies/group/delete', { country, group })
