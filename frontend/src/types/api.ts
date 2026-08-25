export interface SmsKeyStatus {
  provider?: string
  platform?: string
  service?: string
  index: number
  fingerprint: string
  status: string
  balance_usd: number | null
  message?: string
  in_flight?: number
  retry_after_seconds?: number
  last_checked_at?: number
  inventory_count?: number
  minimum_price?: number | null
}

export interface SmsProviderPool {
  provider: string
  enabled: boolean
  api_keys: string[]
  service: string
}

export interface SmsRuntimeAlert {
  id: string
  generation?: string
  kind: string
  level: 'success' | 'warning' | 'info' | 'error'
  message: string
  persistent?: boolean
  created_at?: number
  provider?: string
}

export type TaskStageGroup = 'queue' | 'oauth' | 'email' | 'phone' | 'sms' | 'free' | 'finalizing'

export interface TaskStageTiming {
  code: string
  label: string
  group: TaskStageGroup
  elapsed_seconds: number
  visits: number
}

export interface TaskTimingSegment {
  code: string
  label: string
  elapsed_seconds: number
  visits: number
}

export interface TaskTiming {
  started_at: number
  queued_at?: number
  execution_started_at?: number | null
  finished_at: number | null
  elapsed_seconds: number
  queue_elapsed_seconds?: number
  execution_elapsed_seconds?: number
  stages: TaskStageTiming[]
  segments?: TaskTimingSegment[]
}

export interface TaskProgress {
  code: string
  label: string
  group: TaskStageGroup
  entered_at: number
  finished_at: number | null
  timing?: TaskTiming
}

export type TaskStageCounts = Record<TaskStageGroup, number>

export interface TaskFailure {
  node_code: string
  node_label: string
  error_code: string
  provider_code?: string
  public_message: string
  technical_summary?: string
  retryable: boolean
  http_status?: number | null
  action_hint?: string
  diagnostic_action?: 'openai_connectivity' | string
  page_type?: string
  safe_page?: string
  content_type?: string
  session_rebuilds?: number
}

export interface FreeLogEntry {
  time?: string | number
  level?: string
  message?: string
  task_id?: string
  stage?: string
  stage_label?: string
  node_code?: string
  node_label?: string
  error_code?: string
  provider_code?: string
  page?: string
  safe_page?: string
  page_type?: string
  content_type?: string
  session_rebuilds?: number
  http_status?: number | string | null
  attempt?: number | string
  duration_ms?: number | string
  outcome?: string
  diagnostic?: string
  technical_summary?: string
  action_hint?: string
  retryable?: boolean
  result?: string
  incident_id?: string
}

export type ManualVerificationInputKind = 'email_otp' | 'sms_otp' | 'totp'

export interface ManualVerificationRequest {
  input_kind: ManualVerificationInputKind
  generation: number
  opened_at: number
  deadline_at: number
  capabilities: Array<'submit'>
  can_submit: boolean
  remaining_seconds: number
}

export interface ManualVerificationSubmission {
  task_id: string
  input_kind: ManualVerificationInputKind
  generation: number
  code: string
}

export interface ManualVerificationAccepted {
  ok: true
  accepted: true
  task_id: string
  input_kind: ManualVerificationInputKind
  generation: number
}

export type TaskCheckpointState =
  | 'saved'
  | 'restored'
  | 'available'
  | 'claimed'
  | 'disabled'
  | 'expired'
  | 'invalid'

export interface TaskCheckpoint {
  state: TaskCheckpointState
  resume_stage: 'phone_acquiring' | ''
  expires_at: number | null
  age?: number
  age_seconds?: number
  remaining_seconds?: number
  reason: string
}

export interface RuntimeTask {
  task_id: string
  incident_id?: string
  run_mode?: 'register' | 'free_register' | 'relogin' | string
  account?: string
  email?: string
  ordinal?: number
  batch_id?: string
  batch_started_at?: number
  has_mailbox_url?: boolean
  has_mailbox_password?: boolean
  has_totp?: boolean
  status?: string
  error?: string
  reason?: string
  failure?: TaskFailure | null
  created_at?: number
  updated_at?: number
  progress?: TaskProgress | null
  timing?: TaskTiming | null
  manual_verification?: ManualVerificationRequest | null
  checkpoint?: TaskCheckpoint | null
  proxy_masked?: string
  proxy_fingerprint?: string
  exit_ip?: string
  result?: {
    plan_type?: string
    plus_trial_eligible?: boolean
    twofa_status?: string
    twofa_error?: string
    has_access_token?: boolean
    has_password?: boolean
    has_totp?: boolean
    has_credential?: boolean
    proxy?: string
    exit_ip?: string
    sms_cost_usd?: number | null
    sms_cost_cny?: number | null
    sms_exchange_rate?: number | null
    sms_exchange_date?: string
    timing?: TaskTiming
    run_mode?: 'relogin' | string
    batch_id?: string
    batch_started_at?: number
  }
}

export interface RuntimeSummary {
  run_id?: string
  batch_id?: string
  batch_started_at?: number | null
  target?: number
  total?: number
  active?: number
  success?: number
  failed?: number
  stopped?: number
  started_at?: number | null
  last_activity_at?: number | null
  finished_at?: number | null
  sms_cost_usd?: number
  sms_cost_cny?: number
  sms_cost_history?: {
    account_count: number
    total_cny: number
    average_cny: number
  }
}

export interface NotificationRuntimeStatus {
  event?: string
  status?: 'queued' | 'sent' | 'failed'
  timestamp?: number
  recipient_count?: number
  error?: string
}

export type OpenAIConnectivityStatus = 'unknown' | 'healthy' | 'outage' | 'recovering'

export interface OpenAIAuthConnectivityState {
  status?: OpenAIConnectivityStatus
  runtime_epoch?: number | string
  revision?: number | string
  incident_id?: string
  event_id?: string
  reason_code?: string
  reason_label?: string
  enabled?: boolean
  paused?: boolean
  pause_reason?: string
  node_code?: string
  node_label?: string
  affected_origins?: string[]
  detected_at?: number | null
  recovered_at?: number | null
  updated_at?: number | null
  failure_count?: number
  consecutive_failures?: number
  failure_counts?: Record<string, number>
  probe_success_rounds?: number
  probe_successful_rounds?: number
  probe_required_rounds?: number
  last_probe_at?: number | null
  next_probe_at?: number | null
  next_probe_in_seconds?: number
  proxy_fingerprint?: string
  probe?: {
    successful_rounds?: number
    required_rounds?: number
    next_probe_at?: number | null
  }
}

export interface OpenAIConnectivityDiagnosticOrigin {
  origin: string
  reachable: boolean
  service_status?: 'available' | 'rate_limited' | 'upstream_error' | 'transport_error' | string
  service_available?: boolean
  latency_ms?: number
  status_code?: number | null
  reason_code?: string
  reason_label?: string
  technical_summary?: string
}

export interface OpenAIConnectivityDiagnosticSentinel {
  attempted: boolean
  ok: boolean
  skipped_reason?: string
  latency_ms?: number
  error_code?: string
  public_message?: string
  technical_summary?: string
}

export interface OpenAIConnectivityDiagnostic {
  tested_at?: number
  proxy_configured?: boolean
  overall: 'healthy' | 'degraded' | 'failed' | string
  network: OpenAIConnectivityDiagnosticOrigin[]
  sentinel: OpenAIConnectivityDiagnosticSentinel
  elapsed_ms?: number
}

export interface RuntimeCapacitySnapshot {
  active?: number
  base?: number
  baseline?: number
  ceiling?: number
  healthy_ceiling?: number
  limit?: number
  waiting?: number
  paused?: boolean
  suspended?: boolean
  pause_reason?: string
  last_reason?: string
  pause_remaining_seconds?: number
  sticky_baseline?: boolean
  expansion_eligible?: boolean
  recovery_eligible?: boolean
  restore_ceiling?: number
}

export interface RuntimeConcurrencyState {
  task?: RuntimeCapacitySnapshot
  node?: RuntimeCapacitySnapshot
  protocol?: RuntimeCapacitySnapshot
  email?: RuntimeCapacitySnapshot
  phone?: RuntimeCapacitySnapshot
  [key: string]: RuntimeCapacitySnapshot | undefined
}

export interface RuntimeState {
  running?: boolean
  stop_requested?: boolean
  tasks?: RuntimeTask[]
  pool?: Record<string, any>
  free_register?: {
    running?: boolean
    batch_id?: string
    pool?: { total?: number; available?: number; proxies?: number }
    summary?: RuntimeSummary
  }
  concurrency?: RuntimeConcurrencyState
  connectivity?: {
    openai_auth?: OpenAIAuthConnectivityState
  }
  stage_counts?: Partial<TaskStageCounts>
  sms_key_statuses?: SmsKeyStatus[]
  sms_alerts?: SmsRuntimeAlert[]
  sms_safe_stop?: boolean
  summary?: RuntimeSummary
  notification?: NotificationRuntimeStatus
}

export interface AppState {
  settings?: Record<string, any>
  runtime?: RuntimeState
  logs?: Array<{ time?: string; level?: string; type?: string; message?: string; text?: string }>
  sms_key_statuses?: SmsKeyStatus[]
  sms_alerts?: SmsRuntimeAlert[]
}

export interface MailboxRow {
  row_id: string
  line_no: number
  display_index?: number
  source_row: string
  email: string
  password?: string
  has_totp?: boolean
  has_mailbox_url?: boolean
  phone_risk_retry?: boolean
  phone_risk_label?: string
  quota_status?: 'ok' | 'error' | string
  quota_error?: string
  quota_queried_at?: number | null
  quota_5h?: OpenAIQuotaWindow | null
  quota_7d?: OpenAIQuotaWindow | null
  status: string
  status_label?: string
  pool_status?: string
  manual_sms_received?: boolean
  error?: string
  reason?: string
  technical_error?: string
  failure?: TaskFailure | null
  task_id?: string
  task_status?: string
  run_mode?: 'register' | 'relogin' | string
  batch_id?: string
  batch_started_at?: number
  progress?: TaskProgress | null
  timing?: TaskTiming | null
  sms_cost_usd?: number | null
  sms_cost_cny?: number | null
  sms_exchange_rate?: number | null
  sms_exchange_date?: string
  sub2api_account_id?: string
  sub2_status?: Sub2MailboxStatus | null
  updated_at?: number
}

export type MailboxRowAction =
  | 'copy_email'
  | 'copy_password'
  | 'copy_totp'
  | 'open_url'
  | 'manual_used'
  | 'manual_unused'
  | 'draft'
  | 'restore'
  | 'unavailable'
  | 'relogin'
  | 'delete'

export interface OpenAIQuotaWindow {
  remaining_percent: number | null
  reset_at?: number | null
  reset_after_seconds?: number | null
  queried_at?: number | null
  status?: string
}

export interface Sub2MailboxStatus {
  kind?: string
  status?: string
  code?: number | string | null
  status_code?: number | string | null
  label?: string
  summary?: string
  tested_at?: number | string | null
  is_test_failure?: boolean
  is_error?: boolean
  is_abnormal?: boolean
  needs_rerun?: boolean
  linked?: boolean
  remote_account_id?: number | string | null
}

export type MailboxOperationKind = 'quota' | 'openai_test'
export type MailboxOperationStatus = 'running' | 'completed' | 'failed'

export interface MailboxOperationRowUpdate {
  row_id: string
  line_no: number
  quota_status?: 'ok' | 'error'
  quota_error?: string
  quota_error_code?: string
  quota_queried_at?: number | null
  quota_5h?: OpenAIQuotaWindow | null
  quota_7d?: OpenAIQuotaWindow | null
  sub2_status?: Sub2MailboxStatus | null
}

export interface MailboxBatchOperation {
  job_id: string
  kind: MailboxOperationKind
  status: MailboxOperationStatus
  total: number
  completed: number
  succeeded: number
  failed: number
  skipped: number
  tested: number
  rate_limited: number
  not_ready: number
  deactivated_deleted?: number
  created_at: number
  updated_at: number
  row_updates: MailboxOperationRowUpdate[]
  finished_at?: number | null
  node_code?: string
  node_label?: string
  error_code?: string
  error?: string
}

export interface MailboxPayload {
  ok?: boolean
  counts: Record<string, number>
  rows: MailboxRow[]
  operation?: MailboxBatchOperation | null
  performance?: {
    result_index?: {
      enabled: boolean
      cache_active: boolean
      rollback_active: boolean
      rollback_reason: string
      files_scanned: number
      cache_hits: number
      files_read: number
      elapsed_ms: number
    }
  }
}

export interface MailboxUrlTestDiagnostics {
  listing_messages: number
  detail_links: number
  detail_refreshed: number
  detail_cache_hits: number
  detail_refresh_pending: number
  detail_errors: number
  openai_messages: number
  code_messages: number
}

export interface MailboxUrlTestResult {
  ok: boolean
  code?: string
  verification_code?: string
  email?: string
  code_found: boolean
  reason: string
  error?: string
  attempts: number
  elapsed_seconds: number
  resend_attempted: boolean
  resend_succeeded: boolean
  diagnostics: MailboxUrlTestDiagnostics
}

export interface LatestCodeValue {
  code: string
  kind?: string
  message?: string
  remaining?: number
  receivedAt: number
}

export interface ApiErrorPayload {
  ok?: false
  error?: string
  code?: string
  state?: AppState
  [key: string]: any
}
