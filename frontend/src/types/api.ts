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
  kind: string
  level: 'success' | 'warning' | 'info' | 'error'
  message: string
  persistent?: boolean
  created_at?: number
  provider?: string
}

export type TaskStageGroup = 'queue' | 'oauth' | 'email' | 'phone' | 'sms' | 'finalizing'

export interface TaskProgress {
  code: string
  label: string
  group: TaskStageGroup
  entered_at: number
  finished_at: number | null
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
}

export interface RuntimeTask {
  task_id: string
  account?: string
  email?: string
  ordinal?: number
  status?: string
  error?: string
  reason?: string
  failure?: TaskFailure | null
  created_at?: number
  updated_at?: number
  progress?: TaskProgress | null
  result?: {
    sms_cost_usd?: number | null
    sms_cost_cny?: number | null
  }
}

export interface RuntimeSummary {
  run_id?: string
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
}

export interface NotificationRuntimeStatus {
  event?: string
  status?: 'queued' | 'sent' | 'failed'
  timestamp?: number
  recipient_count?: number
  error?: string
}

export interface RuntimeState {
  running?: boolean
  stop_requested?: boolean
  tasks?: RuntimeTask[]
  pool?: Record<string, any>
  concurrency?: Record<string, any>
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
  source_row: string
  email: string
  password?: string
  has_totp?: boolean
  quota_status?: 'ok' | 'error' | string
  quota_error?: string
  quota_queried_at?: number | null
  quota_5h?: OpenAIQuotaWindow | null
  quota_7d?: OpenAIQuotaWindow | null
  status: string
  status_label?: string
  pool_status?: string
  error?: string
  reason?: string
  technical_error?: string
  failure?: TaskFailure | null
  task_id?: string
  task_status?: string
  batch_id?: string
  batch_started_at?: number
  progress?: TaskProgress | null
  sms_cost_usd?: number | null
  sms_cost_cny?: number | null
  sms_exchange_rate?: number | null
  sms_exchange_date?: string
  sub2api_account_id?: string
  sub2_status?: Sub2MailboxStatus | null
  updated_at?: number
}

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

export interface MailboxPayload {
  ok?: boolean
  counts: Record<string, number>
  rows: MailboxRow[]
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

export interface PixelTarget {
  id: string
  email: string
  connected: boolean
  accountCount: number | null
  lastCheckedAt: string | null
  error: string | null
  autoUpload: boolean
}

export interface PixelAccount {
  id: number
  name: string
  platform: string
  accountLevel: string
  type: string
  shareMode: string
  shareStatus: string
  concurrency: number
  currentConcurrency: number
  status: string
  schedulable: boolean
  credentialsStatus: string
  errorMessage: string
  expiresAt: string | null
  updatedAt: string | null
}

export interface PixelAccountPage {
  items: PixelAccount[]
  total: number
  page: number
  pageSize: number
  pages: number
  target?: PixelTarget
}

export interface PixelBulkOperationResponse {
  ok?: boolean
  success?: number
  failed?: number
  successIds?: number[]
  failedIds?: number[]
  message?: string
  results?: Array<Record<string, any>>
}

export type PixelUploadTargetState =
  | 'pending'
  | 'uploading'
  | 'success'
  | 'partial'
  | 'failed'
  | 'retry_pending'
  | 'needs_confirmation'
  | 'source_unavailable'

export interface PixelUploadTargetRecord {
  targetId: string
  status: PixelUploadTargetState | string
  stage: string
  generatedName: string
  remoteAccountId: number | string | null
  failedIds: Array<number | string>
  concurrency: number | null
  error: string
  attempts: number
  updatedAt: string | number | null
  retryable: boolean
}

export interface PixelUploadRecord {
  recordId: string
  taskId: string
  jobId: string
  status: PixelUploadTargetState | string
  error: string
  sourceAvailable: boolean
  canRetry: boolean
  createdAt: string | number | null
  updatedAt: string | number | null
  targets: PixelUploadTargetRecord[]
}
