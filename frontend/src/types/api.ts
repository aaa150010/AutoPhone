export interface SmsKeyStatus {
  index: number
  fingerprint: string
  status: string
  balance_usd: number | null
  message?: string
  in_flight?: number
  retry_after_seconds?: number
  last_checked_at?: number
}

export interface SmsRuntimeAlert {
  id: string
  kind: string
  level: 'success' | 'warning' | 'info' | 'error'
  message: string
  persistent?: boolean
  created_at?: number
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

export interface RuntimeTask {
  task_id: string
  account?: string
  email?: string
  ordinal?: number
  status?: string
  error?: string
  reason?: string
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
  status: string
  status_label?: string
  pool_status?: string
  error?: string
  reason?: string
  task_id?: string
  task_status?: string
  progress?: TaskProgress | null
  sms_cost_usd?: number | null
  sms_cost_cny?: number | null
  sms_exchange_rate?: number | null
  sms_exchange_date?: string
  updated_at?: number
}

export interface MailboxPayload {
  ok?: boolean
  counts: Record<string, number>
  rows: MailboxRow[]
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
