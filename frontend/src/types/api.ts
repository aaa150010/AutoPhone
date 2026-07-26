export interface SmsKeyStatus {
  index: number
  fingerprint: string
  status: string
  balance_usd: number | null
  message?: string
  in_flight?: number
  retry_after_seconds?: number
}

export interface SmsRuntimeAlert {
  id: string
  kind: string
  level: 'success' | 'warning' | 'info' | 'error'
  message: string
  persistent?: boolean
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
  status?: string
  error?: string
  reason?: string
  progress?: TaskProgress | null
}

export interface MailboxRow {
  line_no: number
  source_row: string
  email: string
  password?: string
  status: string
  status_label?: string
  error?: string
  reason?: string
  task_id?: string
  task_status?: string
  progress?: TaskProgress | null
  sms_cost_usd?: number | null
  sms_cost_cny?: number | null
  sms_exchange_rate?: number | null
  sms_exchange_date?: string
}
export interface MailboxPayload { counts: Record<string, number>; rows: MailboxRow[] }
