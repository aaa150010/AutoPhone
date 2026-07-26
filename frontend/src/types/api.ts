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

export interface MailboxRow {
  line_no: number
  source_row: string
  email: string
  password?: string
  status: string
  status_label?: string
  error?: string
  reason?: string
  sms_cost_usd?: number | null
  sms_cost_cny?: number | null
  sms_exchange_rate?: number | null
  sms_exchange_date?: string
}
export interface MailboxPayload { counts: Record<string, number>; rows: MailboxRow[] }
