export interface MailboxRow { line_no: number; source_row: string; email: string; password?: string; status: string; status_label?: string; error?: string; reason?: string }
export interface MailboxPayload { counts: Record<string, number>; rows: MailboxRow[] }
