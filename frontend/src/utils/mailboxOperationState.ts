import type { MailboxBatchOperation } from '../types/api'

export const MAILBOX_OPERATION_NOTIFICATION_KEY = 'gptphone_mailbox_operation_notified'
export const MAILBOX_OPERATION_RETRY_PROMPT_KEY = 'gptphone_mailbox_operation_retry_prompted'

export interface MailboxOperationStorage {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
}

export function mailboxOperationNotificationId(operation: MailboxBatchOperation) {
  return `${operation.job_id}:${operation.status}`
}

export function claimMailboxOperationNotification(
  operation: MailboxBatchOperation,
  storage: MailboxOperationStorage,
) {
  const id = mailboxOperationNotificationId(operation)
  if (storage.getItem(MAILBOX_OPERATION_NOTIFICATION_KEY) === id) return false
  storage.setItem(MAILBOX_OPERATION_NOTIFICATION_KEY, id)
  return true
}

export function claimMailboxOperationRetryPrompt(
  operation: MailboxBatchOperation,
  storage: MailboxOperationStorage,
) {
  const id = mailboxOperationNotificationId(operation)
  if (storage.getItem(MAILBOX_OPERATION_RETRY_PROMPT_KEY) === id) return false
  storage.setItem(MAILBOX_OPERATION_RETRY_PROMPT_KEY, id)
  return true
}

const RETRYABLE_OPENAI_TEST_KINDS = new Set([
  'network_error',
  'remote_disconnected',
  'timeout',
  'upstream_error',
])

export function retryableOpenAITestBindings(operation: MailboxBatchOperation) {
  if (operation.kind !== 'openai_test' || operation.status === 'running') return []
  const result: Array<{ row_id: string; line_no: number }> = []
  const seen = new Set<string>()
  for (const update of operation.row_updates || []) {
    const status = update.sub2_status || {}
    const kind = String(status.kind || '').trim().toLowerCase()
    const parsedCode = Number(status.status_code ?? status.code)
    const retryable = RETRYABLE_OPENAI_TEST_KINDS.has(kind)
      || (Number.isFinite(parsedCode) && parsedCode >= 500)
    const rowId = String(update.row_id || '').trim()
    const lineNo = Number(update.line_no || 0)
    const key = `${rowId}:${lineNo}`
    if (!retryable || !rowId || lineNo <= 0 || seen.has(key)) continue
    seen.add(key)
    result.push({ row_id: rowId, line_no: lineNo })
  }
  return result
}

function operationTime(value: unknown) {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : 0
}

function isTerminal(operation: MailboxBatchOperation) {
  return operation.status !== 'running'
}

export function shouldApplyMailboxOperationUpdate(
  current: MailboxBatchOperation | null,
  next: MailboxBatchOperation | null,
  authoritativeJobId = '',
) {
  if (!current) return true
  if (!next) return isTerminal(current)
  if (next.job_id !== current.job_id) {
    if (authoritativeJobId && next.job_id === authoritativeJobId) return true
    return operationTime(next.created_at) > operationTime(current.created_at)
  }
  if (isTerminal(current) && !isTerminal(next)) return false
  const nextUpdatedAt = operationTime(next.updated_at)
  const currentUpdatedAt = operationTime(current.updated_at)
  if (nextUpdatedAt !== currentUpdatedAt) return nextUpdatedAt > currentUpdatedAt
  if (Number(next.completed || 0) < Number(current.completed || 0)) return false
  if ((next.row_updates?.length || 0) < (current.row_updates?.length || 0)) return false
  return true
}
