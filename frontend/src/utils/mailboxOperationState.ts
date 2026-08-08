import type { MailboxBatchOperation } from '../types/api'

export const MAILBOX_OPERATION_NOTIFICATION_KEY = 'gptphone_mailbox_operation_notified'

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
