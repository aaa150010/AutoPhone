import type { RuntimeTask } from '../types/api'

// Keep this tiny normalizer local.  The utility is also executed directly by
// the Node-based unit tests, where extensionless TypeScript imports are not
// resolved like they are by Vite.  This preserves the same semantics for
// legacy persisted snapshots without adding a runtime module dependency.
function isRetryResolved(value: unknown): boolean {
  return value === true || String(value || '').trim().toLowerCase() === 'true'
}

export const terminalTaskStatuses = new Set([
  'success', 'failed', 'stopped', 'stopped_before_start', 'cancelled', 'canceled', 'retryable_infra',
  'retryable_email', 'repair_pending', 'email_damaged', 'account_banned',
  'twofa_pending',
])

export const failedTaskStatuses = new Set([
  'failed', 'retryable_infra', 'retryable_email', 'repair_pending', 'email_damaged', 'account_banned',
])

export function taskVerificationKey(task: RuntimeTask) {
  const request = task.manual_verification
  return `${task.task_id}:${request?.input_kind || ''}:${Number(request?.generation || 0)}`
}

export function taskNeedsVerification(task: RuntimeTask) {
  return Boolean(task.manual_verification?.can_submit && task.manual_verification?.capabilities?.includes('submit'))
}

export function taskNeedsAttention(task: RuntimeTask, accepted: ReadonlySet<string>) {
  if (isRetryResolved(task.retry_resolved)) return false
  return (taskNeedsVerification(task) && !accepted.has(taskVerificationKey(task)))
    || String(task.status || '').toLowerCase() === 'twofa_pending'
    || failedTaskStatuses.has(String(task.status || '').toLowerCase())
}

export function pendingTaskRows(tasks: RuntimeTask[], accepted: ReadonlySet<string>) {
  return [...tasks].filter(task => taskNeedsAttention(task, accepted)).sort((a, b) => {
    const aManual = taskNeedsVerification(a)
    const bManual = taskNeedsVerification(b)
    if (aManual !== bManual) return aManual ? -1 : 1
    if (aManual && bManual) {
      return Number(a.manual_verification?.deadline_at || 0) - Number(b.manual_verification?.deadline_at || 0)
    }
    return Number(b.updated_at || b.created_at || 0) - Number(a.updated_at || a.created_at || 0)
  })
}

export function runningTaskRows(tasks: RuntimeTask[], accepted: ReadonlySet<string>) {
  return tasks.filter(task => (
    !terminalTaskStatuses.has(String(task.status || '').toLowerCase())
    && !(taskNeedsVerification(task) && !accepted.has(taskVerificationKey(task)))
  ))
}
