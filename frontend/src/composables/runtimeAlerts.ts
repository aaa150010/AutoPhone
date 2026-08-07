import type { SmsRuntimeAlert } from '../types/api'

const BALANCE_ALERT_KINDS = new Set([
  'insufficient_balance',
  'sms_balance_insufficient',
])

export const RUNTIME_ALERT_HISTORY_LIMIT = 256

export function runtimeAlertDuration(alert: Pick<SmsRuntimeAlert, 'kind' | 'persistent'>) {
  if (BALANCE_ALERT_KINDS.has(alert.kind)) return 3000
  return alert.persistent ? 0 : 5000
}

function runtimeAlertIdentity(alert: SmsRuntimeAlert) {
  return JSON.stringify([
    alert.generation || '',
    alert.id,
    alert.created_at || 0,
    alert.kind || '',
    alert.level || '',
    alert.message || '',
  ])
}

export function createRuntimeAlertTracker(limit = RUNTIME_ALERT_HISTORY_LIMIT) {
  const maximum = Math.max(1, Math.min(4096, Math.trunc(Number(limit)) || 1))
  const seen = new Set<string>()
  const order: string[] = []

  return {
    accept(alert: SmsRuntimeAlert) {
      if (!alert?.id) return false
      const identity = runtimeAlertIdentity(alert)
      if (seen.has(identity)) return false
      seen.add(identity)
      order.push(identity)
      while (order.length > maximum) {
        const oldest = order.shift()
        if (oldest) seen.delete(oldest)
      }
      return true
    },
    get size() {
      return seen.size
    },
  }
}
