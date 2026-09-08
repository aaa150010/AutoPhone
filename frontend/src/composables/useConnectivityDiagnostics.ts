import { readonly, shallowRef } from 'vue'
import type { AppState, TaskFailure } from '../types/api'
import { failureReason, needsDiagnostic, type ApiFailureError } from '../utils/connectivityClassification.ts'

export interface ConnectivityDiagnosticRequest {
  id: string
  reason: string
}

export function createConnectivityDiagnosticTrigger(limit = 128) {
  const request = shallowRef<ConnectivityDiagnosticRequest | null>(null)
  const seen = new Set<string>()
  const order: string[] = []
  let serial = 0

  function remember(id: string) {
    if (seen.has(id)) return false
    seen.add(id)
    order.push(id)
    while (order.length > Math.max(8, limit)) {
      const oldest = order.shift()
      if (oldest) seen.delete(oldest)
    }
    return true
  }

  function emit(id: string, reason: string, force = false) {
    if (!force && !remember(id)) return false
    request.value = { id: `${id}:${++serial}`, reason }
    return true
  }

  function observeState(state: AppState) {
    const runtime = state.runtime || {}
    const connectivity = runtime.connectivity?.openai_auth
    if (connectivity?.status === 'outage' || connectivity?.status === 'recovering') {
      const id = String(connectivity.incident_id || connectivity.event_id || connectivity.detected_at || connectivity.revision || 'openai-outage')
      if (emit(`outage:${id}`, String(connectivity.reason_label || 'OpenAI Auth/Sentinel 链路不可达'))) return
    }
    const currentBatch = String(runtime.summary?.batch_id || '')
    const tasks = currentBatch
      ? (runtime.tasks || []).filter(task => String(task.batch_id || '') === currentBatch)
      : (runtime.tasks || [])
    for (const task of tasks) {
      if (!needsDiagnostic(task.failure, task.error || task.reason || '')) continue
      const batch = String(task.batch_id || currentBatch || 'unbatched')
      if (emit(`batch:${batch}:openai-connectivity`, failureReason(task.failure, task.error || task.reason || ''))) return
    }
  }

  function observeError(error: unknown) {
    if (!(error instanceof Error) || error.name !== 'ApiError') return
    const apiError = error as ApiFailureError
    const failure: TaskFailure | undefined = apiError.payload?.failure
    if (!needsDiagnostic(failure, apiError.message)) return
    const identity = [
      apiError.status,
      failure?.node_code || 'unknown-node',
      failure?.error_code || 'unknown-error',
      failureReason(failure, apiError.message),
    ].join(':')
    emit(`api:${identity}`, failureReason(failure, apiError.message))
  }

  function open(reason = '手动检查当前 OpenAI 授权链路') {
    emit('manual', reason, true)
  }

  function clear() {
    request.value = null
  }

  return { request: readonly(request), observeState, observeError, open, clear }
}
