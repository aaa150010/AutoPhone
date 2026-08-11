import { readonly, shallowRef } from 'vue'
import type { AppState, TaskFailure } from '../types/api'

interface ApiFailureError extends Error {
  status: number
  payload?: { failure?: TaskFailure }
}

export interface ConnectivityDiagnosticRequest {
  id: string
  reason: string
}

const ERROR_CODES = new Set([
  'node_runtime_missing',
  'node_runner_missing',
  'node_proxy_failed',
  'node_tls_failed',
  'node_sentinel_timeout',
  'node_sentinel_sdk_failed',
  'node_sentinel_token_missing',
  'node_bridge_invalid_response',
  'node_sentinel_request_failed',
  'node_sentinel_token_failed',
  'node_sentinel_failed',
  'proxy_connection_failed',
  'tls_connection_failed',
  'remote_disconnected',
  'openai_auth_connectivity_outage',
])

const OPENAI_NODE_CODES = new Set([
  'oauth_session',
  'oauth_create_node',
  'node_sentinel',
  'openai_authorization',
  'oauth_callback',
  'oauth_token_exchange',
])

const IDENTITY_MARKERS = [
  'node/sentinel',
  'sentinelrunner',
  'sentinel token',
  'node bridge',
  'node_sentinel',
]

const NETWORK_MARKERS = [
  '代理连接失败',
  'dns 解析失败',
  'tls 连接',
  '连接超时',
  'connection timed out',
  'unable to connect to proxy',
]

function needsDiagnostic(failure: TaskFailure | null | undefined, error = '') {
  if (failure?.diagnostic_action === 'openai_connectivity') return true
  if (failure && ERROR_CODES.has(String(failure.error_code || '').toLowerCase())) return true
  const text = `${failure?.public_message || ''} ${failure?.technical_summary || ''} ${error}`.toLowerCase()
  if (IDENTITY_MARKERS.some(marker => text.includes(marker))) return true
  const nodeCode = String(failure?.node_code || '').toLowerCase()
  return OPENAI_NODE_CODES.has(nodeCode) && NETWORK_MARKERS.some(marker => text.includes(marker))
}

function failureReason(failure: TaskFailure | null | undefined, fallback = '') {
  return String(failure?.public_message || fallback || '检测到 OpenAI 授权链路异常').trim()
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
    const failure = apiError.payload?.failure
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
