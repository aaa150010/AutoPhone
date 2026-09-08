/**
 * OpenAI connectivity failure classification.
 *
 * Pure predicates and reason formatting extracted verbatim from
 * useConnectivityDiagnostics; the stateful trigger stays in the composable.
 */
import type { TaskFailure } from '../types/api'

interface ApiFailureError extends Error {
  status: number
  payload?: { failure?: TaskFailure }
}

export type { ApiFailureError }

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

export function needsDiagnostic(failure: TaskFailure | null | undefined, error = '') {
  if (failure?.diagnostic_action === 'openai_connectivity') return true
  if (failure && ERROR_CODES.has(String(failure.error_code || '').toLowerCase())) return true
  const text = `${failure?.public_message || ''} ${failure?.technical_summary || ''} ${error}`.toLowerCase()
  if (IDENTITY_MARKERS.some(marker => text.includes(marker))) return true
  const nodeCode = String(failure?.node_code || '').toLowerCase()
  return OPENAI_NODE_CODES.has(nodeCode) && NETWORK_MARKERS.some(marker => text.includes(marker))
}

export function failureReason(failure: TaskFailure | null | undefined, fallback = '') {
  return String(failure?.public_message || fallback || '检测到 OpenAI 授权链路异常').trim()
}
