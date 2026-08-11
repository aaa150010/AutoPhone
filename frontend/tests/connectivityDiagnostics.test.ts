import assert from 'node:assert/strict'
import test from 'node:test'
import { ApiError } from '../src/api/client.ts'
import { createConnectivityDiagnosticTrigger } from '../src/composables/useConnectivityDiagnostics.ts'
import type { AppState, TaskFailure } from '../src/types/api.ts'

function failure(overrides: Partial<TaskFailure> = {}): TaskFailure {
  return {
    node_code: 'oauth_create_node',
    node_label: '初始化 Node/Sentinel',
    error_code: 'node_proxy_failed',
    public_message: '初始化 Node/Sentinel 失败：代理连接失败',
    technical_summary: '无法连接当前显式代理',
    retryable: true,
    diagnostic_action: 'openai_connectivity',
    ...overrides,
  }
}

test('one outage incident opens diagnostics once while a new incident opens again', () => {
  const trigger = createConnectivityDiagnosticTrigger()
  const state = (incidentId: string): AppState => ({
    runtime: {
      connectivity: {
        openai_auth: {
          status: 'outage',
          incident_id: incidentId,
          reason_label: '代理连接失败',
        },
      },
    },
  })

  trigger.observeState(state('incident-1'))
  const first = trigger.request.value
  trigger.clear()
  trigger.observeState(state('incident-1'))
  assert.equal(trigger.request.value, null)
  trigger.observeState(state('incident-2'))
  assert.notEqual(trigger.request.value?.id, first?.id)
})

test('task failures are deduplicated per batch and a new batch opens again', () => {
  const trigger = createConnectivityDiagnosticTrigger()
  const state = (batchId: string): AppState => ({
    runtime: {
      summary: { batch_id: batchId },
      tasks: [{ task_id: 'task-1', batch_id: batchId, failure: failure() }],
    },
  })

  trigger.observeState(state('batch-1'))
  const first = trigger.request.value
  trigger.clear()
  trigger.observeState(state('batch-1'))
  assert.equal(trigger.request.value, null)
  trigger.observeState(state('batch-2'))
  assert.notEqual(trigger.request.value?.id, first?.id)
})

test('a seen historical task cannot block a new current-batch failure', () => {
  const trigger = createConnectivityDiagnosticTrigger()
  trigger.observeState({
    runtime: {
      summary: { batch_id: 'batch-old' },
      tasks: [{ task_id: 'old', batch_id: 'batch-old', failure: failure() }],
    },
  })
  trigger.clear()

  trigger.observeState({
    runtime: {
      summary: { batch_id: 'batch-new' },
      tasks: [
        { task_id: 'old', batch_id: 'batch-old', failure: failure() },
        { task_id: 'new', batch_id: 'batch-new', failure: failure({ public_message: '新批次代理连接失败' }) },
      ],
    },
  })

  assert.match(trigger.request.value?.reason || '', /新批次/)
})

test('historical failures stay silent when the current batch is healthy', () => {
  const trigger = createConnectivityDiagnosticTrigger()
  trigger.observeState({
    runtime: {
      summary: { batch_id: 'batch-current' },
      tasks: [{ task_id: 'old', batch_id: 'batch-old', failure: failure() }],
    },
  })

  assert.equal(trigger.request.value, null)
})

test('the same startup API failure opens only once', () => {
  const trigger = createConnectivityDiagnosticTrigger()
  const error = new ApiError('启动失败', 503, { failure: failure() })

  trigger.observeError(error)
  assert.ok(trigger.request.value)
  trigger.clear()
  trigger.observeError(error)
  assert.equal(trigger.request.value, null)
})

test('manual diagnostics always opens and unrelated provider DNS errors stay silent', () => {
  const trigger = createConnectivityDiagnosticTrigger()
  const unrelated = failure({
    node_code: 'sms_wait',
    node_label: '等待短信验证码',
    error_code: 'sms_provider_network_error',
    public_message: '等待短信验证码失败：DNS 解析失败',
    diagnostic_action: undefined,
  })

  trigger.observeState({ runtime: { tasks: [{ task_id: 'task-1', failure: unrelated }] } })
  assert.equal(trigger.request.value, null)
  trigger.open()
  const first = trigger.request.value
  trigger.clear()
  trigger.open()
  assert.notEqual(trigger.request.value?.id, first?.id)
})
