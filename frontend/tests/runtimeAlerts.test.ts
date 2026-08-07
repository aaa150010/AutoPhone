import assert from 'node:assert/strict'
import test from 'node:test'
import { createRuntimeAlertTracker, runtimeAlertDuration } from '../src/composables/runtimeAlerts.ts'
import type { SmsRuntimeAlert } from '../src/types/api.ts'

function alert(overrides: Partial<SmsRuntimeAlert> = {}): SmsRuntimeAlert {
  return {
    id: 'sms-alert-1',
    kind: 'invalid',
    level: 'warning',
    message: 'SMS Key unavailable',
    ...overrides,
  }
}

test('balance alerts close after three seconds without changing other durations', () => {
  assert.equal(runtimeAlertDuration(alert({ kind: 'insufficient_balance', persistent: true })), 3000)
  assert.equal(runtimeAlertDuration(alert({ kind: 'sms_balance_insufficient' })), 3000)
  assert.equal(runtimeAlertDuration(alert({ kind: 'sms_pool_exhausted', persistent: true })), 0)
  assert.equal(runtimeAlertDuration(alert({ kind: 'sms_key_unavailable', persistent: false })), 5000)
})

test('runtime alert tracking is bounded and distinguishes reused ids with new payloads', () => {
  const tracker = createRuntimeAlertTracker(2)
  const first = alert({ created_at: 100 })

  assert.equal(tracker.accept(first), true)
  assert.equal(tracker.accept(first), false)
  assert.equal(tracker.accept(alert({ created_at: 101 })), true)
  assert.equal(tracker.accept(alert({ id: 'sms-alert-2', created_at: 101 })), true)
  assert.equal(tracker.size, 2)
  assert.equal(tracker.accept(first), true)
  assert.equal(tracker.size, 2)

  const restarted = alert({ generation: 'new-runtime', created_at: 100 })
  assert.equal(tracker.accept(restarted), true)
  assert.equal(tracker.accept(restarted), false)
  assert.equal(tracker.size, 2)
})
