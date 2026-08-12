import assert from 'node:assert/strict'
import test from 'node:test'
import {
  pendingTaskRows,
  runningTaskRows,
  taskVerificationKey,
} from '../src/utils/taskResultViews.ts'
import type { RuntimeTask } from '../src/types/api.ts'

const manual = (id: string, deadline: number, generation = 1): RuntimeTask => ({
  task_id: id,
  status: 'running',
  manual_verification: {
    input_kind: 'email_otp', generation, opened_at: 1, deadline_at: deadline,
    capabilities: ['submit'], can_submit: true, remaining_seconds: deadline,
  },
})

test('pending tasks prioritize expiring verification and include every failure status', () => {
  const tasks: RuntimeTask[] = [
    { task_id: 'success', status: 'success' },
    { task_id: 'stopped', status: 'stopped' },
    { task_id: 'cancelled', status: 'cancelled' },
    { task_id: 'failure-old', status: 'failed', updated_at: 10 },
    { task_id: 'failure-new', status: 'retryable_email', updated_at: 20 },
    manual('later-code', 200),
    manual('urgent-code', 100),
  ]
  assert.deepEqual(
    pendingTaskRows(tasks, new Set()).map(task => task.task_id),
    ['urgent-code', 'later-code', 'failure-new', 'failure-old'],
  )
  assert.deepEqual(runningTaskRows(tasks, new Set()).map(task => task.task_id), [])
})

test('accepted verification leaves pending immediately and returns for a new generation', () => {
  const first = manual('task-1', 100, 1)
  const accepted = new Set([taskVerificationKey(first)])
  assert.deepEqual(pendingTaskRows([first], accepted), [])
  assert.deepEqual(runningTaskRows([first], accepted).map(task => task.task_id), ['task-1'])
  assert.deepEqual(pendingTaskRows([manual('task-1', 200, 2)], accepted).map(task => task.task_id), ['task-1'])
})
