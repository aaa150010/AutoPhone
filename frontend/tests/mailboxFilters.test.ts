import assert from 'node:assert/strict'
import test from 'node:test'
import {
  isSub2TestFailure,
  isLatestMailboxBatchFailure,
  isMailboxNetworkDisconnected,
  latestMailboxBatchId,
  mailboxBatchCandidates,
  matchesMailboxView,
  needsSub2Rerun,
} from '../src/utils/mailboxFilters.ts'
import {
  canMoveMailboxRowsToDraft,
  canSetMailboxRowsUnavailable,
  managedMailboxCount,
  mergeMailboxOperationUpdates,
  mergeMailboxQuotaResults,
} from '../src/utils/mailboxRows.ts'
import { createMailboxRefreshGuard } from '../src/utils/mailboxRefreshGuard.ts'
import {
  claimMailboxOperationNotification,
  claimMailboxOperationRetryPrompt,
  retryableOpenAITestBindings,
  shouldApplyMailboxOperationUpdate,
} from '../src/utils/mailboxOperationState.ts'
import type { MailboxBatchOperation } from '../src/types/api.ts'
import type { MailboxRow } from '../src/types/api.ts'

function row(overrides: Partial<MailboxRow>): MailboxRow {
  return {
    row_id: 'row-a',
    line_no: 1,
    source_row: 'masked',
    email: 'masked@example.test',
    status: 'consumed',
    ...overrides,
  }
}

test('network filter accepts only direct OpenAI disconnection kinds', () => {
  for (const kind of ['network_error', 'remote_disconnected', 'timeout']) {
    assert.equal(isMailboxNetworkDisconnected(row({ sub2_status: { kind } })), true)
  }
  for (const [kind, status_code] of [
    ['unauthorized', 401],
    ['not_found', 404],
    ['rate_limited', 429],
    ['protocol_error', 502],
  ] as const) {
    assert.equal(isMailboxNetworkDisconnected(row({ sub2_status: { kind, status_code } })), false)
  }
})

test('network filter accepts explicit quota connection failures and excludes HTTP/protocol errors', () => {
  for (const quota_error of [
    '查询 OpenAI 额度失败：网络请求失败，请检查当前显式代理',
    '查询 OpenAI 额度失败：连接中断',
    'openai_quota_probe_network_error: request timed out',
  ]) {
    assert.equal(isMailboxNetworkDisconnected(row({ quota_status: 'error', quota_error })), true)
  }
  for (const quota_error of [
    'OpenAI OAuth Token 已失效 HTTP 401',
    'HTTP 404 账号不存在',
    'OpenAI 额度接口限流 HTTP 429',
    '协议错误：返回内容无法解析',
  ]) {
    assert.equal(isMailboxNetworkDisconnected(row({ quota_status: 'error', quota_error })), false)
  }
})

test('OpenAI batch tests every mailbox while quota keeps successful accounts only', () => {
  const rows = [
    row({ row_id: 'available', status: 'available', task_id: '' }),
    row({ row_id: 'consumed', status: 'consumed', task_id: 'task-1' }),
    row({ row_id: 'failed', status: 'failed', task_id: 'task-2' }),
    row({ row_id: 'draft', status: 'draft', task_id: 'task-3' }),
  ]

  assert.deepEqual(
    mailboxBatchCandidates(rows, 'openai_test').map(item => item.row_id),
    ['available', 'consumed', 'failed', 'draft'],
  )
  assert.deepEqual(
    mailboxBatchCandidates(rows, 'quota').map(item => item.row_id),
    ['consumed'],
  )
})

test('quota results merge by stable row id instead of current display order', () => {
  const first = row({ row_id: 'row-a', line_no: 1 })
  const second = row({ row_id: 'row-b', line_no: 2 })
  const merged = mergeMailboxQuotaResults([second, first], [{
    row_id: 'row-a',
    line_no: 1,
    status: 'error',
    error: 'network error',
    queried_at: 123,
  }])

  assert.equal(merged[0], second)
  assert.equal(merged[1].row_id, 'row-a')
  assert.equal(merged[1].quota_status, 'error')
  assert.equal(merged[1].quota_queried_at, 123)
})

test('background row updates merge immediately by row id and source line', () => {
  const original = row({
    row_id: 'row-a',
    line_no: 1,
    quota_status: 'ok',
    quota_queried_at: 100,
    quota_5h: { remaining_percent: 10 },
    sub2_status: { kind: 'unauthorized', status_code: 401, tested_at: 100 },
  })
  const sameIdOtherLine = row({ row_id: 'row-a', line_no: 2 })
  const merged = mergeMailboxOperationUpdates([original, sameIdOtherLine], [{
    row_id: 'row-a',
    line_no: 1,
    quota_status: 'error',
    quota_error: 'network error',
    quota_queried_at: 101,
    quota_5h: null,
    quota_7d: null,
    sub2_status: { kind: 'healthy', status_code: 200, tested_at: 101 },
  }])

  assert.equal(merged[0].quota_status, 'error')
  assert.equal(merged[0].quota_5h, null)
  assert.equal(merged[0].sub2_status?.status_code, 200)
  assert.equal(merged[1], sameIdOtherLine)
})

test('older background updates cannot restore stale quota or OpenAI status', () => {
  const current = row({
    quota_status: 'ok',
    quota_queried_at: 200,
    quota_5h: { remaining_percent: 90 },
    sub2_status: { kind: 'healthy', status_code: 200, tested_at: 200 },
  })
  const [merged] = mergeMailboxOperationUpdates([current], [{
    row_id: 'row-a',
    line_no: 1,
    quota_status: 'error',
    quota_queried_at: 100,
    quota_5h: null,
    quota_7d: null,
    sub2_status: { kind: 'unauthorized', status_code: 401, tested_at: 100 },
  }])

  assert.equal(merged, current)
})

test('setting mailboxes unavailable requires a non-running selection', () => {
  assert.equal(canSetMailboxRowsUnavailable([]), false)
  assert.equal(canSetMailboxRowsUnavailable([
    row({ row_id: 'row-a', status: 'available' }),
    row({ row_id: 'row-b', status: 'consumed' }),
  ]), true)
  assert.equal(canSetMailboxRowsUnavailable([
    row({ row_id: 'row-a', status: 'available' }),
    row({ row_id: 'row-b', status: 'running' }),
  ]), false)
})

test('401 and 404 SUB2 states require rerun while rate limits do not', () => {
  assert.equal(needsSub2Rerun({ status_code: 401 }), true)
  assert.equal(needsSub2Rerun({ status_code: 404 }), true)
  assert.equal(needsSub2Rerun({ kind: 'not_found', needs_rerun: true }), true)
  assert.equal(needsSub2Rerun({ status_code: 429, needs_rerun: true }), false)
  assert.equal(isSub2TestFailure({ status_code: 404 }), true)
  assert.equal(isSub2TestFailure({ status_code: 401 }), false)
})

test('mailbox view filters exclude drafts and preserve combined status and search filters', () => {
  const filters = {
    status: 'available',
    sub2: 'all',
    quota: 'all',
    search: 'alpha',
    latestBatchId: '',
  }
  assert.equal(matchesMailboxView(row({ email: 'alpha@example.test', status: 'available' }), filters), true)
  assert.equal(matchesMailboxView(row({ email: 'beta@example.test', status: 'available' }), filters), false)
  assert.equal(matchesMailboxView(row({ email: 'alpha@example.test', status: 'draft' }), filters), false)
})

test('drafting mailboxes requires every selected row to be currently available', () => {
  assert.equal(canMoveMailboxRowsToDraft([]), false)
  assert.equal(canMoveMailboxRowsToDraft([
    row({ row_id: 'row-a', status: 'available' }),
    row({ row_id: 'row-b', status: 'available' }),
  ]), true)
  for (const status of ['running', 'consumed', 'failed', 'draft']) {
    assert.equal(canMoveMailboxRowsToDraft([
      row({ row_id: 'row-a', status: 'available' }),
      row({ row_id: 'row-b', status }),
    ]), false)
  }
})

test('managed mailbox metric excludes rows shown in the draft dialog', () => {
  assert.equal(managedMailboxCount({ total: 5, draft: 2 }), 3)
  assert.equal(managedMailboxCount({ total: 3 }), 3)
  assert.equal(managedMailboxCount({ total: 1, draft: 4 }), 0)
})

test('mailbox refresh guard rejects requests started before a mutation', () => {
  const guard = createMailboxRefreshGuard()
  const beforeMutation = guard.begin()
  guard.invalidate()
  assert.equal(guard.accepts(beforeMutation), false)

  const current = guard.begin()
  assert.equal(guard.accepts(current), true)
  const newer = guard.begin()
  assert.equal(guard.accepts(current), false)
  assert.equal(guard.accepts(newer), true)
})

test('a terminal operation is claimed only once across page refreshes', () => {
  const values = new Map<string, string>()
  const storage = {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { values.set(key, value) },
  }
  const operation: MailboxBatchOperation = {
    job_id: 'job-a',
    kind: 'quota',
    status: 'completed',
    total: 10,
    completed: 10,
    succeeded: 10,
    failed: 0,
    skipped: 0,
    tested: 0,
    rate_limited: 0,
    not_ready: 0,
    created_at: 1,
    updated_at: 2,
    row_updates: [],
  }

  assert.equal(claimMailboxOperationNotification(operation, storage), true)
  assert.equal(claimMailboxOperationNotification(operation, storage), false)
  assert.equal(claimMailboxOperationRetryPrompt(operation, storage), true)
  assert.equal(claimMailboxOperationRetryPrompt(operation, storage), false)
})

test('network-failed OpenAI rows can be retried without retrying account failures', () => {
  const operation: MailboxBatchOperation = {
    job_id: 'job-network-retry',
    kind: 'openai_test',
    status: 'completed',
    total: 6,
    completed: 6,
    succeeded: 1,
    failed: 5,
    skipped: 0,
    tested: 6,
    rate_limited: 1,
    not_ready: 0,
    created_at: 1,
    updated_at: 2,
    row_updates: [
      { row_id: 'row-network', line_no: 1, sub2_status: { kind: 'network_error' } },
      { row_id: 'row-disconnected', line_no: 2, sub2_status: { kind: 'remote_disconnected' } },
      { row_id: 'row-upstream', line_no: 3, sub2_status: { kind: 'http_error', status_code: 503 } },
      { row_id: 'row-401', line_no: 4, sub2_status: { kind: 'unauthorized', status_code: 401 } },
      { row_id: 'row-429', line_no: 5, sub2_status: { kind: 'rate_limited', status_code: 429 } },
      { row_id: 'row-healthy', line_no: 6, sub2_status: { kind: 'healthy', status_code: 200 } },
    ],
  }

  assert.deepEqual(retryableOpenAITestBindings(operation), [
    { row_id: 'row-network', line_no: 1 },
    { row_id: 'row-disconnected', line_no: 2 },
    { row_id: 'row-upstream', line_no: 3 },
  ])
  assert.deepEqual(
    retryableOpenAITestBindings({ ...operation, status: 'running' }),
    [],
  )
})

test('older mailbox operation polls cannot roll progress or terminal state backward', () => {
  const current: MailboxBatchOperation = {
    job_id: 'job-current',
    kind: 'quota',
    status: 'completed',
    total: 3,
    completed: 3,
    succeeded: 3,
    failed: 0,
    skipped: 0,
    tested: 0,
    rate_limited: 0,
    not_ready: 0,
    created_at: 100,
    updated_at: 130,
    finished_at: 130,
    row_updates: [],
  }
  const stale = {
    ...current,
    status: 'running' as const,
    completed: 1,
    succeeded: 0,
    updated_at: 110,
    finished_at: null,
  }

  assert.equal(shouldApplyMailboxOperationUpdate(current, stale), false)
  assert.equal(shouldApplyMailboxOperationUpdate(current, null), true)
})

test('a missing or older job cannot erase a newer running mailbox operation', () => {
  const current: MailboxBatchOperation = {
    job_id: 'job-new',
    kind: 'openai_test',
    status: 'running',
    total: 4,
    completed: 2,
    succeeded: 1,
    failed: 1,
    skipped: 0,
    tested: 2,
    rate_limited: 0,
    not_ready: 0,
    created_at: 200,
    updated_at: 220,
    row_updates: [],
  }
  const oldJob = { ...current, job_id: 'job-old', created_at: 100, updated_at: 300 }
  const newerProgress = { ...current, completed: 3, tested: 3, updated_at: 230 }

  assert.equal(shouldApplyMailboxOperationUpdate(current, null), false)
  assert.equal(shouldApplyMailboxOperationUpdate(current, oldJob), false)
  assert.equal(shouldApplyMailboxOperationUpdate(current, newerProgress), true)
})

test('an authoritative start accepts a same-time job without letting the old job return', () => {
  const previous: MailboxBatchOperation = {
    job_id: 'job-previous',
    kind: 'quota',
    status: 'completed',
    total: 2,
    completed: 2,
    succeeded: 2,
    failed: 0,
    skipped: 0,
    tested: 0,
    rate_limited: 0,
    not_ready: 0,
    created_at: 200,
    updated_at: 220,
    finished_at: 220,
    row_updates: [],
  }
  const started: MailboxBatchOperation = {
    ...previous,
    job_id: 'job-started',
    kind: 'openai_test',
    status: 'running',
    completed: 0,
    succeeded: 0,
    tested: 0,
    updated_at: 200,
    finished_at: null,
  }

  assert.equal(shouldApplyMailboxOperationUpdate(previous, started), false)
  assert.equal(shouldApplyMailboxOperationUpdate(previous, started, started.job_id), true)
  assert.equal(shouldApplyMailboxOperationUpdate(started, previous), false)
})

test('an unknown same-time terminal job cannot replace current state', () => {
  const previous: MailboxBatchOperation = {
    job_id: 'job-previous',
    kind: 'quota',
    status: 'completed',
    total: 1,
    completed: 1,
    succeeded: 1,
    failed: 0,
    skipped: 0,
    tested: 0,
    rate_limited: 0,
    not_ready: 0,
    created_at: 200,
    updated_at: 210,
    finished_at: 210,
    row_updates: [],
  }
  const next = {
    ...previous,
    job_id: 'job-next',
    kind: 'openai_test' as const,
    updated_at: 220,
    finished_at: 220,
  }

  assert.equal(shouldApplyMailboxOperationUpdate(previous, next), false)
  assert.equal(shouldApplyMailboxOperationUpdate(next, previous), false)
})

test('latest batch comes from all rows and is independent of display order', () => {
  const rows = [
    row({ row_id: 'new-b', batch_id: 'batch-new', batch_started_at: 300 }),
    row({ row_id: 'old', batch_id: 'batch-old', batch_started_at: 200 }),
    row({ row_id: 'new-a', batch_id: 'batch-new', batch_started_at: 300 }),
    row({ row_id: 'none', batch_id: '', batch_started_at: 999 }),
    row({ row_id: 'legacy', batch_id: 'batch-legacy' }),
  ]
  assert.equal(latestMailboxBatchId(rows), 'batch-new')
  assert.equal(latestMailboxBatchId([...rows].reverse()), 'batch-new')
})

test('latest batch failures include explicit terminal failures and failure identity only', () => {
  for (const task_status of ['failed', 'email_damaged', 'account_banned']) {
    assert.equal(isLatestMailboxBatchFailure(row({ task_status })), true)
  }
  assert.equal(isLatestMailboxBatchFailure(row({
    task_status: '',
    failure: {
      node_code: 'openai_authorization',
      node_label: 'OpenAI 授权',
      error_code: 'authorization_failed',
      public_message: '授权失败',
      retryable: false,
    },
  })), true)
  for (const task_status of [
    'queued',
    'running',
    'success',
    'stopped',
    'stopped_before_start',
    'cancelled',
    'canceled',
  ]) {
    assert.equal(isLatestMailboxBatchFailure(row({
      task_status,
      status: 'failed',
      failure: {
        node_code: 'stopped',
        node_label: '停止',
        error_code: 'stopped',
        public_message: '已停止',
        retryable: false,
      },
    })), false)
  }
})
