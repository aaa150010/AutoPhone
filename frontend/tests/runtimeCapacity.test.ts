import assert from 'node:assert/strict'
import test from 'node:test'
import { buildTaskCapacityView } from '../src/utils/runtimeCapacity.ts'

test('task capacity separates running, current, baseline, and health ceiling', () => {
  const view = buildTaskCapacityView({
    active: 1,
    base: 8,
    limit: 1,
    restore_ceiling: 10,
    ceiling: 12,
    waiting: 5,
    pause_remaining_seconds: 15,
    last_reason: 'resource_fd_exhausted',
  })

  assert.equal(view.active, 1)
  assert.equal(view.currentLimit, 1)
  assert.equal(view.base, 8)
  assert.equal(view.healthCeiling, 10)
  assert.equal(view.waiting, 5)
  assert.equal(view.pauseRemaining, 15)
  assert.equal(view.degraded, true)
  assert.equal(view.reasonLabel, '文件描述符耗尽')
  assert.match(view.tooltip, /基线 8；当前限制 1；健康上限 10/)
  assert.match(view.tooltip, /暂停准入 15 秒/)
})

test('healthy capacity falls back to the absolute ceiling without a warning', () => {
  const view = buildTaskCapacityView({
    active: 7,
    base: 8,
    limit: 9,
    ceiling: 10,
    last_reason: 'success_streak_with_backlog',
  })

  assert.equal(view.healthCeiling, 10)
  assert.equal(view.degraded, false)
  assert.equal(view.reasonLabel, '')
})

test('unknown protection reasons remain credential-free and Chinese', () => {
  const view = buildTaskCapacityView({
    base: 8,
    limit: 4,
    last_reason: 'unexpected_internal_guard_detail',
  })

  assert.equal(view.degraded, true)
  assert.equal(view.reasonLabel, '运行保护已触发')
  assert.doesNotMatch(view.tooltip, /unexpected_internal_guard_detail/)
})

test('a pause at baseline is described as paused rather than degraded capacity', () => {
  const view = buildTaskCapacityView({
    base: 8,
    limit: 8,
    pause_remaining_seconds: 6,
    last_reason: 'configured_baseline',
  })

  assert.equal(view.degraded, true)
  assert.equal(view.reasonLabel, '新任务准入暂时停止')
})
