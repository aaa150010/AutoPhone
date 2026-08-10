import assert from 'node:assert/strict'
import test from 'node:test'
import {
  buildConnectivityOutageNotice,
  buildConnectivityRecoveryMessage,
  buildOpenAIConnectivityView,
  createConnectivityNotificationTracker,
  preferNewestOpenAIConnectivityState,
} from '../src/utils/openAIConnectivity.ts'
import type { AppState, OpenAIAuthConnectivityState, RuntimeState } from '../src/types/api.ts'

function outage(overrides: Partial<OpenAIAuthConnectivityState> = {}): OpenAIAuthConnectivityState {
  return {
    status: 'outage',
    incident_id: 'incident-1',
    revision: 2,
    reason_code: 'openai_auth_proxy_connect_failed',
    reason_label: '代理连接失败',
    affected_origins: ['auth.openai.com', 'sentinel.openai.com'],
    probe_successful_rounds: 0,
    probe_required_rounds: 2,
    next_probe_at: 110,
    ...overrides,
  }
}

test('first loaded outage is persistent-notification eligible and repeated revisions are deduplicated', () => {
  const tracker = createConnectivityNotificationTracker()
  assert.deepEqual(tracker.observe(outage()).map(action => action.type), ['open-outage'])
  assert.deepEqual(tracker.observe(outage({ revision: 3, failure_count: 4 })), [])

  const notice = buildConnectivityOutageNotice({ connectivity: { openai_auth: outage() } })
  assert.equal(notice.duration, 0)
  assert.equal(notice.type, 'error')
})

test('recovery closes the outage and emits one success notification', () => {
  const tracker = createConnectivityNotificationTracker()
  tracker.observe(outage())
  const recovered = outage({ status: 'healthy', revision: 4, recovered_at: 120 })
  assert.deepEqual(tracker.observe(recovered).map(action => action.type), ['close-outage', 'show-recovery'])
  assert.deepEqual(tracker.observe(recovered), [])
})

test('initial healthy state stays silent while a later incident is observable', () => {
  const tracker = createConnectivityNotificationTracker()
  assert.deepEqual(tracker.observe({ status: 'healthy', revision: 1 }), [])
  assert.deepEqual(tracker.observe(outage({ incident_id: 'incident-2' })).map(action => action.type), ['open-outage'])
})

test('unknown guard state closes and clears an active outage without reporting recovery', () => {
  const tracker = createConnectivityNotificationTracker()
  tracker.observe(outage())

  assert.deepEqual(
    tracker.observe({ status: 'unknown', enabled: false, revision: 3 }).map(action => action.type),
    ['close-outage'],
  )
  assert.deepEqual(tracker.observe({ status: 'unknown', enabled: false, revision: 4 }), [])
  assert.deepEqual(tracker.observe({ status: 'healthy', enabled: true, revision: 5 }), [])
  assert.deepEqual(tracker.observe(outage({ revision: 6 })).map(action => action.type), ['open-outage'])
})

test('outage presentation shows safe dual-origin probe progress', () => {
  const runtime: RuntimeState = {
    connectivity: { openai_auth: outage() },
    concurrency: { protocol: { baseline: 8, healthy_ceiling: 12, paused: true } },
  }
  const view = buildOpenAIConnectivityView(runtime, 100)
  assert.equal(view.tone, 'danger')
  assert.match(view.banner?.detail || '', /受影响：Auth、Sentinel/)
  assert.match(view.banner?.detail || '', /探测 0\/2/)
  assert.match(view.banner?.detail || '', /下次探测约 10 秒/)
})

test('HTTP 429 is rendered as a cooldown without classifying connectivity as an outage', () => {
  const runtime: RuntimeState = {
    connectivity: { openai_auth: { status: 'healthy' } },
    concurrency: {
      protocol: {
        baseline: 8,
        healthy_ceiling: 12,
        paused: true,
        pause_reason: 'http_429_rate_limit',
        pause_remaining_seconds: 30,
        sticky_baseline: true,
      },
    },
  }
  const view = buildOpenAIConnectivityView(runtime)
  assert.equal(view.status, 'healthy')
  assert.equal(view.tone, 'warning')
  assert.match(view.banner?.title || '', /限流/)
  assert.match(view.banner?.detail || '', /30 秒后按基线并发 8继续/)
})

test('HTTP 429 remains visible while the connectivity guard is disabled', () => {
  const runtime: RuntimeState = {
    connectivity: { openai_auth: { status: 'unknown', enabled: false } },
    concurrency: {
      protocol: {
        baseline: 8,
        paused: true,
        pause_reason: 'http_429',
        pause_remaining_seconds: 12,
        sticky_baseline: true,
      },
    },
  }

  const view = buildOpenAIConnectivityView(runtime)
  assert.equal(view.sidebarLabel, 'OpenAI 限流冷却')
  assert.match(view.banner?.detail || '', /12 秒后/)
})

test('a confirmed outage takes precedence over an overlapping HTTP 429 cooldown', () => {
  const runtime: RuntimeState = {
    connectivity: { openai_auth: outage({ enabled: true }) },
    concurrency: {
      protocol: {
        baseline: 8,
        paused: true,
        pause_reason: 'http_429',
        pause_remaining_seconds: 12,
      },
    },
  }

  const view = buildOpenAIConnectivityView(runtime)
  assert.equal(view.sidebarLabel, 'OpenAI 链路中断')
  assert.equal(view.banner?.type, 'error')
})

test('recovery notification does not claim requests resumed during HTTP 429 cooldown', () => {
  const message = buildConnectivityRecoveryMessage({
    connectivity: { openai_auth: { status: 'healthy' } },
    concurrency: {
      protocol: {
        baseline: 8,
        paused: true,
        pause_reason: 'http_429',
        pause_remaining_seconds: 12,
      },
    },
  })

  assert.match(message, /限流冷却仍在继续/)
  assert.match(message, /12 秒/)
  assert.doesNotMatch(message, /新的协议请求已.*恢复/)
})

test('sticky protocol capacity is presented as fixed at baseline', () => {
  const view = buildOpenAIConnectivityView({
    connectivity: { openai_auth: { status: 'healthy', enabled: true } },
    concurrency: {
      protocol: {
        baseline: 8,
        limit: 8,
        healthy_ceiling: 12,
        sticky_baseline: true,
      },
    },
  })

  assert.equal(view.sidebarDetail, '基线 8 · 本批固定')
})

test('older connectivity revisions cannot overwrite or reopen a newer state', () => {
  const tracker = createConnectivityNotificationTracker()
  const older = outage({ revision: 2 })
  const disabled = outage({ status: 'unknown', enabled: false, revision: 3 })

  assert.deepEqual(tracker.observe(older).map(action => action.type), ['open-outage'])
  assert.deepEqual(tracker.observe(disabled).map(action => action.type), ['close-outage'])
  assert.deepEqual(tracker.observe(older), [])

  const current: AppState = { runtime: { connectivity: { openai_auth: disabled } } }
  const incoming: AppState = { runtime: { connectivity: { openai_auth: older }, running: true } }
  const merged = preferNewestOpenAIConnectivityState(current, incoming)
  assert.equal(merged.runtime?.running, true)
  assert.equal(merged.runtime?.connectivity?.openai_auth?.revision, 3)
})

test('a newer service epoch accepts a reset revision and rejects late old-process state', () => {
  const tracker = createConnectivityNotificationTracker()
  const oldProcess = outage({ runtime_epoch: 100, revision: 40 })
  const restarted = outage({ runtime_epoch: 200, revision: 1, incident_id: 'incident-2' })

  assert.deepEqual(tracker.observe(oldProcess).map(action => action.type), ['open-outage'])
  assert.deepEqual(tracker.observe(restarted).map(action => action.type), ['close-outage', 'open-outage'])
  assert.deepEqual(tracker.observe(oldProcess), [])

  const current: AppState = { runtime: { connectivity: { openai_auth: oldProcess } } }
  const accepted = preferNewestOpenAIConnectivityState(
    current,
    { runtime: { connectivity: { openai_auth: restarted } } },
  )
  assert.equal(accepted.runtime?.connectivity?.openai_auth?.runtime_epoch, 200)
  const retained = preferNewestOpenAIConnectivityState(
    accepted,
    { runtime: { connectivity: { openai_auth: oldProcess } } },
  )
  assert.equal(retained.runtime?.connectivity?.openai_auth?.runtime_epoch, 200)
})
