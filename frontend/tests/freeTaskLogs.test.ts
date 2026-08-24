import assert from 'node:assert/strict'
import test from 'node:test'
import {
  FREE_LOG_WINDOW_SIZE,
  clampFreeLogWindowStart,
  containingFreeLogWindowStart,
  effectiveFreeLogLevel,
  filterFreeLogs,
  freeLogContextText,
  freeLogLevelLabel,
  freeLogNodeCode,
  freeLogNodeLabel,
  isFreeLogError,
  latestFreeLogWindowStart,
  normalizeFreeLogLevel,
  safeFreeLogPage,
  shouldShowFreeLogNodeCode,
} from '../src/utils/freeTaskLogs.ts'
import type { FreeLogEntry } from '../src/types/api.ts'

test('free task logs normalize levels and structured node fields', () => {
  const row: FreeLogEntry = { level: 'warning', node_code: 'free_email_otp', node_label: '邮箱验证码', message: '等待新邮件' }
  assert.equal(normalizeFreeLogLevel(row.level), 'warn')
  assert.equal(freeLogNodeCode(row), 'free_email_otp')
  assert.equal(freeLogNodeLabel(row), '邮箱验证码')
  assert.equal(shouldShowFreeLogNodeCode(row), true)
  assert.equal(freeLogLevelLabel(row.level), '警告')
  assert.equal(isFreeLogError(row), false)
  assert.equal(isFreeLogError({ level: 'info', error_code: 'otp_timeout' }), true)
  assert.equal(effectiveFreeLogLevel({ level: 'info', outcome: 'failed' }), 'error')
  assert.equal(freeLogNodeLabel({ node_code: 'free_email_otp' }), '')
  assert.equal(shouldShowFreeLogNodeCode({ node_code: 'free_email_otp' }), false)
  assert.equal(shouldShowFreeLogNodeCode({ node_code: 'same', node_label: 'same' }), false)
})

test('free task log filtering keeps the complete returned history', () => {
  const rows: FreeLogEntry[] = Array.from({ length: 240 }, (_, index) => ({
    level: index === 5 ? 'error' : index % 2 ? 'info' : 'success',
    stage: index < 120 ? 'free_oauth' : 'free_email_otp',
    message: `event-${index}`,
  }))
  assert.equal(filterFreeLogs(rows).length, 240)
  assert.equal(filterFreeLogs(rows, 'error').length, 1)
  assert.equal(filterFreeLogs(rows, 'all', 'free_email_otp').length, 120)
  assert.equal(filterFreeLogs(rows, 'success', 'free_email_otp').length, 60)
  assert.equal(filterFreeLogs([{ level: 'info', error_code: 'otp_timeout' }], 'error').length, 1)
})

test('free task log pages never render query strings or proxy credentials', () => {
  assert.equal(safeFreeLogPage('https://auth.openai.com/api/accounts/authorize?state=secret#x'), 'https://auth.openai.com/api/accounts/authorize')
  assert.equal(safeFreeLogPage('socks5://user:password@example.test:3000/path?q=1'), 'socks5://example.test:3000/path')
  assert.equal(safeFreeLogPage('/api/free/logs?task_id=secret'), '/api/free/logs')
  for (const proxy of [
    'example.test:3000:user:password',
    'user:password@example.test:3000',
    'example.test:3000@user:password',
  ]) {
    assert.equal(safeFreeLogPage(proxy), '[代理地址已隐藏]')
    assert.doesNotMatch(safeFreeLogPage(proxy), /user|password/)
  }
})

test('free task log windows bound rendered rows and retain direct positioning', () => {
  assert.equal(FREE_LOG_WINDOW_SIZE, 250)
  assert.equal(latestFreeLogWindowStart(5_000), 4_750)
  assert.equal(latestFreeLogWindowStart(5_020), 5_000)
  assert.equal(containingFreeLogWindowStart(5, 5_000), 0)
  assert.equal(containingFreeLogWindowStart(260, 5_000), 250)
  assert.equal(clampFreeLogWindowStart(300, 4_750), 250)

  const rows: FreeLogEntry[] = Array.from({ length: 5_000 }, (_, index) => ({ message: String(index) }))
  const filtered = filterFreeLogs(rows)
  const start = latestFreeLogWindowStart(filtered.length)
  assert.equal(filtered.slice(start, start + FREE_LOG_WINDOW_SIZE).length, 250)
})

test('free task log context renders page and session diagnostics', () => {
  const text = freeLogContextText({
    duration_ms: 810,
    page_type: 'email_otp',
    safe_page: 'https://auth.openai.com/email-verification?state=private',
    content_type: 'text/html; charset=utf-8',
    http_status: 403,
    session_rebuilds: 1,
    attempt: 2,
    outcome: 'failed',
    result: 'challenge_pending',
    retryable: true,
  })
  assert.match(text, /页面 email_otp/)
  assert.match(text, /auth\.openai\.com\/email-verification/)
  assert.match(text, /响应 text\/html; charset=utf-8/)
  assert.match(text, /会话重建 1 次/)
  assert.match(text, /结果 challenge_pending/)
  assert.match(text, /可重试 是/)
  assert.doesNotMatch(text, /private/)
})
