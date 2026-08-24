import assert from 'node:assert/strict'
import test from 'node:test'
import { freeFailureCause, freeFailureDetails, freeFailureNodeIdentity, selectCurrentFreeFailure } from '../src/utils/freeFailure.ts'

test('free failure tooltip includes safe page and HTTP session context', () => {
  const details = freeFailureDetails({
    node_code: 'free_email_otp_wait',
    node_label: '等待 Free 邮箱验证码',
    error_code: 'otp_timeout',
    provider_code: 'email_not_found',
    public_message: '验证码等待超时',
    technical_summary: '三轮未收到新邮件',
    retryable: true,
    http_status: 504,
    page_type: 'email_otp',
    safe_page: 'https://auth.openai.com/email-verification?state=private',
    content_type: 'application/json',
    session_rebuilds: 1,
    action_hint: '检查取件服务',
  }, { includeNode: true })

  assert.deepEqual(details, [
    '节点：等待 Free 邮箱验证码 · free_email_otp_wait',
    'HTTP 状态：504',
    '服务端代码：email_not_found',
    '错误代码：otp_timeout',
    '页面类型：email_otp',
    '安全页面：https://auth.openai.com/email-verification',
    '响应类型：application/json',
    '会话重建：1 次',
    '技术摘要：三轮未收到新邮件',
    '处理建议：检查取件服务',
  ])
})

test('free failure presentation stays blank without a structured failure', () => {
  assert.equal(freeFailureCause(null), '-')
  assert.deepEqual(freeFailureNodeIdentity(null), { label: '', code: '', showCode: false })
  assert.deepEqual(freeFailureDetails(null, { includeNode: true }), [])
})

test('free failure presentation removes duplicated node identity and message prefix', () => {
  const failure = {
    node_code: 'free_email_otp_wait',
    node_label: 'free_email_otp_wait',
    error_code: 'otp_timeout',
    public_message: 'free_email_otp_wait失败：三轮未收到新邮件',
    retryable: true,
  }
  assert.deepEqual(freeFailureNodeIdentity(failure), {
    label: 'free_email_otp_wait',
    code: 'free_email_otp_wait',
    showCode: false,
  })
  assert.equal(freeFailureCause(failure), '三轮未收到新邮件')
  assert.equal(freeFailureDetails(failure, { includeNode: true })[0], '节点：free_email_otp_wait')

  assert.equal(freeFailureCause({
    ...failure,
    node_label: '等待 Free 邮箱验证码',
    public_message: '等待 Free 邮箱验证码 [等待 Free 邮箱验证码/free_email_otp_wait]：三轮未收到新邮件',
  }), '三轮未收到新邮件')
})

test('current mailbox failure prefers a terminal live-check failure but ignores stale live failures', () => {
  const registrationFailure = {
    node_code: 'free_token', node_label: 'Token', error_code: 'missing',
    public_message: 'Token 缺失', retryable: false,
  }
  const liveFailure = {
    node_code: 'free_live_check', node_label: '账号测活', error_code: 'expired',
    public_message: 'Token 已失效', retryable: true,
  }
  assert.equal(selectCurrentFreeFailure(registrationFailure, liveFailure, 'token_expired'), liveFailure)
  assert.equal(selectCurrentFreeFailure(registrationFailure, liveFailure, 'live'), registrationFailure)
  assert.equal(selectCurrentFreeFailure(null, liveFailure, 'running'), null)
  assert.equal(selectCurrentFreeFailure(registrationFailure, liveFailure, ''), registrationFailure)
  assert.equal(selectCurrentFreeFailure(registrationFailure, liveFailure, 'unknown_future_state'), registrationFailure)
})
