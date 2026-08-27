import assert from 'node:assert/strict'
import test from 'node:test'
import {
  ACCOUNT_BANNED_DISPLAY_MESSAGE,
  diagnosticEventNodeLabel,
  diagnosticIncidentNodeLabel,
  diagnosticNodeLabel,
  freeFailureCause,
  freeFailureDetails,
  freeFailureNodeIdentity,
  isAccountBannedDiagnostic,
  isAccountBannedFailure,
  isCurrentAccountBanned,
  isRetryResolved,
  isSuccessfulDiagnosticOutcome,
  selectCurrentFreeFailure,
} from '../src/utils/freeFailure.ts'

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

test('account-banned failures use direct user-facing copy without changing other failures', () => {
  const banned = {
    node_code: 'account_banned',
    node_label: '检查 OpenAI 账号状态',
    error_code: 'password_verify_failed',
    provider_code: 'account_banned',
    public_message: 'OpenAI 账号已被封禁，无法继续接码',
    retryable: false,
  }
  assert.equal(isAccountBannedFailure(banned), true)
  assert.equal(freeFailureCause(banned), ACCOUNT_BANNED_DISPLAY_MESSAGE)
  assert.equal(isAccountBannedFailure({
    ...banned,
    node_code: 'oauth_authorize_node',
    provider_code: 'password_verify_failed',
  }), false)
  assert.equal(freeFailureCause({
    ...banned,
    node_code: 'oauth_authorize_node',
    provider_code: 'password_verify_failed',
    public_message: '授权请求超时',
  }), '授权请求超时')

  assert.equal(isCurrentAccountBanned('failed', banned), true)
  assert.equal(isCurrentAccountBanned('success', banned), false)
  assert.equal(isCurrentAccountBanned('failed', banned, true), false)
  assert.equal(isCurrentAccountBanned('account_banned', banned, 'true'), false)
})

test('historical account-banned failures cannot replace a later successful result', () => {
  const banned = {
    node_code: 'account_banned',
    node_label: '检查 OpenAI 账号状态',
    error_code: 'account_banned',
    public_message: 'OpenAI账号已被封禁',
    retryable: false,
  }
  assert.equal(isCurrentAccountBanned('failed', banned), true)
  assert.equal(isCurrentAccountBanned('account_banned', null), true)
  assert.equal(isCurrentAccountBanned('success', banned), false)
  assert.equal(isCurrentAccountBanned('partial_success', banned), false)
})

test('retry resolution marker accepts persisted boolean and string forms', () => {
  assert.equal(isRetryResolved(true), true)
  assert.equal(isRetryResolved('true'), true)
  assert.equal(isRetryResolved(false), false)
  assert.equal(isRetryResolved('false'), false)
})

test('diagnostic account-banned labels hide legacy status text but preserve stable code separately', () => {
  assert.equal(isAccountBannedDiagnostic({
    first_node_code: 'account_banned',
    first_node_label: '检查 OpenAI 账号状态',
    first_error_code: 'password_verify_failed',
  }), true)
  assert.equal(diagnosticNodeLabel({
    first_node_code: 'account_banned',
    first_node_label: '检查 OpenAI 账号状态',
  }), ACCOUNT_BANNED_DISPLAY_MESSAGE)
  assert.equal(diagnosticNodeLabel({
    node_code: 'oauth_callback',
    node_label: 'OAuth 回调',
    failure: { provider_code: 'account_banned' },
  }), ACCOUNT_BANNED_DISPLAY_MESSAGE)
  assert.equal(diagnosticNodeLabel({
    node_code: 'free_email_otp_wait',
    node_label: '等待 Free 邮箱验证码',
  }), '等待 Free 邮箱验证码')
  assert.equal(diagnosticNodeLabel(null), '未命名节点')
  assert.equal(diagnosticNodeLabel(null, '-'), '-')
})

test('successful retries preserve historical incident and event labels instead of a current ban label', () => {
  const historicalIncident = {
    status: 'success',
    outcome: 'success',
    first_node_code: 'account_banned',
    first_node_label: '检查 OpenAI 账号状态',
    first_error_code: 'account_banned',
  }
  assert.equal(isSuccessfulDiagnosticOutcome(historicalIncident.status), true)
  assert.equal(diagnosticIncidentNodeLabel(historicalIncident), '检查 OpenAI 账号状态')
  assert.equal(diagnosticEventNodeLabel({
    outcome: 'success',
    node_code: 'account_banned',
    node_label: '检查 OpenAI 账号状态',
    error_code: 'account_banned',
  }), '检查 OpenAI 账号状态')

  assert.equal(diagnosticIncidentNodeLabel({
    status: 'error',
    outcome: 'error',
    first_node_code: 'account_banned',
    first_node_label: '检查 OpenAI 账号状态',
  }), ACCOUNT_BANNED_DISPLAY_MESSAGE)
  assert.equal(diagnosticEventNodeLabel({
    outcome: 'error',
    node_code: 'account_banned',
    node_label: '检查 OpenAI 账号状态',
  }), ACCOUNT_BANNED_DISPLAY_MESSAGE)
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
