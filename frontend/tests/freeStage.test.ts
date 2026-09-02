import assert from 'node:assert/strict'
import test from 'node:test'
import { freeStageDetail, freeStageIsSuccess, freeStageLabel, freeStageType } from '../src/utils/freeStage.ts'

test('successful Free outcomes use the concise success stage label', () => {
  assert.equal(freeStageIsSuccess('success'), true)
  assert.equal(freeStageIsSuccess('consumed'), true)
  assert.equal(freeStageLabel('free_result_save', '处理中', 'success'), '成功')
  assert.equal(freeStageDetail('free_result_save', '保存 Free 注册结果', 'success'), '成功')
  assert.equal(freeStageType('free_result_save', 'success'), 'success')
})

test('non-success Free stages retain their Chinese node label and tone', () => {
  assert.equal(freeStageLabel('free_email_otp_wait', '-', 'running'), '等待 Free 邮箱验证码')
  assert.equal(freeStageLabel('free_live_fast', '-', 'running'), '快速测活')
  assert.equal(freeStageLabel('free_live_result', '-', 'running'), '保存 Free 测活结果')
  assert.equal(freeStageType('free_email_otp_wait', 'running'), 'warning')
  assert.equal(freeStageIsSuccess('failed'), false)
})
