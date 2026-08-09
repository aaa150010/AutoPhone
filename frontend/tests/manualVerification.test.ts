import assert from 'node:assert/strict'
import test from 'node:test'
import { manualVerificationRequestKey } from '../src/utils/manualVerification.ts'

test('manual verification acceptance is scoped to task, kind, and generation', () => {
  const email = manualVerificationRequestKey('T001', {
    input_kind: 'email_otp',
    generation: 2,
  })

  assert.notEqual(email, manualVerificationRequestKey('T002', {
    input_kind: 'email_otp',
    generation: 2,
  }))
  assert.notEqual(email, manualVerificationRequestKey('T001', {
    input_kind: 'sms_otp',
    generation: 2,
  }))
  assert.notEqual(email, manualVerificationRequestKey('T001', {
    input_kind: 'email_otp',
    generation: 3,
  }))
})
