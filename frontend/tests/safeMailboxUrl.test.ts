import assert from 'node:assert/strict'
import test from 'node:test'
import { safeMailboxUrl } from '../src/utils/safeMailboxUrl.ts'

test('mailbox URL validation rejects empty, malformed, and non-web values', () => {
  assert.equal(safeMailboxUrl(''), '')
  assert.equal(safeMailboxUrl('not a url'), '')
  assert.equal(safeMailboxUrl('javascript:alert(1)'), '')
  assert.equal(safeMailboxUrl(null), '')
})

test('mailbox URL validation normalizes explicit HTTP(S) URLs', () => {
  assert.equal(safeMailboxUrl(' https://mail.example.test/pickup?token=redacted '), 'https://mail.example.test/pickup?token=redacted')
  assert.equal(safeMailboxUrl('http://mail.example.test/'), 'http://mail.example.test/')
})
