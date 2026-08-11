import assert from 'node:assert/strict'
import test from 'node:test'
import { mailboxSourceLines, mailboxSplitFilename, splitMailboxText } from '../src/utils/mailboxSplitter.ts'

const rows = (count: number) => Array.from({ length: count }, (_, index) => `user-${index + 1}@example.test---pass-${index + 1}`)

test('splits the first 50 of 100 rows and leaves the latter 50 in order', () => {
  const source = rows(100)
  const result = splitMailboxText(source.join('\n'), 50)
  assert.equal(result.valid, true)
  assert.deepEqual(result.splitText.split('\n'), source.slice(0, 50))
  assert.deepEqual(result.remainingText.split('\n'), source.slice(50))
})

test('splits 30 of 100 rows with actual result counts', () => {
  const result = splitMailboxText(rows(100).join('\n'), 30)
  assert.equal(result.splitCount, 30)
  assert.equal(result.remainingCount, 70)
})

test('normalizes CRLF, skips blank lines, and preserves duplicate mixed-format rows', () => {
  const source = 'a@example.test|Pass|TOTP\r\n\r\n  \r\na@example.test|Pass|TOTP\r\nb@example.test----P----C----R'
  assert.deepEqual(mailboxSourceLines(source), [
    'a@example.test|Pass|TOTP',
    'a@example.test|Pass|TOTP',
    'b@example.test----P----C----R',
  ])
  const result = splitMailboxText(source, 2)
  assert.equal(result.splitText, 'a@example.test|Pass|TOTP\na@example.test|Pass|TOTP')
  assert.equal(result.remainingText, 'b@example.test----P----C----R')
})

test('invalid amounts and empty input produce no usable output', () => {
  for (const [source, amount] of [['', 1], ['a', 0], ['a', 2], ['a\nb', 1.5]] as const) {
    const result = splitMailboxText(source, amount)
    assert.equal(result.valid, false)
    assert.equal(result.splitText, '')
    assert.equal(result.remainingText, '')
  }
})

test('download filenames use actual contained counts', () => {
  assert.equal(mailboxSplitFilename('remaining', 70), '剩余-70条.txt')
  assert.equal(mailboxSplitFilename('split', 30), '分割-30条.txt')
})
