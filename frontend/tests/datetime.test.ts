import assert from 'node:assert/strict'
import test from 'node:test'
import {
  formatDateTime,
  formatDateTimeOrDash,
  formatDateTimeZh,
  formatDateTimeZhOrEmpty,
  formatShortDateTime,
  parseTimestamp,
} from '../src/utils/datetime.ts'

test('parseTimestamp accepts seconds, milliseconds and ISO strings', () => {
  assert.equal(parseTimestamp(1_700_000_000)?.getTime(), 1_700_000_000_000)
  assert.equal(parseTimestamp(1_700_000_000_000)?.getTime(), 1_700_000_000_000)
  assert.equal(parseTimestamp('2023-11-14T22:13:20Z')?.getTime(), 1_700_000_000_000)
  assert.equal(parseTimestamp(''), null)
  assert.equal(parseTimestamp(null), null)
  assert.equal(parseTimestamp('not-a-date'), null)
})

test('formatDateTime keeps the locale rendering with empty fallback', () => {
  assert.equal(formatDateTime(''), '')
  assert.equal(formatDateTime(null), '')
  assert.equal(typeof formatDateTime(1_700_000_000), 'string')
})

test('formatDateTimeOrDash renders a dash for missing values', () => {
  assert.equal(formatDateTimeOrDash(''), '-')
  assert.equal(formatDateTimeOrDash(undefined), '-')
})

test('zh-CN helpers keep 24-hour clock text', () => {
  assert.equal(formatDateTimeZh(''), '-')
  assert.equal(formatDateTimeZhOrEmpty(''), '')
  assert.match(formatDateTimeZh(1_700_000_000), /^\d{4}\/\d{1,2}\/\d{1,2} \d{2}:\d{2}:\d{2}$/)
})

test('formatShortDateTime renders compact month/day hour/minute', () => {
  assert.equal(formatShortDateTime(''), '-')
  assert.match(formatShortDateTime(1_700_000_000), /^\d{1,2}\/\d{1,2} \d{2}:\d{2}$/)
})
