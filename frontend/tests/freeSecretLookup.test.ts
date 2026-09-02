import assert from 'node:assert/strict'
import test from 'node:test'
import { freeRowSecretLookup, freeTaskSecretLookup } from '../src/utils/freeSecretLookup.ts'

test('Free task email lookup prefers the private task id over masked public text', () => {
  assert.deepEqual(freeTaskSecretLookup(' task-42 ', 'row-42'), { task_ids: ['task-42'] })
  assert.deepEqual(freeTaskSecretLookup('', 'row-42'), { row_ids: ['row-42'] })
  assert.deepEqual(freeTaskSecretLookup('', ''), {})
})

test('Free mailbox email lookup is scoped to the private row id', () => {
  assert.deepEqual(freeRowSecretLookup(' row-17 '), { row_ids: ['row-17'] })
  assert.deepEqual(freeRowSecretLookup(null), {})
})
