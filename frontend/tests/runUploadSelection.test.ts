import assert from 'node:assert/strict'
import test from 'node:test'
import { ref } from 'vue'
import { useRunUploadSelection } from '../src/composables/useRunUploadSelection.ts'

test('upload targets start unchecked and reset every time the dialog opens', () => {
  const selection = useRunUploadSelection(() => true)

  assert.deepEqual(selection.targets(), { pixel: false, nv: false })
  selection.pixel.value = true
  selection.nv.value = true
  assert.deepEqual(selection.targets(), { pixel: true, nv: true })

  selection.open()
  assert.equal(selection.visible.value, true)
  assert.equal(selection.pixel.value, false)
  assert.equal(selection.nv.value, false)
  assert.deepEqual(selection.targets(), { pixel: false, nv: false })
})

test('NV is disabled and omitted when its configuration is unavailable', () => {
  const configured = ref(false)
  const selection = useRunUploadSelection(() => configured.value)

  selection.nv.value = true
  assert.equal(selection.nvDisabled.value, true)
  assert.deepEqual(selection.targets(), { pixel: false, nv: false })

  configured.value = true
  assert.equal(selection.nvDisabled.value, false)
  assert.deepEqual(selection.targets(), { pixel: false, nv: true })
})
