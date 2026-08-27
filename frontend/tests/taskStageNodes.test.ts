import assert from 'node:assert/strict'
import test from 'node:test'
import { FREE_CAMOUFOX_STAGE_NODES } from '../src/utils/taskStageNodes.ts'

test('task details register every stable Camoufox stage', () => {
  assert.deepEqual(
    FREE_CAMOUFOX_STAGE_NODES.map(node => node.code),
    [
      'free_camoufox_dependency',
      'free_camoufox_launch',
      'free_camoufox_signup',
      'free_camoufox_navigation',
      'free_camoufox_signup_email',
      'free_camoufox_signup_password',
      'free_camoufox_profile',
      'free_camoufox_browser',
      'free_camoufox_challenge',
    ],
  )
  assert.ok(FREE_CAMOUFOX_STAGE_NODES.every(node => node.group === 'free' && node.label.length > 0))
})
