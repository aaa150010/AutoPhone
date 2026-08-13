import assert from 'node:assert/strict'
import test from 'node:test'
import {
  DEFAULT_RUN_LOG_PANEL_WIDTH,
  MAX_RUN_LOG_PANEL_WIDTH,
  MIN_RUN_LOG_PANEL_WIDTH,
  RUN_LOG_PANEL_WIDTH_KEY,
  readRunLogPanelWidth,
  saveRunLogPanelWidth,
} from '../src/utils/runLogPanel.ts'

class MemoryStorage {
  values = new Map<string, string>()
  getItem(key: string) { return this.values.get(key) ?? null }
  setItem(key: string, value: string) { this.values.set(key, value) }
}

test('run log panel uses the default width for absent or invalid saved values', () => {
  const storage = new MemoryStorage()
  assert.equal(readRunLogPanelWidth(storage), DEFAULT_RUN_LOG_PANEL_WIDTH)
  storage.setItem(RUN_LOG_PANEL_WIDTH_KEY, 'not-a-width')
  assert.equal(readRunLogPanelWidth(storage), DEFAULT_RUN_LOG_PANEL_WIDTH)
})

test('run log panel clamps and persists a safe width', () => {
  const storage = new MemoryStorage()
  assert.equal(saveRunLogPanelWidth(storage, MIN_RUN_LOG_PANEL_WIDTH - 50), MIN_RUN_LOG_PANEL_WIDTH)
  assert.equal(readRunLogPanelWidth(storage), MIN_RUN_LOG_PANEL_WIDTH)
  assert.equal(saveRunLogPanelWidth(storage, MAX_RUN_LOG_PANEL_WIDTH + 50), MAX_RUN_LOG_PANEL_WIDTH)
  assert.equal(readRunLogPanelWidth(storage), MAX_RUN_LOG_PANEL_WIDTH)
  assert.equal(saveRunLogPanelWidth(storage, 312.7), 313)
  assert.equal(readRunLogPanelWidth(storage), 313)
})
