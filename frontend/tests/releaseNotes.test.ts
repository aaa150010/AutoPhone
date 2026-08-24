import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'
import { currentRelease } from '../src/releaseNotes.ts'
import { ACKNOWLEDGED_VERSION_KEY, acknowledgeReleaseNotes, shouldShowReleaseNotes } from '../src/utils/releaseNotes.ts'

class MemoryStorage {
  values = new Map<string, string>()
  getItem(key: string) { return this.values.get(key) ?? null }
  setItem(key: string, value: string) { this.values.set(key, value) }
}

test('each release version is shown once for the current browser', () => {
  const storage = new MemoryStorage()
  assert.equal(shouldShowReleaseNotes(storage, '1.1.0'), true)
  acknowledgeReleaseNotes(storage, '1.1.0')
  assert.equal(storage.getItem(ACKNOWLEDGED_VERSION_KEY), '1.1.0')
  assert.equal(shouldShowReleaseNotes(storage, '1.1.0'), false)
  assert.equal(shouldShowReleaseNotes(storage, '1.3.1'), true)
})

test('current release documents every feature shipped in this update', () => {
  const text = currentRelease.sections.map(section => `${section.title} ${section.usage}`).join('\n')
  for (const expected of ['待处理', '运行中', '全部', '验证码', '密码', '2FA', '取件 URL', '批次', '任意数量', '并发', '下一批', '重登', 'HTTP 402', 'deactivated_workspace', 'SUB2', '立即删除', '增量加载', '完整扫描', 'ChatGPT/Auth/Sentinel', 'initiate_oauth', '安全页面', '会话重建', '出口地区画像']) {
    assert.match(text, new RegExp(expected))
  }
})

test('release notes and package metadata use the same version', () => {
  const packageJson = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
  assert.equal(currentRelease.version, packageJson.version)
})
