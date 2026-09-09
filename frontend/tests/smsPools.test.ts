import assert from 'node:assert/strict'
import test from 'node:test'
import type { SmsProviderPool } from '../src/types/api'
import {
  legacySmsKeys,
  mergeRevealedSmsPools,
  normalizeSmsKeyRows,
  normalizeSmsProviderPools,
  smsProviderKeyCounts,
  syncLegacySmsFields,
} from '../src/utils/smsPools.ts'

test('normalizeSmsKeyRows deduplicates but keeps mask placeholders', () => {
  // Mask placeholders bypass dedup on purpose (each slot may reveal a different key).
  assert.deepEqual(normalizeSmsKeyRows([' a ', 'a', '', '********', 'b', '********']), ['a', '********', 'b', '********'])
  assert.deepEqual(normalizeSmsKeyRows([]), [])
})

test('normalizeSmsProviderPools merges duplicate providers and applies aliases', () => {
  const pools = normalizeSmsProviderPools([
    { provider: 'Hero-SMS', api_keys: ['k1'], enabled: true, service: '' },
    { provider: 'herosms', api_keys: ['k2'], enabled: false },
  ])
  assert.equal(pools.length, 1)
  assert.equal(pools[0].provider, 'herosms')
  assert.deepEqual(pools[0].api_keys, ['k1', 'k2'])
  assert.equal(pools[0].enabled, true)
  assert.equal(pools[0].service, 'dr')
})

test('normalizeSmsProviderPools falls back to the legacy single-provider shape', () => {
  const pools = normalizeSmsProviderPools(null, { sms_provider: '5sim', sms_api_keys: ['x'] })
  assert.equal(pools.length, 1)
  assert.equal(pools[0].provider, '5sim')
  assert.equal(pools[0].service, 'openai')
  assert.deepEqual(pools[0].api_keys, ['x'])
})

test('legacySmsKeys prefers smsbower then the first enabled pool', () => {
  const pools = normalizeSmsProviderPools([
    { provider: '5sim', api_keys: ['five'], enabled: true },
    { provider: 'smsbower', api_keys: ['primary'], enabled: true },
  ])
  assert.deepEqual(legacySmsKeys(pools), ['primary'])
})

test('mergeRevealedSmsPools fills masked keys from revealed secrets', () => {
  const current = [{ provider: 'smsbower', api_keys: ['********', 'plain'], enabled: true, service: 'dr' }]
  const merged = mergeRevealedSmsPools(current, [{ provider: 'smsbower', api_keys: ['secret'], enabled: true }])
  assert.deepEqual(merged[0].api_keys, ['secret', 'plain'])
})

test('mergeRevealedSmsPools returns the revealed pools when current is empty', () => {
  const merged = mergeRevealedSmsPools([], [{ provider: '5sim', api_keys: ['a'], enabled: false }])
  assert.equal(merged.length, 1)
  assert.equal(merged[0].enabled, false)
})

test('smsProviderKeyCounts counts only non-empty keys', () => {
  const counts = smsProviderKeyCounts([{ provider: 'smsbower', api_keys: ['a', '********', '  '], enabled: true }])
  assert.deepEqual(counts, { smsbower: 2 })
})

test('syncLegacySmsFields bridges pools back to the legacy single-key fields', () => {
  const config = syncLegacySmsFields({
    sms_provider_pools: [{ provider: '5sim', api_keys: ['z'], enabled: true }],
  })
  assert.equal(config.sms_provider, '5sim')
  assert.deepEqual(config.sms_api_keys, ['z'])
  assert.equal(config.sms_api_key, 'z')
  const pools = config.sms_provider_pools as SmsProviderPool[]
  assert.equal(pools.length, 1)
})
