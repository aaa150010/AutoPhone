/** SMS provider-pool normalization shared by the app controller.

Pure functions extracted verbatim from ``useAppController`` so the pool merge,
legacy-key bridge and key counting rules can be unit tested without mounting
the Vue controller.
*/

import type { SmsProviderPool } from '../types/api'

export const smsProviderDefaults: Record<string, string> = {
  smsbower: 'dr',
  herosms: 'dr',
  '5sim': 'openai',
}

export const smsProviderAliases: Record<string, string> = {
  'hero-sms': 'herosms',
  hero_sms: 'herosms',
  fivesim: '5sim',
  'five-sim': '5sim',
  five_sim: '5sim',
}

export function normalizeSmsKeyRows(value: unknown[]): string[] {
  const keys: string[] = []
  const seen = new Set<string>()
  value.forEach((rawKey) => {
    const key = String(rawKey || '').trim()
    if (!key) return
    if (key === '********') {
      keys.push(key)
      return
    }
    if (seen.has(key)) return
    seen.add(key)
    keys.push(key)
  })
  return keys
}

interface RawSmsPoolRow {
  provider?: unknown
  api_keys?: unknown
  api_key?: unknown
  enabled?: unknown
  service?: unknown
}

export function normalizeSmsProviderPools(value: unknown, legacy: unknown = {}): SmsProviderPool[] {
  const rows = Array.isArray(value) ? value : []
  const byProvider = new Map<string, SmsProviderPool>()
  rows.forEach((input: unknown) => {
    if (!input || typeof input !== 'object') return
    const row = input as RawSmsPoolRow
    const providerName = String(row.provider || '').trim().toLowerCase()
    const provider = smsProviderAliases[providerName] || providerName
    if (!provider) return
    const rawKeys = Array.isArray(row.api_keys) ? row.api_keys : [row.api_key || '']
    const keys = normalizeSmsKeyRows(rawKeys)
    const previous = byProvider.get(provider)
    if (previous) {
      previous.enabled = previous.enabled || row.enabled !== false
      const mergedKeys = normalizeSmsKeyRows([...previous.api_keys, ...keys])
      previous.api_keys = mergedKeys.length ? mergedKeys : ['']
      if (!previous.service) previous.service = String(row.service || smsProviderDefaults[provider] || 'dr').trim()
      return
    }
    byProvider.set(provider, {
      provider,
      enabled: row.enabled !== false,
      api_keys: keys.length ? keys : [''],
      service: String(row.service || smsProviderDefaults[provider] || 'dr').trim(),
    })
  })
  const normalized = [...byProvider.values()]
  if (normalized.length) return normalized

  const legacyRecord = (legacy && typeof legacy === 'object' ? legacy : {}) as Record<string, unknown>
  const legacyProviderName = String(legacyRecord.sms_provider || 'smsbower').trim().toLowerCase()
  const provider = smsProviderAliases[legacyProviderName] || legacyProviderName || 'smsbower'
  const rawKeys = Array.isArray(legacyRecord.sms_api_keys)
    ? legacyRecord.sms_api_keys
    : [legacyRecord.sms_api_key || '']
  const keys = normalizeSmsKeyRows(rawKeys)
  return [{
    provider,
    enabled: true,
    api_keys: keys.length ? keys : [''],
    service: smsProviderDefaults[provider] || 'dr',
  }]
}

export function legacySmsKeys(pools: SmsProviderPool[]) {
  const primary = pools.find(pool => pool.provider === 'smsbower')
    || pools.find(pool => pool.enabled && pool.api_keys.some(Boolean))
    || pools[0]
  return normalizeSmsKeyRows(primary?.api_keys || [])
}

export function mergeRevealedSmsPools(current: unknown, revealed: unknown): SmsProviderPool[] {
  const secretPools = normalizeSmsProviderPools(revealed)
  const secretByProvider = new Map(secretPools.map(pool => [pool.provider, pool]))
  const rows = Array.isArray(current) ? current : []
  if (!rows.length) return secretPools
  return rows.map((input: unknown) => {
    const raw = (input && typeof input === 'object' ? input : {}) as RawSmsPoolRow
    const providerName = String(raw?.provider || '').trim().toLowerCase()
    const provider = smsProviderAliases[providerName] || providerName
    const secret = secretByProvider.get(provider)
    const rawKeys = Array.isArray(raw?.api_keys) ? raw.api_keys : [raw?.api_key || '']
    const keys = rawKeys.map((key: unknown, index: number) => (
      String(key || '').trim() === '********'
        ? String(secret?.api_keys[index] || '')
        : String(key || '')
    ))
    return {
      provider,
      enabled: raw?.enabled !== false,
      api_keys: keys,
      service: String(raw?.service || secret?.service || smsProviderDefaults[provider] || 'dr'),
    }
  }).filter(pool => pool.provider)
}

export function smsProviderKeyCounts(value: unknown) {
  return Object.fromEntries(normalizeSmsProviderPools(value).map(pool => [
    pool.provider,
    pool.api_keys.filter(key => String(key || '').trim()).length,
  ]))
}

export function syncLegacySmsFields(config: Record<string, any>) {
  const pools = normalizeSmsProviderPools(config.sms_provider_pools, config)
  const keys = legacySmsKeys(pools)
  config.sms_provider_pools = pools
  config.sms_provider = pools.find(pool => pool.enabled && pool.api_keys.some(Boolean))?.provider
    || pools[0]?.provider
    || 'smsbower'
  config.sms_api_keys = keys.length ? keys : ['']
  config.sms_api_key = keys[0] || ''
  return config
}
