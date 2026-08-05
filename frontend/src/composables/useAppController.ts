import { computed, inject, reactive, readonly, ref, shallowRef, type InjectionKey } from 'vue'
import { ElMessageBox, ElNotification } from 'element-plus'
import {
  ApiError,
  api,
  getLocalConfig,
  getSecret,
  getState,
  preflightRun,
  saveConfig,
  startExistingRun,
  stopRun,
  testEmailNotification,
} from '../api/client'
import type { AppState, SmsProviderPool, SmsRuntimeAlert } from '../types/api'

const smsProviderDefaults: Record<string, string> = {
  smsbower: 'dr',
  herosms: 'dr',
  '5sim': 'openai',
}

const smsProviderAliases: Record<string, string> = {
  'hero-sms': 'herosms',
  hero_sms: 'herosms',
  fivesim: '5sim',
  'five-sim': '5sim',
  five_sim: '5sim',
}

function normalizeSmsKeyRows(value: unknown[]): string[] {
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

function normalizeSmsProviderPools(value: any, legacy: any = {}): SmsProviderPool[] {
  const rows = Array.isArray(value) ? value : []
  const byProvider = new Map<string, SmsProviderPool>()
  rows.forEach((row: any) => {
    if (!row || typeof row !== 'object') return
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

  const legacyProviderName = String(legacy.sms_provider || 'smsbower').trim().toLowerCase()
  const provider = smsProviderAliases[legacyProviderName] || legacyProviderName || 'smsbower'
  const rawKeys = Array.isArray(legacy.sms_api_keys)
    ? legacy.sms_api_keys
    : [legacy.sms_api_key || '']
  const keys = normalizeSmsKeyRows(rawKeys)
  return [{
    provider,
    enabled: true,
    api_keys: keys.length ? keys : [''],
    service: smsProviderDefaults[provider] || 'dr',
  }]
}

function legacySmsKeys(pools: SmsProviderPool[]) {
  const primary = pools.find(pool => pool.provider === 'smsbower')
    || pools.find(pool => pool.enabled && pool.api_keys.some(Boolean))
    || pools[0]
  return normalizeSmsKeyRows(primary?.api_keys || [])
}

function mergeRevealedSmsPools(current: any, revealed: any): SmsProviderPool[] {
  const secretPools = normalizeSmsProviderPools(revealed)
  const secretByProvider = new Map(secretPools.map(pool => [pool.provider, pool]))
  const rows = Array.isArray(current) ? current : []
  if (!rows.length) return secretPools
  return rows.map((raw: any) => {
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

function smsProviderKeyCounts(value: any) {
  return Object.fromEntries(normalizeSmsProviderPools(value).map(pool => [
    pool.provider,
    pool.api_keys.filter(key => String(key || '').trim()).length,
  ]))
}

function syncLegacySmsFields(config: Record<string, any>) {
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

const defaultEmailNotification = () => ({
  enabled: false,
  provider: 'qq',
  smtp_host: 'smtp.qq.com',
  smtp_port: 465,
  security: 'ssl',
  username: '',
  sender: '',
  password: '',
  recipients: [] as string[],
  stalled_minutes: 10,
  events: {
    batch_completed: true,
    unexpected_stop: true,
    stalled: true,
    sms_exhausted: true,
    manual_stop: false,
  },
})

const defaultForm = () => ({
  proxy: 'http://127.0.0.1:7897',
  proxy_scope: { sms: false, email: false, upload: false },
  target_count: '1',
  concurrency: '5',
  node_concurrency: '5',
  auto_email_login_concurrency: 5,
  node_timeout: 45,
  email_code_timeout: 90,
  auth_session_retries: 1,
  sms_provider: 'smsbower',
  sms_min_price: '0.01',
  max_price: '0.15',
  sms_timeout: '30',
  phone_max_attempts: 45,
  phone_attempts_per_provider: 15,
  phone_session_cycle_seconds: 1800,
  sms_api_keys: [''],
  sms_provider_pools: normalizeSmsProviderPools(null),
  pixel_upload_enabled: true,
  sub2api: {},
  email_notification: defaultEmailNotification(),
})

function mergeConfig(...values: any[]) {
  const result: Record<string, any> = {}
  for (const value of values) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) continue
    for (const [key, item] of Object.entries(value)) {
      if (item && typeof item === 'object' && !Array.isArray(item)) {
        result[key] = mergeConfig(result[key], item)
      } else {
        result[key] = item
      }
    }
  }
  return result
}

function normalizeEmailNotificationDraft(value: any) {
  return {
    ...mergeConfig(defaultEmailNotification(), value || {}),
    provider: 'qq',
    smtp_host: 'smtp.qq.com',
    smtp_port: 465,
    security: 'ssl',
  }
}

function stableValue(value: any): any {
  if (Array.isArray(value)) return value.map(stableValue)
  if (!value || typeof value !== 'object') return value
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, stableValue(value[key])]))
}

function signature(value: any) {
  return JSON.stringify(stableValue(value))
}

function normalizeImportedConfig(value: any) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('配置 JSON 必须是对象')
  }
  const config = mergeConfig(value)
  syncLegacySmsFields(config)
  delete config.nvtoken
  delete config.nvtoken_upload
  if (config.pixel_upload_enabled == null) config.pixel_upload_enabled = true
  config.email_notification = normalizeEmailNotificationDraft(config.email_notification)
  return config
}

export function createAppController() {
  const state = shallowRef<AppState>({ runtime: {}, settings: {}, logs: [] })
  const form = reactive<Record<string, any>>(defaultForm())
  const dirty = ref(false)
  const initialized = ref(false)
  const secretsLoaded = ref(false)
  const actions = reactive({
    saving: false,
    preflighting: false,
    starting: false,
    stopping: false,
    importing: false,
    exporting: false,
    testingNotification: false,
  })
  const seenAlerts = new Set<string>()
  let baseline = signature(form)
  let pollTimer = 0
  let pollingStopped = true
  let stateSignature = ''
  let secretLoadPromise: Promise<void> | null = null

  const runtime = computed(() => state.value.runtime || {})
  const running = computed(() => Boolean(runtime.value.running))
  const hasPool = computed(() => Number(runtime.value.pool?.available || 0) > 0)
  const smsKeyStatuses = computed(() => state.value.sms_key_statuses || runtime.value.sms_key_statuses || [])

  function showRuntimeAlerts(alerts: SmsRuntimeAlert[]) {
    for (const alert of alerts || []) {
      if (!alert?.id || seenAlerts.has(alert.id)) continue
      seenAlerts.add(alert.id)
      ElNotification({
        title: alert.level === 'error' ? 'SMS 服务异常' : 'SMS 服务提醒',
        message: alert.message,
        type: alert.level || 'warning',
        duration: alert.persistent ? 0 : 5000,
      })
    }
  }

  function syncState(payload: any) {
    const next = payload?.state || payload
    if (!next || typeof next !== 'object') return
    const nextSignature = JSON.stringify(next)
    if (nextSignature !== stateSignature) {
      stateSignature = nextSignature
      state.value = next
    }
    showRuntimeAlerts(next.sms_alerts || next.runtime?.sms_alerts || [])
  }

  function syncError(error: unknown) {
    if (error instanceof ApiError && error.payload?.state) syncState(error.payload.state)
  }

  function markClean() {
    baseline = signature(form)
    dirty.value = false
  }

  function updateForm(value: Record<string, any>) {
    Object.assign(form, mergeConfig(form, value))
    dirty.value = signature(form) !== baseline
  }

  function requestPayload() {
    const value = syncLegacySmsFields(mergeConfig(form))
    value.email_notification = normalizeEmailNotificationDraft(value.email_notification)
    delete value.nvtoken
    delete value.nvtoken_upload
    return value
  }

  function resetRunSnapshot() {
    const current = state.value
    state.value = {
      ...current,
      runtime: {
        ...(current.runtime || {}),
        running: false,
        stop_requested: false,
        tasks: [],
        stage_counts: {},
        summary: {
          total: 0,
          active: 0,
          success: 0,
          failed: 0,
          stopped: 0,
          sms_cost_usd: 0,
          sms_cost_cny: 0,
        },
      },
    }
    stateSignature = JSON.stringify(state.value)
  }

  async function pixelUploadChoice() {
    try {
      await ElMessageBox.confirm(
        '本次运行成功的账号是否自动上传到 Pixel？',
        '开始运行',
        {
          type: 'info',
          distinguishCancelAndClose: true,
          confirmButtonText: '上传到 Pixel',
          cancelButtonText: '本次不上传',
        },
      )
      return true
    } catch (action) {
      if (action === 'cancel') return false
      return null
    }
  }

  async function refresh() {
    try {
      syncState(await getState())
    } catch {
      // Polling resumes automatically on the next interval.
    }
  }

  async function initialize() {
    if (initialized.value) return
    const [stateResult, localResult] = await Promise.all([getState(), getLocalConfig()])
    syncState(stateResult)
    const merged = mergeConfig(defaultForm(), state.value.settings || {}, localResult.config || {})
    delete merged.nvtoken
    delete merged.nvtoken_upload
    if (merged.pixel_upload_enabled == null) merged.pixel_upload_enabled = true
    Object.assign(form, merged)
    syncLegacySmsFields(form)
    form.email_notification = normalizeEmailNotificationDraft(form.email_notification)
    markClean()
    initialized.value = true
  }

  async function loadSecret(target: () => any, assign: (value: any) => void, id: string) {
    if (target() !== '********') return
    try {
      assign((await getSecret(id)).value)
    } catch {
      // An empty or older local config legitimately has no value for this secret.
    }
  }

  async function ensureSecretsLoaded() {
    if (secretsLoaded.value) return
    if (secretLoadPromise) return secretLoadPromise
    secretLoadPromise = (async () => {
      await initialize()
      const wasDirty = dirty.value
      await Promise.all([
        form.sms_provider_pools?.some((pool: SmsProviderPool) => pool.api_keys.some(key => key === '********'))
          ? getSecret('sms_provider_pools').then(result => {
              form.sms_provider_pools = mergeRevealedSmsPools(form.sms_provider_pools, result.value)
              syncLegacySmsFields(form)
            }).catch(() => undefined)
          : Promise.resolve(),
        loadSecret(() => form.sub2api?.password, value => { form.sub2api.password = String(value || '') }, 'sub2_password'),
        loadSecret(() => form.email_notification?.password, value => {
          form.email_notification.password = String(value || '')
        }, 'notification_email_password'),
        loadSecret(() => form.proxy, value => { form.proxy = String(value || '') }, 'proxy'),
      ])
      secretsLoaded.value = true
      if (!wasDirty && !dirty.value) markClean()
    })()
    try {
      await secretLoadPromise
    } finally {
      secretLoadPromise = null
    }
  }

  async function save() {
    actions.saving = true
    try {
      await ensureSecretsLoaded()
      const payload = requestPayload()
      const expectedCounts = smsProviderKeyCounts(payload.sms_provider_pools)
      const result = await saveConfig(payload)
      syncState(result)
      const savedSettings = Array.isArray(result.settings?.sms_provider_pools)
        ? result.settings
        : result.state?.settings
      if (savedSettings && Array.isArray(savedSettings.sms_provider_pools)) {
        const savedCounts = smsProviderKeyCounts(savedSettings.sms_provider_pools)
        for (const [provider, expected] of Object.entries(expectedCounts)) {
          const actual = Number(savedCounts[provider] || 0)
          if (actual !== Number(expected)) {
            throw new Error(`${provider} API Key 保存校验失败：期望 ${expected} 个，实际 ${actual} 个`)
          }
        }
      }
      markClean()
      return result
    } catch (error) {
      syncError(error)
      throw error
    } finally {
      actions.saving = false
    }
  }

  async function preflight() {
    actions.preflighting = true
    try {
      await ensureSecretsLoaded()
      const result = await preflightRun(requestPayload())
      syncState(result)
      markClean()
      return result
    } catch (error) {
      syncError(error)
      throw error
    } finally {
      actions.preflighting = false
    }
  }

  async function start(allowDirty = false) {
    await ensureSecretsLoaded()
    if (dirty.value && !allowDirty) throw new Error('运行配置有未保存修改')
    const uploadToPixel = await pixelUploadChoice()
    if (uploadToPixel == null) return null
    actions.starting = true
    resetRunSnapshot()
    try {
      const payload = requestPayload()
      payload.pixel_upload_enabled = uploadToPixel
      const result = await startExistingRun(payload)
      syncState(result)
      markClean()
      return result
    } catch (error) {
      syncError(error)
      throw error
    } finally {
      actions.starting = false
    }
  }

  async function stop() {
    actions.stopping = true
    try {
      const result = await stopRun()
      syncState(result)
      return result
    } catch (error) {
      syncError(error)
      throw error
    } finally {
      actions.stopping = false
    }
  }

  async function importConfig(value: any) {
    actions.importing = true
    try {
      const imported = normalizeImportedConfig(value)
      updateForm(mergeConfig(form, imported))
      const result = await saveConfig(requestPayload())
      syncState(result)
      markClean()
      return result
    } catch (error) {
      syncError(error)
      throw error
    } finally {
      actions.importing = false
    }
  }

  async function exportConfig() {
    actions.exporting = true
    try {
      return await api<{ config: Record<string, any> }>('/api/local-config/export', {
        ...requestPayload(),
        download: true,
      })
    } finally {
      actions.exporting = false
    }
  }

  async function sendTestNotification() {
    actions.testingNotification = true
    try {
      const result = await testEmailNotification(requestPayload())
      syncState(result)
      return result
    } catch (error) {
      syncError(error)
      throw error
    } finally {
      actions.testingNotification = false
    }
  }

  async function poll() {
    await refresh()
    if (pollingStopped) return
    pollTimer = window.setTimeout(poll, running.value ? 700 : 1500)
  }

  async function startPolling() {
    pollingStopped = false
    await initialize()
    if (!pollingStopped) pollTimer = window.setTimeout(poll, running.value ? 700 : 1500)
  }

  function stopPolling() {
    pollingStopped = true
    window.clearTimeout(pollTimer)
  }

  return {
    state: readonly(state),
    form,
    dirty: readonly(dirty),
    initialized: readonly(initialized),
    actions,
    runtime,
    running,
    hasPool,
    smsKeyStatuses,
    initialize,
    ensureSecretsLoaded,
    updateForm,
    syncState,
    refresh,
    save,
    preflight,
    start,
    stop,
    importConfig,
    exportConfig,
    sendTestNotification,
    startPolling,
    stopPolling,
  }
}

export type AppController = ReturnType<typeof createAppController>
export const appControllerKey: InjectionKey<AppController> = Symbol('app-controller')

export function useAppController() {
  const controller = inject(appControllerKey)
  if (!controller) throw new Error('App controller is not available')
  return controller
}
