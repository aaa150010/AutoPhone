import { computed, inject, reactive, readonly, ref, shallowRef, type InjectionKey } from 'vue'
import {
  ApiError,
  api,
  getLocalConfig,
  getSecret,
  getState,
  preflightRun,
  querySmsBalances,
  saveConfig,
  startExistingRun,
  stopRun,
  testEmailNotification,
  updateOpenAIConnectivityGuard,
} from '../api/client'
import type { AppState, SmsKeyStatus, SmsProviderPool } from '../types/api'
import { createRuntimeNotificationObserver } from './useRuntimeNotifications'
import { createConnectivityDiagnosticTrigger } from './useConnectivityDiagnostics'
import { preferNewestOpenAIConnectivityState } from '../utils/openAIConnectivity'
import {
  mergeRevealedSmsPools,
  normalizeSmsProviderPools,
  smsProviderKeyCounts,
  syncLegacySmsFields,
} from '../utils/smsPools'

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
    sms_balance_low: true,
    openai_auth_connectivity: true,
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
  phone_submission_concurrency: 2,
  node_timeout: 45,
  email_code_timeout: 60,
  auth_session_retries: 1,
  adaptive_task_concurrency: true,
  task_inflight_optimization: true,
  task_inflight_limit: 20,
  openai_connectivity_guard: true,
  phone_binding_compatibility: true,
  mailbox_result_index_cache: true,
  protocol_concurrency_ceiling: 12,
  sms_provider: 'smsbower',
  sms_min_price: '0.01',
  max_price: '0.15',
  sms_timeout: '30',
  phone_max_attempts: 45,
  phone_attempts_per_provider: 15,
  phone_session_cycle_seconds: 1800,
  sms_quality_optimization: true,
  sms_api_keys: [''],
  sms_provider_pools: normalizeSmsProviderPools(null),
  sub2api: {},
  online_mailbox: {
    base_url: 'https://lynote.xyz/token-tool',
    api_token: '',
  },
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

function normalizeOperationalSettings(config: Record<string, any>) {
  config.phone_submission_concurrency = Math.max(1, Math.min(5, Number(config.phone_submission_concurrency) || 2))
  config.adaptive_task_concurrency = config.adaptive_task_concurrency !== false
  config.task_inflight_optimization = config.task_inflight_optimization !== false
  config.task_inflight_limit = Math.max(1, Math.min(20, Number(config.task_inflight_limit) || 20))
  config.openai_connectivity_guard = config.openai_connectivity_guard !== false
  config.phone_binding_compatibility = config.phone_binding_compatibility !== false
  config.mailbox_result_index_cache = config.mailbox_result_index_cache !== false
  config.protocol_concurrency_ceiling = Math.max(8, Math.min(15, Number(config.protocol_concurrency_ceiling) || 12))
  delete config.allow_free_plan_sms_binding
  delete config.allow_unknown_plan_sms_binding
  config.sms_quality_optimization = config.sms_quality_optimization !== false
  return config
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
  delete config.free_target_count
  delete config.free_concurrency
  delete config.free_proxy_probe_url
  delete config.free_proxy_pool_content
  delete config.free_register_password
  delete config.free_pool_content
  syncLegacySmsFields(config)
  normalizeOperationalSettings(config)
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
    queryingSmsBalances: false,
    updatingConnectivityGuard: false,
  })
  const queriedSmsKeyStatuses = ref<SmsKeyStatus[] | null>(null)
  const runtimeNotificationObserver = createRuntimeNotificationObserver()
  const connectivityDiagnostics = createConnectivityDiagnosticTrigger()
  let baseline = signature(form)
  let pollTimer = 0
  let pollingStopped = true
  let stateSignature = ''
  let secretLoadPromise: Promise<void> | null = null

  const runtime = computed(() => state.value.runtime || {})
  const running = computed(() => Boolean(runtime.value.running))
  const hasPool = computed(() => Number(runtime.value.pool?.available || 0) > 0)
  const smsKeyStatuses = computed(() => (
    queriedSmsKeyStatuses.value
    || state.value.sms_key_statuses
    || runtime.value.sms_key_statuses
    || []
  ))

  function syncState(payload: any) {
    const next = payload?.state || payload
    if (!next || typeof next !== 'object') return
    const accepted = preferNewestOpenAIConnectivityState(state.value, next)
    const nextSignature = JSON.stringify(accepted)
    if (nextSignature !== stateSignature) {
      stateSignature = nextSignature
      state.value = accepted
    }
    runtimeNotificationObserver.observe(accepted)
    connectivityDiagnostics.observeState(accepted)
  }

  function syncError(error: unknown) {
    if (error instanceof ApiError && error.payload?.state) syncState(error.payload.state)
    connectivityDiagnostics.observeError(error)
  }

  function markClean() {
    baseline = signature(form)
    dirty.value = false
  }

  function updateForm(value: Record<string, any>) {
    Object.assign(form, mergeConfig(form, value))
    queriedSmsKeyStatuses.value = []
    dirty.value = signature(form) !== baseline
  }

  function acceptSavedField(key: string, value: any) {
    const saved = JSON.parse(baseline)
    saved[key] = value
    baseline = signature(saved)
    form[key] = value
    dirty.value = signature(form) !== baseline
  }

  function requestPayload() {
    const value = syncLegacySmsFields(mergeConfig(form))
    value.email_notification = normalizeEmailNotificationDraft(value.email_notification)
            return value
  }

  function smsBalanceDraftSignature() {
    return JSON.stringify({
      sms_provider_pools: form.sms_provider_pools,
      sms_provider: form.sms_provider,
      sms_api_keys: form.sms_api_keys,
      sms_api_key: form.sms_api_key,
      sms_min_price: form.sms_min_price,
      max_price: form.max_price,
      proxy: form.proxy,
      proxy_scope: form.proxy_scope,
    })
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
          sms_cost_history: current.runtime?.summary?.sms_cost_history,
        },
      },
    }
    stateSignature = JSON.stringify(state.value)
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
            delete merged.free_target_count
    delete merged.free_concurrency
    delete merged.free_proxy_probe_url
    delete merged.free_proxy_pool_content
    delete merged.free_register_password
    delete merged.free_pool_content
    normalizeOperationalSettings(merged)
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
        loadSecret(() => form.online_mailbox?.api_token, value => {
          form.online_mailbox.api_token = String(value || '')
        }, 'online_mailbox_api_token'),
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

  async function setOpenAIConnectivityGuard(enabled: boolean) {
    actions.updatingConnectivityGuard = true
    try {
      const result = await updateOpenAIConnectivityGuard(enabled)
      acceptSavedField('openai_connectivity_guard', enabled)
      syncState(result)
      return result
    } catch (error) {
      syncError(error)
      throw error
    } finally {
      actions.updatingConnectivityGuard = false
    }
  }

  async function preflight() {
    actions.preflighting = true
    try {
      await ensureSecretsLoaded()
      const result = await preflightRun(requestPayload())
      syncState(result)
      queriedSmsKeyStatuses.value = result.sms_key_statuses || []
      markClean()
      return result
    } catch (error) {
      syncError(error)
      throw error
    } finally {
      actions.preflighting = false
    }
  }

  async function start(
    allowDirty = false,
    runMode: 'register' | 'free_register' = 'register',
  ) {
    await ensureSecretsLoaded()
    if (dirty.value && !allowDirty) throw new Error('运行配置有未保存修改')
    actions.starting = true
    resetRunSnapshot()
    try {
      const payload = requestPayload()
      payload.run_mode = runMode
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

  async function queryBalances() {
    actions.queryingSmsBalances = true
    try {
      await ensureSecretsLoaded()
      const draftSignature = smsBalanceDraftSignature()
      const result = await querySmsBalances(requestPayload())
      if (draftSignature !== smsBalanceDraftSignature()) {
        throw new Error('接码 Key 配置已变化，请重新查询余额')
      }
      queriedSmsKeyStatuses.value = result.sms_key_statuses || []
      return result
    } finally {
      actions.queryingSmsBalances = false
    }
  }

  async function poll() {
    await refresh()
    if (pollingStopped) return
    pollTimer = window.setTimeout(poll, running.value ? 700 : 1500)
  }

  async function startPolling() {
    pollingStopped = false
    while (!pollingStopped && !initialized.value) {
      try {
        await initialize()
      } catch (error) {
        syncError(error)
        await new Promise(resolve => window.setTimeout(resolve, 1000))
      }
    }
    if (!pollingStopped) pollTimer = window.setTimeout(poll, running.value ? 700 : 1500)
  }

  function stopPolling() {
    pollingStopped = true
    window.clearTimeout(pollTimer)
    runtimeNotificationObserver.dispose()
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
    connectivityDiagnosticRequest: connectivityDiagnostics.request,
    initialize,
    ensureSecretsLoaded,
    updateForm,
    syncState,
    refresh,
    save,
    setOpenAIConnectivityGuard,
    openConnectivityDiagnostics: connectivityDiagnostics.open,
    clearConnectivityDiagnosticRequest: connectivityDiagnostics.clear,
    preflight,
    start,
    stop,
    importConfig,
    exportConfig,
    sendTestNotification,
    queryBalances,
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
