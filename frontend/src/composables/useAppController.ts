import { computed, inject, reactive, readonly, ref, shallowRef, type InjectionKey } from 'vue'
import { ElNotification } from 'element-plus'
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
import type { AppState, SmsRuntimeAlert } from '../types/api'

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
  node_timeout: 45,
  auth_session_retries: 1,
  sms_provider: 'smsbower',
  sms_min_price: '0.01',
  max_price: '0.1',
  sms_timeout: '30',
  phone_max_attempts: 15,
  phone_session_cycle_seconds: 480,
  sms_api_keys: [''],
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
  const keys = Array.isArray(config.sms_api_keys)
    ? config.sms_api_keys
    : config.sms_api_key
      ? [config.sms_api_key]
      : []
  config.sms_api_keys = [...new Set(keys.map((key: unknown) => String(key || '').trim()).filter(Boolean))]
  if (!config.sms_api_keys.length) config.sms_api_keys = ['']
  delete config.sms_api_key
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
    const value = mergeConfig(form)
    const keys = Array.isArray(value.sms_api_keys) ? [...value.sms_api_keys] : [value.sms_api_key || '']
    value.sms_api_keys = keys
    value.sms_api_key = keys[0] || ''
    value.email_notification = normalizeEmailNotificationDraft(value.email_notification)
    delete value.nvtoken
    delete value.nvtoken_upload
    return value
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
    if (!Array.isArray(form.sms_api_keys)) form.sms_api_keys = [form.sms_api_key || '']
    if (!form.sms_api_keys.length) form.sms_api_keys = ['']
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
    await initialize()
    const wasDirty = dirty.value
    await Promise.all([
      form.sms_api_keys?.some((key: string) => key === '********')
        ? getSecret('sms_api_keys').then(result => {
            form.sms_api_keys = Array.isArray(result.value) ? result.value : [String(result.value || '')]
          }).catch(() => undefined)
        : Promise.resolve(),
      loadSecret(() => form.sub2api?.password, value => { form.sub2api.password = String(value || '') }, 'sub2_password'),
      loadSecret(() => form.email_notification?.password, value => {
        form.email_notification.password = String(value || '')
      }, 'notification_email_password'),
      loadSecret(() => form.proxy, value => { form.proxy = String(value || '') }, 'proxy'),
    ])
    secretsLoaded.value = true
    if (!wasDirty) markClean()
  }

  async function save() {
    actions.saving = true
    try {
      const result = await saveConfig(requestPayload())
      syncState(result)
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
    if (dirty.value && !allowDirty) throw new Error('运行配置有未保存修改')
    actions.starting = true
    try {
      const result = await startExistingRun(requestPayload())
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
