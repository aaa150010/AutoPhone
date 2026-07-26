<script setup lang="ts">
import { onMounted, onUnmounted, reactive, ref } from 'vue'
import { ElMessage, ElNotification } from 'element-plus'
import { getLocalConfig, getSecret, getState, preflightRun, saveConfig, startRun, stopRun } from '../api/client'
import SettingsForm from '../components/SettingsForm.vue'
import RunOperationBar from '../components/RunOperationBar.vue'
import RuntimeMetrics from '../components/RuntimeMetrics.vue'
import TaskResultsPanel from '../components/TaskResultsPanel.vue'
import LogPanel from '../components/LogPanel.vue'
import type { SmsRuntimeAlert } from '../types/api'

const state = ref<any>({ runtime: {}, settings: {} })
const form = reactive<any>({
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
  phone_max_attempts: 10,
  phone_session_cycle_seconds: 480,
  sms_api_keys: [''],
  nvtoken_upload: true,
  nvtoken: {},
  sub2api: {},
})

const saving = ref(false)
const preflighting = ref(false)
const smsKeysDirty = ref(false)
const seenAlerts = new Set<string>()
let timer = 0

const running = () => Boolean(state.value.runtime?.running)
const hasPool = () => Number(state.value.runtime?.pool?.available || 0) > 0
const smsKeyStatuses = () => smsKeysDirty.value
  ? []
  : state.value.sms_key_statuses || state.value.runtime?.sms_key_statuses || []

function normalizedKeys(value: any) {
  const source = Array.isArray(value?.sms_api_keys) ? value.sms_api_keys : [value?.sms_api_key || '']
  return source.map((key: unknown) => String(key || '').trim())
}

function updateForm(value: any) {
  if (JSON.stringify(normalizedKeys(form)) !== JSON.stringify(normalizedKeys(value))) {
    smsKeysDirty.value = true
  }
  Object.assign(form, value)
}

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

function sync(payload: any) {
  state.value = payload.state || payload
  showRuntimeAlerts(state.value.sms_alerts || state.value.runtime?.sms_alerts || [])
}

function payload() {
  const keys = Array.isArray(form.sms_api_keys) ? [...form.sms_api_keys] : [form.sms_api_key || '']
  return { ...form, sms_api_keys: keys, sms_api_key: keys[0] || '' }
}

async function refresh() {
  try {
    sync(await getState())
  } catch {}
}

async function load() {
  try {
    const [stateResult, localResult] = await Promise.all([getState(), getLocalConfig()])
    sync(stateResult)
    Object.assign(form, state.value.settings || {}, localResult.config || {})
    form.proxy_scope = { sms: false, email: false, upload: false, ...(form.proxy_scope || {}) }
    form.sub2api = { ...(form.sub2api || {}) }
    form.nvtoken = { ...(form.nvtoken || {}) }
    if (!Array.isArray(form.sms_api_keys)) form.sms_api_keys = [form.sms_api_key || '']

    const secretLoads: Promise<void>[] = []
    if (form.sms_api_keys.some((key: string) => key === '********')) {
      secretLoads.push((async () => {
        try {
          const value = (await getSecret('sms_api_keys')).value
          form.sms_api_keys = Array.isArray(value) ? value : [String(value || '')]
        } catch {}
      })())
    }
    if (form.sub2api.password === '********') {
      secretLoads.push((async () => {
        try { form.sub2api.password = String((await getSecret('sub2_password')).value || '') } catch {}
      })())
    }
    if (form.nvtoken.api_key === '********') {
      secretLoads.push((async () => {
        try { form.nvtoken.api_key = String((await getSecret('nvtoken_api_key')).value || '') } catch {}
      })())
    }
    await Promise.all(secretLoads)
    if (!form.sms_api_keys.length) form.sms_api_keys = ['']
    smsKeysDirty.value = false
  } catch (error: any) {
    ElMessage.error(error.message)
  }
}

async function save() {
  saving.value = true
  try {
    await saveConfig(payload())
    smsKeysDirty.value = false
    ElMessage.success('配置已保存')
    await refresh()
  } catch (error: any) {
    ElMessage.error(error.message)
  } finally {
    saving.value = false
  }
}

async function preflight() {
  preflighting.value = true
  try {
    await preflightRun(payload())
    smsKeysDirty.value = false
    ElMessage.success('真实链路预检通过')
    await refresh()
  } catch (error: any) {
    ElMessage.error(error.message)
    await refresh()
  } finally {
    preflighting.value = false
  }
}

async function start() {
  try {
    await startRun(payload())
    ElMessage.success('任务已启动')
    await refresh()
  } catch (error: any) {
    ElMessage.error(error.message)
    await refresh()
  }
}

async function stop() {
  try {
    await stopRun()
    ElMessage.success('已发送停止请求')
    await refresh()
  } catch (error: any) {
    ElMessage.error(error.message)
  }
}

onMounted(async () => {
  await load()
  timer = window.setInterval(refresh, 1200)
})
onUnmounted(() => window.clearInterval(timer))
</script>

<template>
  <div class="page">
    <div class="content">
      <el-card shadow="never" class="config-card">
        <SettingsForm
          :model-value="form"
          :sms-key-statuses="smsKeyStatuses()"
          @update:model-value="updateForm"
        />
        <RunOperationBar
          :model-value="form"
          :running="running()"
          :has-pool="hasPool()"
          :saving="saving"
          :preflighting="preflighting"
          @update:model-value="updateForm"
          @save="save"
          @preflight="preflight"
          @start="start"
          @stop="stop"
        />
      </el-card>

      <el-card shadow="never" class="runtime-card">
        <RuntimeMetrics :runtime="state.runtime" />
        <el-divider content-position="center">任务结果</el-divider>
        <div class="task-section"><TaskResultsPanel :tasks="state.runtime?.tasks || []" /></div>
        <el-divider content-position="center">运行日志</el-divider>
        <div class="log-section"><LogPanel :logs="state.logs || state.runtime?.logs || []" /></div>
      </el-card>
    </div>
  </div>
</template>

<style scoped>
.page { width: 100%; height: 100%; padding: 2px; overflow: hidden; }
.content { display: grid; grid-template-columns: minmax(410px, 38%) minmax(0, 1fr); gap: 8px; width: 100%; height: 100%; min-height: 0; margin-top: 0; }
.config-card,
.runtime-card { min-width: 0; min-height: 0; height: 100%; display: flex; flex-direction: column; }
.config-card > :deep(.el-card__body) { min-height: 0; flex: 1; padding: 10px; overflow: auto; }
.runtime-card > :deep(.el-card__body) { min-height: 0; flex: 1; display: flex; flex-direction: column; padding: 8px; overflow: hidden; }
.runtime-card :deep(.el-divider) { flex: 0 0 auto; margin: 20px 0; }
.task-section { min-height: 0; flex: 1.1; overflow: hidden; }
.log-section { min-height: 0; flex: 1; overflow: hidden; }
@media (max-width: 1040px) {
  .content { grid-template-columns: 1fr; grid-template-rows: minmax(0, 1fr) minmax(0, 1fr); }
}
</style>
