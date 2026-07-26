<script setup lang="ts">
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api/client'

const props = defineProps<{
  modelValue: any
  running: boolean
  hasPool: boolean
  saving: boolean
  preflighting: boolean
}>()

const emit = defineEmits<{
  'update:modelValue': [any]
  save: []
  preflight: []
  start: []
  stop: []
}>()

const fileInput = ref<HTMLInputElement>()
const importing = ref(false)
const exporting = ref(false)
const performancePolicyVersion = 5

async function exportConfig() {
  exporting.value = true
  try {
    const result: any = await api('/api/local-config/export', { ...props.modelValue, download: true })
    const blob = new Blob([JSON.stringify(result.config || {}, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'gptphone-config.json'
    link.click()
    URL.revokeObjectURL(url)
    ElMessage.success('配置已导出')
  } catch (error: any) {
    ElMessage.error(error.message || '导出配置失败')
  } finally {
    exporting.value = false
  }
}

async function importConfig(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  importing.value = true
  try {
    const config = JSON.parse(await file.text())
    if (!Array.isArray(config.sms_api_keys) && config.sms_api_key) {
      config.sms_api_keys = [config.sms_api_key]
    }
    config.sms_api_keys = [...new Set(
      (Array.isArray(config.sms_api_keys) ? config.sms_api_keys : [''])
        .map((key: unknown) => String(key || '').trim())
        .filter(Boolean),
    )]
    if (!config.sms_api_keys.length) config.sms_api_keys = ['']
    if (Number(config.performance_policy_version || 0) < performancePolicyVersion) {
      if (Number(config.phone_max_attempts || 0) <= 0) config.phone_max_attempts = 10
      if (Number(config.phone_session_cycle_seconds || 0) <= 0) config.phone_session_cycle_seconds = 480
      if (Number(config.auth_session_retries || 0) <= 0) config.auth_session_retries = 1
      config.performance_policy_version = performancePolicyVersion
    }
    delete config.sms_api_key
    await api('/api/local-config/import', { config })
    emit('update:modelValue', {
      ...props.modelValue,
      ...config,
      sub2api: { ...(props.modelValue.sub2api || {}), ...(config.sub2api || {}) },
      nvtoken: { ...(props.modelValue.nvtoken || {}), ...(config.nvtoken || {}) },
    })
    ElMessage.success('配置已导入')
  } catch (error: any) {
    ElMessage.error(error.message || '导入配置失败')
  } finally {
    importing.value = false
    input.value = ''
  }
}
</script>

<template>
  <div class="operation-scroll">
    <div class="operation-bar">
      <input ref="fileInput" class="file-input" type="file" accept="application/json,.json" @change="importConfig" />
      <el-button :loading="importing" :disabled="running" @click="fileInput?.click()">
        <el-icon><Upload /></el-icon>导入配置
      </el-button>
      <el-button :loading="exporting" @click="exportConfig">
        <el-icon><Download /></el-icon>导出配置
      </el-button>
      <el-button :loading="saving" :disabled="running" @click="emit('save')">
        <el-icon><Check /></el-icon>保存配置
      </el-button>
      <el-button :loading="preflighting" :disabled="running" @click="emit('preflight')">
        <el-icon><CircleCheck /></el-icon>真实链路预检
      </el-button>
      <el-button type="primary" :disabled="running || !hasPool" @click="emit('start')">
        <el-icon><VideoPlay /></el-icon>开始运行
      </el-button>
      <el-button type="danger" plain :disabled="!running" @click="emit('stop')">
        <el-icon><VideoPause /></el-icon>停止
      </el-button>
    </div>
  </div>
</template>

<style scoped>
.operation-scroll { width: 100%; margin-top: 8px; overflow-x: auto; overflow-y: hidden; }
.operation-bar { display: flex; flex-wrap: nowrap; gap: 4px; width: max-content; min-width: 100%; }
.operation-bar :deep(.el-button) { flex: 0 0 auto; min-width: 0; margin-left: 0; padding: 5px 6px; }
.file-input { display: none; }
</style>
