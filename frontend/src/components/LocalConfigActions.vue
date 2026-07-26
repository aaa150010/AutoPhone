<script setup lang="ts">
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api/client'

const props = defineProps<{ modelValue: any }>()
const emit = defineEmits<{ 'update:modelValue': [any] }>()
const fileInput = ref<HTMLInputElement>()
const importing = ref(false)
const exporting = ref(false)

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
<template><div class="local-actions"><input ref="fileInput" class="file-input" type="file" accept="application/json,.json" @change="importConfig" /><el-button :loading="importing" @click="fileInput?.click()"><el-icon><Upload /></el-icon>导入配置</el-button><el-button :loading="exporting" @click="exportConfig"><el-icon><Download /></el-icon>导出配置</el-button></div></template>
<style scoped>.local-actions{display:flex;gap:7px;margin:4px 0 10px}.file-input{display:none}</style>
