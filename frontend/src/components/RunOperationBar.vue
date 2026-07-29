<script setup lang="ts">
import { ref } from 'vue'
import { ElMessage } from 'element-plus'

defineProps<{
  running: boolean
  hasPool: boolean
  saving: boolean
  preflighting: boolean
  starting: boolean
  stopping?: boolean
  importing?: boolean
  exporting?: boolean
}>()

const emit = defineEmits<{
  importConfig: [any]
  exportConfig: []
  save: []
  preflight: []
  start: []
  stop: []
}>()

const fileInput = ref<HTMLInputElement>()

async function importFile(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  try {
    emit('importConfig', JSON.parse(await file.text()))
  } catch (error: any) {
    ElMessage.error(error?.message || '配置文件不是有效 JSON')
  } finally {
    input.value = ''
  }
}
</script>

<template>
  <div class="operation-bar">
    <input ref="fileInput" class="file-input" type="file" accept="application/json,.json" @change="importFile" />
    <el-button :loading="importing" :disabled="running" @click="fileInput?.click()">
      <el-icon><Upload /></el-icon>导入配置
    </el-button>
    <el-button :loading="exporting" @click="emit('exportConfig')">
      <el-icon><Download /></el-icon>导出配置
    </el-button>
    <el-button :loading="saving" :disabled="running" @click="emit('save')">
      <el-icon><Check /></el-icon>保存配置
    </el-button>
    <el-button :loading="preflighting" :disabled="running" @click="emit('preflight')">
      <el-icon><CircleCheck /></el-icon>真实链路预检
    </el-button>
    <el-button type="primary" :loading="starting" :disabled="running || !hasPool" @click="emit('start')">
      <el-icon><VideoPlay /></el-icon>开始运行
    </el-button>
    <el-button type="danger" plain :loading="stopping" :disabled="!running" @click="emit('stop')">
      <el-icon><VideoPause /></el-icon>停止
    </el-button>
  </div>
</template>

<style scoped>
.operation-bar { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 6px; width: 100%; }
.operation-bar :deep(.el-button) { width: 100%; min-width: 0; height: 34px; margin-left: 0; padding: 0 8px; font-size: 13px; white-space: nowrap; }
.operation-bar :deep(.el-button .el-icon) { flex: 0 0 auto; font-size: 15px; }
.file-input { display: none; }
</style>
