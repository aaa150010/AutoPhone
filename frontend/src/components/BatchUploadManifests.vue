<script setup lang="ts">
import { RefreshRight } from '@element-plus/icons-vue'
import ContentEmptyState from './ContentEmptyState.vue'
import type { BatchUploadManifest } from '../types/api'

defineProps<{
  records: BatchUploadManifest[]
  loading: boolean
  retryingKeys: string[]
}>()
const emit = defineEmits<{
  retry: [string, 'pixel' | 'nv']
}>()

function statusLabel(status: string) {
  const labels: Record<string, string> = {
    waiting: '等待批次结束',
    collected: '已收集',
    queueing: '正在入队',
    queued: '已入队',
    queue_failed: '入队失败',
    empty: '无成功账号',
    disabled: '未选择',
    complete: '已完成',
  }
  return labels[String(status || '').toLowerCase()] || status || '未知'
}

function statusTone(status: string): 'success' | 'warning' | 'danger' | 'info' {
  const value = String(status || '').toLowerCase()
  if (['queued', 'complete'].includes(value)) return 'success'
  if (['waiting', 'collected', 'queueing'].includes(value)) return 'warning'
  if (value === 'queue_failed') return 'danger'
  return 'info'
}

function platformStatus(row: BatchUploadManifest, platform: 'pixel' | 'nv') {
  if (!row.targets?.[platform]) return 'disabled'
  return row.platforms?.[platform]?.status || 'waiting'
}

function errorLabel(row: BatchUploadManifest) {
  return (['pixel', 'nv'] as const)
    .map(platform => {
      const error = row.platforms?.[platform]?.error || ''
      return error ? `${platform.toUpperCase()}：${error}` : ''
    })
    .filter(Boolean)
    .join('；') || '-'
}

function retryKey(batchId: string, platform: 'pixel' | 'nv') {
  return `${batchId}:${platform}`
}
</script>

<template>
  <el-table v-loading="loading" :data="records" height="100%" row-key="batch_id" stripe>
    <el-table-column prop="batch_id" label="批次" min-width="180" show-overflow-tooltip />
    <el-table-column prop="source_count" label="成功账号" width="84" align="right" />
    <el-table-column v-for="target in (['pixel', 'nv'] as const)" :key="target" :label="target.toUpperCase()" width="116">
      <template #default="{ row }">
        <span class="platform-state">
          <el-tag :type="statusTone(platformStatus(row, target))" effect="light">
            {{ statusLabel(platformStatus(row, target)) }}
          </el-tag>
          <el-tooltip v-if="platformStatus(row, target) === 'queue_failed'" :content="`重试 ${target.toUpperCase()} 入队`" placement="top">
            <el-button
              circle
              :icon="RefreshRight"
              :loading="retryingKeys.includes(retryKey(row.batch_id, target))"
              :aria-label="`重试 ${target.toUpperCase()} 入队`"
              @click.stop="emit('retry', row.batch_id, target)"
            />
          </el-tooltip>
        </span>
      </template>
    </el-table-column>
    <el-table-column label="脱敏错误" min-width="240" show-overflow-tooltip>
      <template #default="{ row }">
        <span :class="{ danger: errorLabel(row) !== '-' }">{{ errorLabel(row) }}</span>
      </template>
    </el-table-column>
    <template #empty><ContentEmptyState description="暂无批次上传清单" /></template>
  </el-table>
</template>

<style scoped>
.platform-state { display: flex; align-items: center; gap: 5px; min-width: 0; }
.platform-state :deep(.el-tag) { min-width: 0; }
.platform-state :deep(.el-button) { flex: 0 0 24px; width: 24px; height: 24px; }
.danger { color: var(--el-color-danger); }
</style>
