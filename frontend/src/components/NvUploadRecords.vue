<script setup lang="ts">
import { RefreshRight } from '@element-plus/icons-vue'
import ContentEmptyState from './ContentEmptyState.vue'
import type { NvUploadRecord } from '../types/api'

defineProps<{
  records: NvUploadRecord[]
  loading: boolean
  retryingIds: string[]
}>()
const emit = defineEmits<{ retry: [string] }>()

function statusLabel(status: string) {
  const labels: Record<string, string> = {
    queued: '等待上传',
    processing: '上传中',
    success: '成功',
    partial: '部分接收/需人工确认',
    failed: '失败',
    source_unavailable: '源文件不可用',
  }
  return labels[String(status || '').toLowerCase()] || status || '未知'
}

function statusTone(status: string): 'success' | 'warning' | 'danger' | 'info' {
  const value = String(status || '').toLowerCase()
  if (value === 'success') return 'success'
  if (['queued', 'processing', 'partial'].includes(value)) return 'warning'
  if (['failed', 'source_unavailable'].includes(value)) return 'danger'
  return 'info'
}

function stageLabel(stage: string) {
  const labels: Record<string, string> = { import: 'NV 导入' }
  return labels[String(stage || '').toLowerCase()] || stage || '-'
}

function dateLabel(value: number) {
  if (!value) return '-'
  return new Date(value * 1000).toLocaleString('zh-CN', { hour12: false })
}
</script>

<template>
  <el-table v-loading="loading" :data="records" height="100%" row-key="record_id" stripe>
    <el-table-column prop="batch_id" label="批次" min-width="210" show-overflow-tooltip />
    <el-table-column label="批次时间" width="170">
      <template #default="{ row }">{{ dateLabel(row.batch_started_at || row.created_at) }}</template>
    </el-table-column>
    <el-table-column prop="source_count" label="账号数" width="82" align="right" />
    <el-table-column label="状态" width="116">
      <template #default="{ row }">
        <el-tag :type="statusTone(row.status)" effect="light">{{ statusLabel(row.status) }}</el-tag>
      </template>
    </el-table-column>
    <el-table-column label="导入结果" width="112" align="right">
      <template #default="{ row }">{{ row.accepted || 0 }}/{{ row.source_count }}</template>
    </el-table-column>
    <el-table-column prop="attempts" label="队列次数" width="92" align="right" />
    <el-table-column label="阶段" width="104">
      <template #default="{ row }">{{ stageLabel(row.stage) }}</template>
    </el-table-column>
    <el-table-column label="失败节点" width="150" show-overflow-tooltip>
      <template #default="{ row }">{{ row.failure?.node_label || '-' }}</template>
    </el-table-column>
    <el-table-column label="HTTP" width="72" align="right">
      <template #default="{ row }">{{ row.failure?.http_status || '-' }}</template>
    </el-table-column>
    <el-table-column label="Provider" width="132" show-overflow-tooltip>
      <template #default="{ row }">{{ row.failure?.provider_code || '-' }}</template>
    </el-table-column>
    <el-table-column label="脱敏错误" min-width="280" show-overflow-tooltip>
      <template #default="{ row }">
        <span :class="{ danger: row.error }">{{ row.error || '-' }}</span>
      </template>
    </el-table-column>
    <el-table-column label="操作" width="72" fixed="right" align="center">
      <template #default="{ row }">
        <el-tooltip v-if="row.can_retry" content="重试 NV 上传" placement="top">
          <el-button
            circle
            :icon="RefreshRight"
            :loading="retryingIds.includes(row.record_id)"
            aria-label="重试 NV 上传"
            @click="emit('retry', row.record_id)"
          />
        </el-tooltip>
        <span v-else>-</span>
      </template>
    </el-table-column>
    <template #empty><ContentEmptyState description="暂无 NV 上传记录" /></template>
  </el-table>
</template>

<style scoped>
.danger { color: var(--el-color-danger); }
</style>
