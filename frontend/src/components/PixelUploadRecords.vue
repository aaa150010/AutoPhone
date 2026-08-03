<script setup lang="ts">
import { computed } from 'vue'
import { RefreshRight } from '@element-plus/icons-vue'
import ContentEmptyState from './ContentEmptyState.vue'
import type { PixelUploadRecord, PixelUploadTargetRecord } from '../types/api'

const props = defineProps<{
  records: PixelUploadRecord[]
  loading?: boolean
  retryingKeys?: string[]
}>()

const emit = defineEmits<{
  retry: [string, string]
  retryAll: [string]
}>()

interface UploadRow extends PixelUploadTargetRecord {
  rowKey: string
  recordId: string
  taskId: string
  jobId: string
  recordError: string
  recordStatus: string
  recordCreatedAt: string | number | null
  firstForRecord: boolean
  hasRetryableTargets: boolean
}

const rows = computed<UploadRow[]>(() => props.records.flatMap((record) => {
  const targets = record.targets.length ? record.targets : [{
    targetId: '-',
    status: record.status,
    stage: '',
    generatedName: '',
    remoteAccountId: null,
    failedIds: [],
    concurrency: null,
    error: '',
    attempts: 0,
    updatedAt: record.updatedAt,
    retryable: false,
  }]
  const hasRetryableTargets = targets.some(target => target.retryable)
  return targets.map((target, index) => ({
    ...target,
    rowKey: `${record.recordId}:${target.targetId}:${index}`,
    recordId: record.recordId,
    taskId: record.taskId,
    jobId: record.jobId,
    recordError: record.error,
    recordStatus: record.status,
    recordCreatedAt: record.createdAt,
    firstForRecord: index === 0,
    hasRetryableTargets,
  }))
}))

const statusLabels: Record<string, string> = {
  pending: '待上传',
  queued: '待上传',
  waiting: '等待处理',
  uploading: '上传中',
  importing: '导入中',
  imported: '待共享',
  sharing: '共享中',
  processing: '处理中',
  success: '成功',
  complete: '成功',
  completed: '成功',
  partial: '部分失败',
  failed: '上传失败',
  import_failed: '导入待重传',
  share_failed: '共享待重传',
  retry_pending: '待重传',
  pending_retry: '待重传',
  retrying: '重传中',
  needs_confirmation: '需人工确认',
  ambiguous: '需人工确认',
  manual_review: '需人工确认',
  source_unavailable: '源数据不可用',
  source_missing: '源数据不可用',
}

function statusLabel(status: string) {
  return statusLabels[String(status || '').toLowerCase()] || status || '未知'
}

function statusTone(status: string): 'success' | 'warning' | 'danger' | 'info' {
  const value = String(status || '').toLowerCase()
  if (['success', 'complete', 'completed'].includes(value)) return 'success'
  if (['pending', 'queued', 'waiting', 'uploading', 'importing', 'imported', 'sharing', 'processing', 'retrying'].includes(value)) return 'warning'
  if (['failed', 'partial', 'retry_pending', 'pending_retry', 'import_failed', 'share_failed'].includes(value)) return 'danger'
  return 'info'
}

function dateLabel(value: string | number | null) {
  if (value == null || value === '') return '-'
  const numeric = Number(value)
  if (Number.isFinite(numeric) && numeric <= 0) return '-'
  const date = Number.isFinite(numeric)
    ? new Date(numeric < 10_000_000_000 ? numeric * 1000 : numeric)
    : new Date(String(value))
  return Number.isNaN(date.getTime())
    ? '-'
    : date.toLocaleString('zh-CN', { hour12: false, month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

function shortId(value: string) {
  return value.length > 14 ? `${value.slice(0, 12)}...` : value
}

function isRetrying(recordId: string, targetId?: string) {
  const keys = props.retryingKeys || []
  return keys.includes(targetId ? `${recordId}:${targetId}` : `${recordId}:*`)
}
</script>

<template>
  <el-table
    v-loading="loading"
    class="upload-record-table"
    :data="rows"
    row-key="rowKey"
    height="100%"
    stripe
  >
    <el-table-column label="记录" width="126" show-overflow-tooltip>
      <template #default="{ row }">
        <el-tooltip :content="row.recordId" placement="top"><span class="record-id">{{ shortId(row.recordId) }}</span></el-tooltip>
      </template>
    </el-table-column>
    <el-table-column label="任务" width="118" show-overflow-tooltip>
      <template #default="{ row }">{{ shortId(row.taskId || '-') }}</template>
    </el-table-column>
    <el-table-column label="远端任务" width="118" show-overflow-tooltip>
      <template #default="{ row }">{{ shortId(row.jobId || '-') }}</template>
    </el-table-column>
    <el-table-column prop="targetId" label="目标" width="86" />
    <el-table-column label="状态" width="118">
      <template #default="{ row }"><el-tag :type="statusTone(row.status)" effect="light">{{ statusLabel(row.status) }}</el-tag></template>
    </el-table-column>
    <el-table-column label="阶段" width="100" show-overflow-tooltip>
      <template #default="{ row }">{{ row.stage || '-' }}</template>
    </el-table-column>
    <el-table-column label="生成账号名" min-width="210" show-overflow-tooltip>
      <template #default="{ row }"><span class="generated-name">{{ row.generatedName || '-' }}</span></template>
    </el-table-column>
    <el-table-column label="远端 ID" width="90" show-overflow-tooltip>
      <template #default="{ row }">{{ row.remoteAccountId ?? '-' }}</template>
    </el-table-column>
    <el-table-column label="并发" width="64" align="right">
      <template #default="{ row }">{{ row.concurrency ?? '-' }}</template>
    </el-table-column>
    <el-table-column prop="attempts" label="尝试" width="62" align="right" />
    <el-table-column label="失败说明" min-width="190" show-overflow-tooltip>
      <template #default="{ row }"><span :class="{ danger: row.error || row.recordError }">{{ row.error || row.recordError || '-' }}</span></template>
    </el-table-column>
    <el-table-column label="更新时间" width="126">
      <template #default="{ row }">{{ dateLabel(row.updatedAt || row.recordCreatedAt) }}</template>
    </el-table-column>
    <el-table-column label="操作" width="142" fixed="right">
      <template #default="{ row }">
        <el-tooltip content="重传当前目标" placement="top">
          <el-button
            circle
            :icon="RefreshRight"
            :loading="isRetrying(row.recordId, row.targetId)"
            :disabled="!row.retryable || isRetrying(row.recordId, '*')"
            aria-label="重传当前目标"
            @click="emit('retry', row.recordId, row.targetId)"
          />
        </el-tooltip>
        <el-button
          v-if="row.firstForRecord && row.hasRetryableTargets"
          link
          type="primary"
          :loading="isRetrying(row.recordId, '*')"
          @click="emit('retryAll', row.recordId)"
        >全部失败</el-button>
      </template>
    </el-table-column>
    <template #empty><ContentEmptyState description="暂无 Pixel 上传记录" /></template>
  </el-table>
</template>

<style scoped>
.upload-record-table { width: 100%; height: 100%; min-height: 0; }
.record-id,
.generated-name { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; }
.danger { color: var(--el-color-danger); }
</style>
