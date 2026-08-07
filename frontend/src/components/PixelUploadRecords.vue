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
  taskIds: string[]
  sourceCount: number
  batchId: string
  batchStartedAt: string | number | null
  sourceEmail: string
  recordError: string
  recordStatus: string
  recordCreatedAt: string | number | null
  firstForRecord: boolean
  targetCount: number
  hasRetryableTargets: boolean
}

const rows = computed<UploadRow[]>(() => props.records.flatMap((record) => {
  const targets: PixelUploadTargetRecord[] = record.targets.length ? record.targets : [{
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
    taskIds: record.taskIds,
    sourceCount: record.sourceCount,
    batchId: record.batchId,
    batchStartedAt: record.batchStartedAt,
    sourceEmail: record.sourceEmail,
    recordError: record.error,
    recordStatus: record.status,
    recordCreatedAt: record.createdAt,
    firstForRecord: index === 0,
    targetCount: targets.length,
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
  if (['failed', 'partial', 'retry_pending', 'pending_retry', 'import_failed', 'share_failed', 'source_unavailable'].includes(value)) return 'danger'
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
    : date.toLocaleString('zh-CN', {
        hour12: false,
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      })
}

function isRetrying(recordId: string, targetId?: string) {
  const keys = props.retryingKeys || []
  return keys.includes(targetId ? `${recordId}:${targetId}` : `${recordId}:*`)
}

function spanMethod({ row, column }: { row: UploadRow; column: { property?: string } }) {
  if (!['batchId', 'taskTime', 'recordStatus', 'sourceEmail'].includes(column.property || '')) return undefined
  return row.firstForRecord
    ? { rowspan: row.targetCount, colspan: 1 }
    : { rowspan: 0, colspan: 0 }
}
</script>

<template>
  <el-table
    v-loading="loading"
    class="upload-record-table"
    :data="rows"
    :span-method="spanMethod"
    row-key="rowKey"
    height="100%"
    stripe
  >
    <el-table-column prop="batchId" label="批次" width="218" show-overflow-tooltip>
      <template #default="{ row }">
        <el-tooltip :content="`任务 ${(row.taskIds || [row.taskId]).join(', ') || '-'} / 记录 ${row.recordId}`" placement="top">
          <span class="batch-id">{{ row.batchId || '-' }}</span>
        </el-tooltip>
      </template>
    </el-table-column>
    <el-table-column prop="taskTime" label="任务时间" width="172">
      <template #default="{ row }">{{ dateLabel(row.recordCreatedAt || row.batchStartedAt) }}</template>
    </el-table-column>
    <el-table-column prop="recordStatus" label="任务状态" width="118">
      <template #default="{ row }"><el-tag :type="statusTone(row.recordStatus)" effect="light">{{ statusLabel(row.recordStatus) }}</el-tag></template>
    </el-table-column>
    <el-table-column prop="sourceEmail" label="初始邮箱名" min-width="230" show-overflow-tooltip>
      <template #default="{ row }">
        <span class="email-name">{{ row.sourceCount > 1 ? `${row.sourceCount} 个同域账号` : row.sourceEmail || '-' }}</span>
      </template>
    </el-table-column>
    <el-table-column prop="generatedName" label="上传后邮箱名" min-width="310" show-overflow-tooltip>
      <template #default="{ row }">
        <span class="target-id">{{ row.targetId }}</span>
        <span class="email-name">{{ row.generatedName || '-' }}</span>
      </template>
    </el-table-column>
    <el-table-column label="失败说明" min-width="240" show-overflow-tooltip>
      <template #default="{ row }"><span :class="{ danger: row.error || row.recordError }">{{ row.error || row.recordError || '-' }}</span></template>
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
.batch-id,
.email-name { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; }
.target-id { display: inline-block; min-width: 58px; margin-right: 8px; color: var(--el-text-color-secondary); font-size: 11px; }
.danger { color: var(--el-color-danger); }
</style>
