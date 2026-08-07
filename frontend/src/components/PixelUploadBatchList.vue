<script setup lang="ts">
import { List } from '@element-plus/icons-vue'
import ContentEmptyState from './ContentEmptyState.vue'
import WorkspacePanel from './WorkspacePanel.vue'
import type { PixelUploadBatch } from '../types/api'

const props = defineProps<{
  batches: PixelUploadBatch[]
  loading: boolean
  page: number
  pageSize: number
  total: number
  selectedBatchId: string
}>()

const emit = defineEmits<{
  select: [PixelUploadBatch]
  page: [number]
  pageSize: [number]
}>()

function dateLabel(value: number | string | null | undefined) {
  if (value == null || value === '') return '-'
  const numeric = Number(value)
  const date = Number.isFinite(numeric)
    ? new Date(numeric < 10_000_000_000 ? numeric * 1000 : numeric)
    : new Date(String(value))
  return Number.isNaN(date.getTime())
    ? '-'
    : date.toLocaleString('zh-CN', {
        hour12: false,
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
      })
}

function statusLabel(status: string) {
  const labels: Record<string, string> = {
    processing: '处理中',
    success: '全部成功',
    partial: '部分失败',
    failed: '失败',
    empty: '空批次',
  }
  return labels[String(status || '').toLowerCase()] || status || '未知'
}

function statusTone(status: string): 'success' | 'warning' | 'danger' | 'info' {
  const value = String(status || '').toLowerCase()
  if (value === 'success') return 'success'
  if (value === 'processing') return 'warning'
  if (['failed', 'partial'].includes(value)) return 'danger'
  return 'info'
}

function rowClassName({ row }: { row: PixelUploadBatch }) {
  return row.batch_id === props.selectedBatchId ? 'selected-batch-row' : ''
}
</script>

<template>
  <WorkspacePanel class="batch-panel" title="上传批次" :icon="List" fill body-padding="none">
    <div class="batch-table-region">
      <el-table
        v-loading="loading"
        :data="batches"
        :row-class-name="rowClassName"
        height="100%"
        row-key="batch_id"
        stripe
        @row-click="emit('select', $event)"
      >
        <el-table-column label="开始时间" width="116">
          <template #default="{ row }">{{ dateLabel(row.batch_started_at) }}</template>
        </el-table-column>
        <el-table-column prop="batch_id" label="批次" min-width="145" show-overflow-tooltip />
        <el-table-column label="来源账号" width="94" align="right">
          <template #default="{ row }">{{ row.source.completed }}/{{ row.source.total }}</template>
        </el-table-column>
        <el-table-column label="目标投递" width="104" align="right">
          <template #default="{ row }">{{ row.deliveries.completed }}/{{ row.deliveries.total }}</template>
        </el-table-column>
        <el-table-column label="状态" width="96">
          <template #default="{ row }"><el-tag :type="statusTone(row.status)" effect="light">{{ statusLabel(row.status) }}</el-tag></template>
        </el-table-column>
        <template #empty><ContentEmptyState description="暂无 Pixel 上传批次" /></template>
      </el-table>
      <el-pagination
        :current-page="page"
        :page-size="pageSize"
        class="pager"
        background
        layout="total, sizes, prev, pager, next"
        :page-sizes="[10, 20, 50]"
        :total="total"
        @update:current-page="emit('page', $event)"
        @update:page-size="emit('pageSize', $event)"
      />
    </div>
  </WorkspacePanel>
</template>

<style scoped>
.batch-panel { min-width: 0; min-height: 0; }
.batch-table-region { display: grid; grid-template-rows: minmax(0, 1fr) 42px; width: 100%; height: 100%; min-height: 0; padding: 7px 8px 0; }
.pager { justify-content: flex-end; min-width: 0; border-top: 1px solid var(--workspace-border); }
.batch-panel :deep(.el-table__row) { cursor: pointer; }
.batch-panel :deep(.selected-batch-row > td.el-table__cell) { background: var(--el-color-primary-light-9) !important; }
</style>
