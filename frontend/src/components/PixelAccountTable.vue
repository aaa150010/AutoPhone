<script setup lang="ts">
import { ref } from 'vue'
import ContentEmptyState from './ContentEmptyState.vue'
import type { PixelAccount } from '../types/api'

defineProps<{
  rows: PixelAccount[]
  loading?: boolean
  selectionDisabled?: boolean
}>()

const emit = defineEmits<{ select: [PixelAccount[]] }>()
const tableRef = ref<any>()

function clearSelection() {
  tableRef.value?.clearSelection()
}

function statusLabel(row: PixelAccount) {
  const status = String(row.status || '').toLowerCase()
  if (status === 'active') return '正常'
  if (status === 'rate_limited') return '额度受限'
  if (status === 'codex_quota_protected') return '配额保护'
  if (status === 'error') return '异常'
  if (status === 'disabled') return '已停用'
  return row.status || '未知'
}

function statusTone(row: PixelAccount): 'success' | 'warning' | 'danger' | 'info' {
  const status = String(row.status || '').toLowerCase()
  if (status === 'active') return 'success'
  if (status === 'rate_limited' || status === 'codex_quota_protected') return 'warning'
  if (status === 'error') return 'danger'
  return 'info'
}

function shareLabel(row: PixelAccount) {
  return String(row.shareMode || '').toLowerCase() === 'public' ? '公开' : '私有'
}

function dateLabel(value: string | null) {
  if (!value) return '-'
  const date = new Date(value)
  return Number.isNaN(date.getTime())
    ? '-'
    : date.toLocaleString('zh-CN', { hour12: false, month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

defineExpose({ clearSelection })
</script>

<template>
  <el-table
    ref="tableRef"
    v-loading="loading"
    class="pixel-account-table"
    :data="rows"
    row-key="id"
    height="100%"
    stripe
    @selection-change="emit('select', $event)"
  >
    <el-table-column type="selection" width="45" reserve-selection :selectable="() => !selectionDisabled" />
    <el-table-column prop="id" label="ID" width="76" />
    <el-table-column label="账号名" min-width="210" show-overflow-tooltip>
      <template #default="{ row }"><span class="account-name">{{ row.name || '-' }}</span></template>
    </el-table-column>
    <el-table-column label="套餐" width="82">
      <template #default="{ row }">{{ row.accountLevel || '-' }}</template>
    </el-table-column>
    <el-table-column label="状态" width="100">
      <template #default="{ row }"><el-tag :type="statusTone(row)" effect="light">{{ statusLabel(row) }}</el-tag></template>
    </el-table-column>
    <el-table-column label="共享" width="84">
      <template #default="{ row }">
        <el-tag :type="String(row.shareMode).toLowerCase() === 'public' ? 'success' : 'info'" effect="plain">
          {{ shareLabel(row) }}
        </el-tag>
      </template>
    </el-table-column>
    <el-table-column label="并发" width="82" align="right">
      <template #default="{ row }"><span class="numeric">{{ row.currentConcurrency || 0 }}/{{ row.concurrency || 0 }}</span></template>
    </el-table-column>
    <el-table-column label="凭据" width="104" show-overflow-tooltip>
      <template #default="{ row }">{{ row.credentialsStatus || '-' }}</template>
    </el-table-column>
    <el-table-column label="异常说明" min-width="190" show-overflow-tooltip>
      <template #default="{ row }"><span :class="{ danger: row.errorMessage }">{{ row.errorMessage || '-' }}</span></template>
    </el-table-column>
    <el-table-column label="更新时间" width="126">
      <template #default="{ row }">{{ dateLabel(row.updatedAt) }}</template>
    </el-table-column>
    <template #empty><ContentEmptyState /></template>
  </el-table>
</template>

<style scoped>
.pixel-account-table { width: 100%; height: 100%; min-height: 0; }
.account-name { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
.numeric { font-variant-numeric: tabular-nums; }
.danger { color: var(--el-color-danger); }
</style>
