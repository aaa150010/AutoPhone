<script setup lang="ts">
import ContentEmptyState from './ContentEmptyState.vue'
import TaskProgressCell from './TaskProgressCell.vue'
import { useTaskProgressClock } from '../composables/useTaskProgressClock'
import type { RuntimeTask } from '../types/api'

const props = defineProps<{ tasks: RuntimeTask[] }>()
const nowSeconds = useTaskProgressClock(() => props.tasks)

function statusLabel(status?: string) {
  const value = String(status || '').toLowerCase()
  if (value === 'success') return '成功'
  if (value === 'failed') return '失败'
  if (value === 'stopped' || value === 'stopped_before_start') return '已停止'
  if (['retryable_infra', 'retryable_email', 'repair_pending', 'email_damaged'].includes(value)) return '未成功'
  return value ? '运行中' : '-'
}

function statusType(status?: string) {
  const value = String(status || '').toLowerCase()
  if (value === 'success') return 'success'
  if (value === 'failed' || value === 'email_damaged') return 'danger'
  if (value === 'stopped' || value === 'stopped_before_start') return 'info'
  return 'warning'
}
</script>

<template>
  <el-table class="task-table" :data="tasks" row-key="task_id" size="small" stripe height="100%">
    <el-table-column prop="task_id" label="任务" width="135" show-overflow-tooltip />
    <el-table-column label="账号" min-width="205" show-overflow-tooltip>
      <template #default="{ row }">{{ row.account || row.email || '-' }}</template>
    </el-table-column>
    <el-table-column label="运行状态" width="190">
      <template #default="{ row }">
        <TaskProgressCell :progress="row.progress" :now-seconds="nowSeconds" />
      </template>
    </el-table-column>
    <el-table-column label="状态" width="95">
      <template #default="{ row }">
        <el-tag :type="statusType(row.status)" size="small">{{ statusLabel(row.status) }}</el-tag>
      </template>
    </el-table-column>
    <el-table-column label="说明" min-width="220" show-overflow-tooltip>
      <template #default="{ row }">{{ row.error || row.reason || '-' }}</template>
    </el-table-column>
    <template #empty><ContentEmptyState /></template>
  </el-table>
</template>

<style scoped>
.task-table { height: 100%; min-height: 0; }
</style>
