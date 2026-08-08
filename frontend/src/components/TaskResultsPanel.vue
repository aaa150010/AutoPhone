<script setup lang="ts">
import { View } from '@element-plus/icons-vue'
import ContentEmptyState from './ContentEmptyState.vue'
import TaskProgressCell from './TaskProgressCell.vue'
import { useTaskProgressClock } from '../composables/useTaskProgressClock'
import type { RuntimeTask } from '../types/api'

const props = withDefaults(defineProps<{
  tasks: RuntimeTask[]
  openingMailboxUrls?: readonly string[]
}>(), {
  openingMailboxUrls: () => [],
})
const emit = defineEmits<{
  copyAccount: [RuntimeTask]
  mailboxUrl: [RuntimeTask]
}>()
const nowSeconds = useTaskProgressClock(() => props.tasks)

function taskTooltip(row: RuntimeTask) {
  const details = []
  if (row.batch_id) details.push(`运行批次 ${row.batch_id}`)
  if (Number(row.ordinal) > 0) details.push(`批内序号 ${Math.floor(Number(row.ordinal))}`)
  return details.join(' · ') || `任务 ${row.task_id}`
}

function taskRowKey(row: RuntimeTask) {
  return `${String(row.batch_id || 'legacy')}::${row.task_id}`
}

function statusLabel(status?: string) {
  const value = String(status || '').toLowerCase()
  if (value === 'success') return '成功'
  if (value === 'failed') return '失败'
  if (value === 'account_banned') return '账号封禁'
  if (value === 'stopped' || value === 'stopped_before_start') return '已停止'
  if (['retryable_infra', 'retryable_email', 'repair_pending', 'email_damaged'].includes(value)) return '未成功'
  return value ? '运行中' : '-'
}

function statusType(status?: string) {
  const value = String(status || '').toLowerCase()
  if (value === 'success') return 'success'
  if (value === 'failed' || value === 'email_damaged' || value === 'account_banned') return 'danger'
  if (value === 'stopped' || value === 'stopped_before_start') return 'info'
  return 'warning'
}

function failureCause(row: RuntimeTask) {
  const failure = row.failure
  if (!failure) {
    const value = String(row.error || row.reason || '').trim()
    return value.toLowerCase() === 'sub2_uploaded' ? '-' : value || '-'
  }
  const message = String(failure.public_message || '').trim()
  const prefix = `${failure.node_label}失败：`
  return message.startsWith(prefix) ? message.slice(prefix.length) : message || '-'
}

function failureTooltip(row: RuntimeTask) {
  const failure = row.failure
  if (!failure) return ''
  const codes = [failure.node_code, failure.error_code, failure.provider_code].filter(Boolean).join(' / ')
  const technical = String(failure.technical_summary || '').trim()
  return technical ? `${codes} · ${technical}` : codes
}
</script>

<template>
  <el-table class="task-table" :data="tasks" :row-key="taskRowKey" stripe height="100%">
    <el-table-column label="任务" width="135">
      <template #default="{ row }">
        <el-tooltip :content="taskTooltip(row)" placement="top">
          <span class="task-id">{{ row.task_id }}</span>
        </el-tooltip>
      </template>
    </el-table-column>
    <el-table-column label="账号" min-width="205">
      <template #default="{ row }">
        <el-tooltip v-if="row.account || row.email" content="点击复制账号或邮箱" placement="top">
          <button
            type="button"
            class="copyable-account"
            aria-label="复制账号或邮箱"
            @click="emit('copyAccount', row)"
          >{{ row.account || row.email }}</button>
        </el-tooltip>
        <span v-else>-</span>
      </template>
    </el-table-column>
    <el-table-column label="取件 URL" width="92" align="center">
      <template #default="{ row }">
        <el-tooltip v-if="row.has_mailbox_url" content="打开取件网页" placement="top">
          <el-button
            link
            :icon="View"
            :loading="openingMailboxUrls.includes(row.task_id)"
            :disabled="openingMailboxUrls.includes(row.task_id)"
            aria-label="打开取件网页"
            @click="emit('mailboxUrl', row)"
          />
        </el-tooltip>
        <span v-else class="muted">-</span>
      </template>
    </el-table-column>
    <el-table-column label="运行状态" width="190">
      <template #default="{ row }">
        <TaskProgressCell :progress="row.progress" :timing="row.timing" :now-seconds="nowSeconds" />
      </template>
    </el-table-column>
    <el-table-column label="状态" width="95">
      <template #default="{ row }">
        <el-tag :type="statusType(row.status)">{{ statusLabel(row.status) }}</el-tag>
      </template>
    </el-table-column>
    <el-table-column label="说明" min-width="220" show-overflow-tooltip>
      <template #default="{ row }">
        <el-tooltip v-if="row.failure" :content="failureTooltip(row)" placement="top">
          <span class="failure-detail">
            <span class="failure-node">{{ row.failure.node_label }}</span>
            <span>{{ failureCause(row) }}</span>
          </span>
        </el-tooltip>
        <span v-else>{{ failureCause(row) }}</span>
      </template>
    </el-table-column>
    <template #empty><ContentEmptyState /></template>
  </el-table>
</template>

<style scoped>
.task-table { height: 100%; min-height: 0; }
.task-id {
  display: block;
  overflow: hidden;
  color: var(--el-text-color-regular);
  font-variant-numeric: tabular-nums;
  text-overflow: ellipsis;
  white-space: nowrap;
  cursor: help;
}
.copyable-account {
  display: block;
  max-width: 100%;
  overflow: hidden;
  padding: 0;
  border: 0;
  background: transparent;
  color: var(--el-color-primary);
  font: inherit;
  text-align: left;
  text-overflow: ellipsis;
  white-space: nowrap;
  cursor: copy;
}
.copyable-account:focus-visible { outline: 2px solid var(--el-color-primary-light-5); outline-offset: 2px; border-radius: 2px; }
.failure-detail { display: inline-flex; max-width: 100%; align-items: center; gap: 6px; }
.failure-node { flex: none; color: var(--el-color-danger); font-weight: 600; }
.failure-detail > span:last-child { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.muted { color: var(--el-text-color-secondary); }
</style>
