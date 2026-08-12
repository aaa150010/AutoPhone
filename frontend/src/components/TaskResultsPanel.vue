<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { CopyDocument, Document, Key, Tickets, VideoPlay, View, WarningFilled } from '@element-plus/icons-vue'
import ContentEmptyState from './ContentEmptyState.vue'
import TaskDetailsDrawer from './TaskDetailsDrawer.vue'
import TaskProgressCell from './TaskProgressCell.vue'
import TaskVerificationInput from './TaskVerificationInput.vue'
import { useTaskProgressClock } from '../composables/useTaskProgressClock'
import type { RuntimeTask } from '../types/api'
import {
  failedTaskStatuses,
  pendingTaskRows,
  runningTaskRows,
  taskNeedsVerification,
  taskVerificationKey,
} from '../utils/taskResultViews'

const props = withDefaults(defineProps<{
  tasks: RuntimeTask[]
  openingMailboxUrls?: readonly string[]
  loadingMailboxPasswords?: readonly string[]
  loadingMailboxTotps?: readonly string[]
}>(), { openingMailboxUrls: () => [], loadingMailboxPasswords: () => [], loadingMailboxTotps: () => [] })
const emit = defineEmits<{
  copyAccount: [RuntimeTask]
  mailboxPassword: [RuntimeTask]
  mailboxTotp: [RuntimeTask]
  mailboxUrl: [RuntimeTask]
}>()

type ViewMode = 'pending' | 'running' | 'all'
const activeView = ref<ViewMode>('pending')
const detailsOpen = ref(false)
const selectedTaskKey = ref('')
const acceptedVerificationKeys = ref(new Set<string>())
const autoOpenedBatch = ref('')

const nowSeconds = useTaskProgressClock(
  () => props.tasks,
  () => props.tasks.some(task => shouldShowManualVerification(task)),
)

function taskRowKey(row: RuntimeTask) {
  return `${String(row.batch_id || 'legacy')}::${row.task_id}`
}

function verificationKey(row: RuntimeTask) {
  return taskVerificationKey(row)
}

function shouldShowManualVerification(row: RuntimeTask) {
  return taskNeedsVerification(row)
}

const pendingTasks = computed(() => pendingTaskRows(props.tasks, acceptedVerificationKeys.value))
const runningTasks = computed(() => runningTaskRows(props.tasks, acceptedVerificationKeys.value))
const visibleTasks = computed(() => activeView.value === 'pending'
  ? pendingTasks.value
  : activeView.value === 'running' ? runningTasks.value : props.tasks)
const selectedTask = computed(() => props.tasks.find(row => taskRowKey(row) === selectedTaskKey.value) || null)

watch(() => props.tasks, (tasks) => {
  const current = new Set<string>()
  for (const task of tasks) {
    if (acceptedVerificationKeys.value.has(verificationKey(task)) && shouldShowManualVerification(task)) current.add(verificationKey(task))
  }
  acceptedVerificationKeys.value = current
  const batch = String(tasks.find(task => task.batch_id)?.batch_id || 'legacy')
  if (pendingTasks.value.length > 0 && autoOpenedBatch.value !== batch) {
    autoOpenedBatch.value = batch
    activeView.value = 'pending'
  }
  if (activeView.value === 'pending' && pendingTasks.value.length === 0) activeView.value = 'running'
}, { deep: true, immediate: true })

function markVerificationAccepted(row: RuntimeTask) {
  acceptedVerificationKeys.value = new Set(acceptedVerificationKeys.value).add(verificationKey(row))
  if (activeView.value === 'pending' && pendingTasks.value.length === 0) activeView.value = 'running'
}

function taskTooltip(row: RuntimeTask) {
  const details = []
  if (row.batch_id) details.push(`运行批次 ${row.batch_id}`)
  if (Number(row.ordinal) > 0) details.push(`批内序号 ${Math.floor(Number(row.ordinal))}`)
  return details.join(' · ') || `任务 ${row.task_id}`
}

function statusLabel(status?: string) {
  const value = String(status || '').toLowerCase()
  if (value === 'success') return '成功'
  if (value === 'failed') return '失败'
  if (value === 'retryable_infra') return '基础设施可重试'
  if (value === 'retryable_email') return '邮箱可重试'
  if (value === 'repair_pending') return '待修复'
  if (value === 'email_damaged') return '邮箱不可用'
  if (value === 'account_banned') return '封禁'
  if (value === 'stopped' || value === 'stopped_before_start') return '停止'
  return value ? '运行中' : '-'
}

function statusType(status?: string) {
  const value = String(status || '').toLowerCase()
  if (value === 'success') return 'success'
  if (failedTaskStatuses.has(value)) return 'danger'
  if (value.startsWith('stopped')) return 'info'
  return 'warning'
}

function failureCause(row: RuntimeTask) {
  const failure = row.failure
  if (!failure) return String(row.error || row.reason || '').trim() || '-'
  const message = String(failure.public_message || '').trim()
  const prefix = `${failure.node_label}失败：`
  return message.startsWith(prefix) ? message.slice(prefix.length) : message || '-'
}

function failureTooltip(row: RuntimeTask) {
  const failure = row.failure
  if (!failure) return ''
  return [failure.node_code, failure.error_code, failure.provider_code, failure.technical_summary, failure.action_hint].filter(Boolean).join(' · ')
}

function openDetails(row: RuntimeTask) {
  selectedTaskKey.value = taskRowKey(row)
  detailsOpen.value = true
}
</script>

<template>
  <div class="task-results">
    <div class="task-summary-tabs" role="tablist" aria-label="任务结果分类">
      <button type="button" role="tab" :aria-selected="activeView === 'pending'" :class="{ active: activeView === 'pending', urgent: pendingTasks.length }" @click="activeView = 'pending'"><el-icon><WarningFilled /></el-icon><span>待处理</span><b>{{ pendingTasks.length }}</b></button>
      <button type="button" role="tab" :aria-selected="activeView === 'running'" :class="{ active: activeView === 'running' }" @click="activeView = 'running'"><el-icon><VideoPlay /></el-icon><span>运行中</span><b>{{ runningTasks.length }}</b></button>
      <button type="button" role="tab" :aria-selected="activeView === 'all'" :class="{ active: activeView === 'all' }" @click="activeView = 'all'"><el-icon><Tickets /></el-icon><span>全部</span><b>{{ props.tasks.length }}</b></button>
    </div>
    <el-table class="task-table" :data="visibleTasks" :row-key="taskRowKey" stripe height="100%">
      <el-table-column label="邮箱" min-width="154">
        <template #default="{ row }">
          <el-tooltip v-if="row.email || row.account" content="点击复制邮箱" placement="top"><button type="button" class="copyable-account" @click="emit('copyAccount', row)">{{ row.email || row.account }}</button></el-tooltip>
          <span v-else>-</span>
          <small class="task-id" :title="taskTooltip(row)">{{ row.task_id }}</small>
        </template>
      </el-table-column>
      <el-table-column label="取件 URL" width="92" align="center">
        <template #default="{ row }"><el-tooltip v-if="row.has_mailbox_url" content="打开取件网页" placement="top"><el-button link :icon="View" :loading="openingMailboxUrls.includes(row.task_id)" @click="emit('mailboxUrl', row)">打开</el-button></el-tooltip><span v-else class="muted">-</span></template>
      </el-table-column>
      <el-table-column label="密码" width="66" align="center">
        <template #default="{ row }"><el-tooltip v-if="row.has_mailbox_password" content="复制密码" placement="top"><el-button link :icon="Key" :loading="loadingMailboxPasswords.includes(row.task_id)" aria-label="复制密码" @click="emit('mailboxPassword', row)" /></el-tooltip><span v-else class="muted">-</span></template>
      </el-table-column>
      <el-table-column label="2FA" width="62" align="center">
        <template #default="{ row }"><el-tooltip v-if="row.has_totp" content="复制临时 2FA 验证码" placement="top"><el-button link :icon="CopyDocument" :loading="loadingMailboxTotps.includes(row.task_id)" aria-label="复制临时 2FA 验证码" @click="emit('mailboxTotp', row)" /></el-tooltip><span v-else class="muted">-</span></template>
      </el-table-column>
      <el-table-column label="当前阶段 / 结果" min-width="250">
        <template #default="{ row }"><TaskProgressCell :progress="row.progress" :timing="row.timing" :now-seconds="nowSeconds" :status="row.status" /><el-tag class="result-tag" :type="statusType(row.status)">{{ statusLabel(row.status) }}</el-tag></template>
      </el-table-column>
      <el-table-column label="待处理事项" min-width="280" show-overflow-tooltip>
        <template #default="{ row }"><el-tooltip v-if="row.failure" :content="failureTooltip(row)" placement="top"><span class="failure-detail"><span class="failure-node">{{ row.failure.node_label }}</span>{{ failureCause(row) }}</span></el-tooltip><TaskVerificationInput v-else-if="shouldShowManualVerification(row) && !acceptedVerificationKeys.has(verificationKey(row))" :task-id="row.task_id" :request="row.manual_verification" :now-seconds="nowSeconds" @accepted="markVerificationAccepted(row)" /><span v-else class="muted">-</span></template>
      </el-table-column>
      <el-table-column label="操作" width="70" fixed="right" align="center"><template #default="{ row }"><el-tooltip content="查看任务链路详情" placement="top"><el-button link :icon="Document" aria-label="查看任务链路详情" @click="openDetails(row)" /></el-tooltip></template></el-table-column>
      <template #empty><ContentEmptyState /></template>
    </el-table>
  </div>
  <TaskDetailsDrawer v-model="detailsOpen" :task="selectedTask" :now-seconds="nowSeconds" />
</template>

<style scoped>
.task-results { display: flex; flex-direction: column; width: 100%; height: 100%; min-height: 0; }
.task-summary-tabs { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1px; height: 48px; padding: 0; border: 1px solid #bdcbc6; border-bottom: 2px solid #93a7a0; background: #bdcbc6; }
.task-summary-tabs button { position: relative; display: inline-flex; align-items: center; justify-content: center; gap: 7px; min-width: 0; height: 46px; border: 0; border-top: 3px solid transparent; border-radius: 0; padding: 0 14px; background: #f5f8f7; color: #536174; font-size: 13px; font-weight: 650; cursor: pointer; transition: background-color 0.15s ease, color 0.15s ease; }
.task-summary-tabs button:hover { background: #e6f1ed; color: #0f6b5b; }
.task-summary-tabs button.active { border-top-color: #075e50; background: #167d6a; color: #fff; font-weight: 700; box-shadow: inset 0 -2px 0 rgb(0 0 0 / 12%); }
.task-summary-tabs button.urgent { background: #fff0f1; color: #b42335; }
.task-summary-tabs button.active.urgent { border-top-color: #8f1625; background: #c83f4f; color: #fff; }
.task-summary-tabs button .el-icon { width: 17px; height: 17px; font-size: 17px; }
.task-summary-tabs button.active b { background: #fff; color: #075e50; }
.task-summary-tabs button.active.urgent b { color: #a51d2d; }
.task-summary-tabs button.urgent:not(.active) b { background: #c83f4f; color: #fff; }
.task-summary-tabs b { display: inline-grid; place-items: center; min-width: 24px; height: 20px; padding: 0 6px; border-radius: 10px; background: #dce4e1; color: #405064; font-size: 11px; }
.task-table { width: 100%; flex: 1; min-height: 0; }
.copyable-account { display: block; max-width: 100%; overflow: hidden; padding: 0; border: 0; background: transparent; color: var(--el-color-primary); font: inherit; text-align: left; text-overflow: ellipsis; white-space: nowrap; cursor: copy; }
.copyable-account:focus-visible { outline: 2px solid var(--el-color-primary-light-5); outline-offset: 2px; border-radius: 2px; }
.task-id { display: block; overflow: hidden; color: var(--el-text-color-secondary); font-size: 10px; line-height: 14px; text-overflow: ellipsis; white-space: nowrap; }
.result-tag { margin-top: 3px; }
.failure-detail { display: inline-flex; max-width: 100%; gap: 6px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.failure-node { flex: none; color: var(--el-color-danger); font-weight: 600; }
.muted { color: var(--el-text-color-secondary); }
</style>
