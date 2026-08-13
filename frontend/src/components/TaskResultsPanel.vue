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
const previousPendingKeys = ref<Set<string> | null>(null)

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
  const pendingKeys = new Set(pendingTasks.value.map(task => (
    `${taskRowKey(task)}::${shouldShowManualVerification(task) ? verificationKey(task) : 'failure'}`
  )))
  const firstSnapshot = previousPendingKeys.value === null
  const hasNewPending = firstSnapshot
    || [...pendingKeys].some(key => !previousPendingKeys.value?.has(key))
  if (pendingTasks.value.length > 0 && hasNewPending) activeView.value = 'pending'
  previousPendingKeys.value = pendingKeys
  if (activeView.value === 'pending' && pendingTasks.value.length === 0) activeView.value = 'running'
}, { deep: true, immediate: true })

function markVerificationAccepted(row: RuntimeTask) {
  acceptedVerificationKeys.value = new Set(acceptedVerificationKeys.value).add(verificationKey(row))
  if (activeView.value === 'pending' && pendingTasks.value.length === 0) activeView.value = 'running'
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
    <Teleport to="#task-summary-tabs-target">
      <div class="task-summary-tabs" role="tablist" aria-label="任务结果分类">
        <button type="button" role="tab" :aria-selected="activeView === 'pending'" :class="{ active: activeView === 'pending', urgent: pendingTasks.length }" @click="activeView = 'pending'"><el-icon><WarningFilled /></el-icon><span>待处理</span><b>{{ pendingTasks.length }}</b></button>
        <button type="button" role="tab" :aria-selected="activeView === 'running'" :class="{ active: activeView === 'running' }" @click="activeView = 'running'"><el-icon><VideoPlay /></el-icon><span>运行中</span><b>{{ runningTasks.length }}</b></button>
        <button type="button" role="tab" :aria-selected="activeView === 'all'" :class="{ active: activeView === 'all' }" @click="activeView = 'all'"><el-icon><Tickets /></el-icon><span>全部</span><b>{{ props.tasks.length }}</b></button>
      </div>
    </Teleport>
    <el-table class="task-table" :data="visibleTasks" :row-key="taskRowKey" stripe height="100%">
      <el-table-column label="邮箱" min-width="154">
        <template #default="{ row }">
          <el-tooltip v-if="row.email || row.account" content="点击复制邮箱" placement="top"><button type="button" class="copyable-account" @click="emit('copyAccount', row)">{{ row.email || row.account }}</button></el-tooltip>
          <span v-else>-</span>
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
      <el-table-column label="当前阶段 / 结果" min-width="340">
        <template #default="{ row }"><div class="result-cell"><TaskProgressCell :progress="row.progress" :timing="row.timing" :now-seconds="nowSeconds" :status="row.status" /><el-tag class="result-tag" :type="statusType(row.status)">{{ statusLabel(row.status) }}</el-tag></div></template>
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
.task-summary-tabs { display: grid; grid-template-columns: repeat(3, 120px); align-content: center; justify-content: start; gap: 3px; height: 34px; padding: 3px 0; background: transparent; pointer-events: auto; }
.task-summary-tabs button { display: inline-flex; align-items: center; justify-content: center; gap: 5px; min-width: 0; height: 26px; border: 1px solid transparent; border-radius: 4px; padding: 0 8px; background: transparent; color: #586a67; font-size: 12px; font-weight: 600; cursor: pointer; transition: border-color 0.15s ease, background-color 0.15s ease, color 0.15s ease, box-shadow 0.15s ease; }
.task-summary-tabs button:hover { background: #edf4f2; color: #0f6b5b; }
.task-summary-tabs button:focus-visible { outline: 2px solid #72b8a8; outline-offset: 1px; }
.task-summary-tabs button.active { border-color: #83bdae; background: #e8f4f0; color: #0b6757; font-weight: 700; box-shadow: 0 1px 2px rgb(15 107 91 / 10%); }
.task-summary-tabs button.urgent { color: #a52b3b; }
.task-summary-tabs button.active.urgent { border-color: #df9da5; background: #fff1f2; color: #9f2435; box-shadow: 0 1px 2px rgb(165 43 59 / 10%); }
.task-summary-tabs button .el-icon { width: 14px; height: 14px; font-size: 14px; }
.task-summary-tabs button.active b { background: #0f6b5b; color: #fff; }
.task-summary-tabs button.urgent b,
.task-summary-tabs button.active.urgent b { background: #c83f4f; color: #fff; }
.task-summary-tabs b { display: inline-grid; place-items: center; min-width: 18px; height: 16px; padding: 0 4px; border-radius: 8px; background: #e1e8e6; color: #52635f; font-size: 9px; font-variant-numeric: tabular-nums; }
.task-table { width: 100%; flex: 1; min-height: 0; }
.task-table :deep(.el-table__cell) { padding-top: 4px; padding-bottom: 4px; }
.copyable-account { display: block; max-width: 100%; overflow: hidden; padding: 0; border: 0; background: transparent; color: var(--el-color-primary); font: inherit; text-align: left; text-overflow: ellipsis; white-space: nowrap; cursor: copy; }
.copyable-account:focus-visible { outline: 2px solid var(--el-color-primary-light-5); outline-offset: 2px; border-radius: 2px; }
.result-cell { display: flex; align-items: center; min-width: 0; gap: 8px; white-space: nowrap; }
.result-cell :deep(.el-tooltip__trigger) { display: block; min-width: 0; flex: 1 1 auto; overflow: hidden; }
.result-cell :deep(.progress-cell) { min-width: 0; overflow: hidden; text-overflow: ellipsis; }
.result-cell :deep(.progress-cell span) { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.result-tag { flex: 0 0 auto; margin-top: 0; }
.failure-detail { display: inline-flex; max-width: 100%; gap: 6px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.failure-node { flex: none; color: var(--el-color-danger); font-weight: 600; }
.muted { color: var(--el-text-color-secondary); }
</style>
