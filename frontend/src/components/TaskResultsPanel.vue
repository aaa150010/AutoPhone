<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { CopyDocument, Document, Key, View } from '@element-plus/icons-vue'
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
  activeView?: 'pending' | 'running' | 'all'
}>(), { openingMailboxUrls: () => [], loadingMailboxPasswords: () => [], loadingMailboxTotps: () => [], activeView: 'pending' })
const emit = defineEmits<{
  copyAccount: [RuntimeTask]
  mailboxPassword: [RuntimeTask]
  mailboxTotp: [RuntimeTask]
  mailboxUrl: [RuntimeTask]
  freeSecret: [{ kind: 'token' | 'password' | 'totp' | 'proxy' | 'credential'; tasks: RuntimeTask[] }]
  freeTwofaRetry: [RuntimeTask]
  'update:activeView': ['pending' | 'running' | 'all']
  counts: [{ pending: number; running: number; all: number }]
}>()

const detailsOpen = ref(false)
const selectedTaskKey = ref('')
const acceptedVerificationKeys = ref(new Set<string>())
const previousPendingKeys = ref<Set<string> | null>(null)
const selectedFreeTasks = ref<RuntimeTask[]>([])

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
const visibleTasks = computed(() => props.activeView === 'pending'
  ? pendingTasks.value
  : props.activeView === 'running' ? runningTasks.value : props.tasks)
const selectedTask = computed(() => props.tasks.find(row => taskRowKey(row) === selectedTaskKey.value) || null)
const visibleFreeTasks = computed(() => visibleTasks.value.filter(task => task.run_mode === 'free_register'))

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
  if (pendingTasks.value.length > 0 && hasNewPending && props.activeView !== 'pending') emit('update:activeView', 'pending')
  previousPendingKeys.value = pendingKeys
  if (props.activeView === 'pending' && pendingTasks.value.length === 0) emit('update:activeView', 'running')
}, { deep: true, immediate: true })

watch([pendingTasks, runningTasks], () => {
  emit('counts', { pending: pendingTasks.value.length, running: runningTasks.value.length, all: props.tasks.length })
}, { immediate: true })

function markVerificationAccepted(row: RuntimeTask) {
  acceptedVerificationKeys.value = new Set(acceptedVerificationKeys.value).add(verificationKey(row))
  if (props.activeView === 'pending' && pendingTasks.value.length === 0) emit('update:activeView', 'running')
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
  if (value === 'twofa_pending') return '2FA 待重试'
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

function selectFreeTasks(rows: RuntimeTask[]) {
  selectedFreeTasks.value = rows.filter(row => row.run_mode === 'free_register')
}

function emitFreeSecret(kind: 'token' | 'password' | 'totp' | 'proxy' | 'credential', rows: RuntimeTask[]) {
  emit('freeSecret', { kind, tasks: rows.filter(row => row.run_mode === 'free_register') })
}
</script>

<template>
  <div class="task-results">
    <div v-if="visibleFreeTasks.length" class="free-actions">
      <span>Free 记录 {{ visibleFreeTasks.length }} 条</span>
      <el-button size="small" :disabled="!visibleFreeTasks.some(row => row.result?.has_access_token)" @click="emitFreeSecret('token', visibleFreeTasks)">复制当前页 Token</el-button>
      <el-button size="small" :disabled="!selectedFreeTasks.length" @click="emitFreeSecret('token', selectedFreeTasks)">复制选中 Token</el-button>
      <el-button size="small" :disabled="!selectedFreeTasks.length" @click="emitFreeSecret('credential', selectedFreeTasks)">复制选中凭据</el-button>
    </div>
    <el-table class="task-table" :data="visibleTasks" :row-key="taskRowKey" stripe height="100%" @selection-change="selectFreeTasks">
      <el-table-column type="selection" width="42" reserve-selection />
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
        <template #default="{ row }"><el-tooltip v-if="row.run_mode === 'free_register' && row.result?.has_credential" content="复制注册密码" placement="top"><el-button link :icon="Key" aria-label="复制注册密码" @click="emitFreeSecret('password', [row])" /></el-tooltip><el-tooltip v-else-if="row.has_mailbox_password" content="复制邮箱密码" placement="top"><el-button link :icon="Key" :loading="loadingMailboxPasswords.includes(row.task_id)" aria-label="复制邮箱密码" @click="emit('mailboxPassword', row)" /></el-tooltip><span v-else class="muted">-</span></template>
      </el-table-column>
      <el-table-column label="2FA" width="62" align="center">
        <template #default="{ row }"><el-tooltip v-if="row.run_mode === 'free_register' && row.result?.has_credential" content="复制注册 2FA 密钥" placement="top"><el-button link :icon="CopyDocument" aria-label="复制注册 2FA 密钥" @click="emitFreeSecret('totp', [row])" /></el-tooltip><el-tooltip v-else-if="row.has_totp" content="复制临时 2FA 验证码" placement="top"><el-button link :icon="CopyDocument" :loading="loadingMailboxTotps.includes(row.task_id)" aria-label="复制临时 2FA 验证码" @click="emit('mailboxTotp', row)" /></el-tooltip><span v-else class="muted">-</span></template>
      </el-table-column>
      <el-table-column label="Token / 代理" width="108" align="center"><template #default="{ row }"><template v-if="row.run_mode === 'free_register'"><el-button v-if="row.result?.has_access_token" link @click="emitFreeSecret('token', [row])">Token</el-button><el-button v-if="row.proxy_masked" link @click="emitFreeSecret('proxy', [row])">代理</el-button><span v-if="!row.result?.has_access_token && !row.proxy_masked" class="muted">-</span></template><span v-else class="muted">-</span></template></el-table-column>
      <el-table-column label="当前阶段 / 结果" min-width="340">
        <template #default="{ row }"><div class="result-cell"><TaskProgressCell :progress="row.progress" :timing="row.timing" :now-seconds="nowSeconds" :status="row.status" /><el-tag class="result-tag" :type="statusType(row.status)">{{ statusLabel(row.status) }}</el-tag></div></template>
      </el-table-column>
      <el-table-column label="待处理事项" min-width="280" show-overflow-tooltip>
        <template #default="{ row }"><el-tooltip v-if="row.failure" :content="failureTooltip(row)" placement="top"><span class="failure-detail"><span class="failure-node">{{ row.failure.node_label }}</span>{{ failureCause(row) }}</span></el-tooltip><el-button v-else-if="row.run_mode === 'free_register' && row.status === 'twofa_pending'" link type="warning" @click="emit('freeTwofaRetry', row)">重试 2FA</el-button><TaskVerificationInput v-else-if="shouldShowManualVerification(row) && !acceptedVerificationKeys.has(verificationKey(row))" :task-id="row.task_id" :request="row.manual_verification" :now-seconds="nowSeconds" @accepted="markVerificationAccepted(row)" /><span v-else class="muted">-</span></template>
      </el-table-column>
      <el-table-column label="操作" width="70" fixed="right" align="center"><template #default="{ row }"><el-tooltip content="查看任务链路详情" placement="top"><el-button link :icon="Document" aria-label="查看任务链路详情" @click="openDetails(row)" /></el-tooltip></template></el-table-column>
      <template #empty><ContentEmptyState /></template>
    </el-table>
  </div>
  <TaskDetailsDrawer v-model="detailsOpen" :task="selectedTask" :now-seconds="nowSeconds" />
</template>

<style scoped>
.task-results { display: flex; flex-direction: column; width: 100%; height: 100%; min-height: 0; }
.free-actions { display: flex; align-items: center; gap: 6px; min-height: 42px; padding: 0 10px; border-bottom: 1px solid var(--workspace-border); color: var(--el-text-color-secondary); font-size: 12px; }
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
