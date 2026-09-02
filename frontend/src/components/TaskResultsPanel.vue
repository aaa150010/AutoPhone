<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { CopyDocument, Document, Key, Loading, View } from '@element-plus/icons-vue'
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
import {
  ACCOUNT_BANNED_DISPLAY_MESSAGE,
  freeFailureCause,
  freeFailureDetails,
  freeFailureNodeIdentity,
  isCurrentAccountBanned,
  isRetryResolved,
} from '../utils/freeFailure'

const props = withDefaults(defineProps<{
  tasks: RuntimeTask[]
  openingMailboxUrls?: readonly string[]
  loadingMailboxPasswords?: readonly string[]
  loadingMailboxTotps?: readonly string[]
  loadingMailboxLatestCodes?: readonly string[]
  loadingAccountEmails?: readonly string[]
  activeView?: 'pending' | 'running' | 'all'
}>(), { openingMailboxUrls: () => [], loadingMailboxPasswords: () => [], loadingMailboxTotps: () => [], loadingMailboxLatestCodes: () => [], loadingAccountEmails: () => [], activeView: 'pending' })
const emit = defineEmits<{
  copyAccount: [RuntimeTask]
  mailboxPassword: [RuntimeTask]
  mailboxTotp: [RuntimeTask]
  mailboxUrl: [RuntimeTask]
  mailboxLatestCode: [RuntimeTask]
  freeSecret: [{ kind: 'token' | 'password' | 'totp' | 'credential'; tasks: RuntimeTask[] }]
  freeTwofaRetry: [RuntimeTask]
  diagnostic: [RuntimeTask]
  copyDiagnosticId: [string]
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

function statusLabel(status?: string, row?: RuntimeTask) {
  const value = String(status || '').toLowerCase()
  if (row && isRetryResolved(row.retry_resolved)) return '已由重试解决'
  if (value === 'account_banned' || (row && isAccountBanned(row))) return ACCOUNT_BANNED_DISPLAY_MESSAGE
  if (value === 'success') return '成功'
  if (value === 'failed') return '失败'
  if (value === 'retryable_infra') return '基础设施可重试'
  if (value === 'retryable_email') return '邮箱可重试'
  if (value === 'repair_pending') return '待修复'
  if (value === 'email_damaged') return '邮箱不可用'
  if (value === 'twofa_pending') return '2FA 待重试'
  if (value === 'stopped' || value === 'stopped_before_start') return '停止'
  return value ? '运行中' : '-'
}

function statusType(status?: string, row?: RuntimeTask) {
  const value = String(status || '').toLowerCase()
  if (row && isRetryResolved(row.retry_resolved)) return 'success'
  if (value === 'account_banned' || (row && isAccountBanned(row))) return 'danger'
  if (value === 'success') return 'success'
  if (failedTaskStatuses.has(value)) return 'danger'
  if (value.startsWith('stopped')) return 'info'
  return 'warning'
}

function failureCause(row: RuntimeTask) {
  return freeFailureCause(row.failure, { retryResolved: row.retry_resolved })
}

function isAccountBanned(row: RuntimeTask) {
  return isCurrentAccountBanned(row.status, row.failure, row.retry_resolved)
}

function failureIdentity(row: RuntimeTask) {
  return freeFailureNodeIdentity(row.failure)
}

function failureTooltip(row: RuntimeTask) {
  if (isAccountBanned(row)) return ACCOUNT_BANNED_DISPLAY_MESSAGE
  const details = freeFailureDetails(row.failure, { includeNode: true })
  return isRetryResolved(row.retry_resolved)
    ? ['历史失败已由重试解决', ...details].join(' · ')
    : details.join(' · ')
}

function isHistoricalDriver(row: RuntimeTask) {
  const driver = String((row as any)?.driver || '').trim().toLowerCase()
  return Boolean(driver) && driver !== 'protocol' && driver !== 'camoufox'
}

function openDetails(row: RuntimeTask) {
  selectedTaskKey.value = taskRowKey(row)
  detailsOpen.value = true
}

function selectFreeTasks(rows: RuntimeTask[]) {
  selectedFreeTasks.value = rows.filter(row => row.run_mode === 'free_register')
}

function emitFreeSecret(kind: 'token' | 'password' | 'totp' | 'credential', rows: RuntimeTask[]) {
  emit('freeSecret', { kind, tasks: rows.filter(row => row.run_mode === 'free_register') })
}
</script>

<template>
  <div class="task-results">
    <div v-if="visibleFreeTasks.length" class="free-actions">
      <span>Free 记录 {{ visibleFreeTasks.length }} 条</span>
      <el-button size="small" :disabled="!visibleFreeTasks.some(row => row.result?.has_access_token)" @click="emitFreeSecret('token', visibleFreeTasks)">复制当前页 Token</el-button>
      <el-button size="small" :disabled="!selectedFreeTasks.some(row => row.result?.has_access_token)" @click="emitFreeSecret('token', selectedFreeTasks)">复制选中 Token</el-button>
      <el-button size="small" :disabled="!selectedFreeTasks.some(row => row.result?.has_credential)" @click="emitFreeSecret('credential', selectedFreeTasks)">复制选中凭据</el-button>
    </div>
    <el-table class="task-table" :data="visibleTasks" :row-key="taskRowKey" stripe height="100%" @selection-change="selectFreeTasks">
      <el-table-column type="selection" width="42" reserve-selection />
      <el-table-column type="index" label="序号" width="58" align="center" fixed="left" />
      <el-table-column label="邮箱" min-width="154">
        <template #default="{ row }">
          <el-tooltip v-if="row.email || row.account" :content="String(row.email || row.account)" placement="top"><button type="button" class="copyable-account" @click="emit('copyAccount', row)"><span>{{ row.email || row.account }}</span><el-icon v-if="row.run_mode === 'free_register'" :class="{ 'is-loading': loadingAccountEmails.includes(row.task_id) }"><Loading v-if="loadingAccountEmails.includes(row.task_id)" /><CopyDocument v-else /></el-icon></button></el-tooltip>
          <span v-else>-</span>
        </template>
      </el-table-column>
      <el-table-column label="密码" width="66" align="center">
        <template #default="{ row }"><el-tooltip v-if="row.run_mode === 'free_register' && row.result?.has_password" content="复制注册密码" placement="top"><el-button link :icon="Key" aria-label="复制注册密码" @click="emitFreeSecret('password', [row])" /></el-tooltip><el-tooltip v-else-if="row.has_mailbox_password" content="复制邮箱密码" placement="top"><el-button link :icon="Key" :loading="loadingMailboxPasswords.includes(row.task_id)" aria-label="复制邮箱密码" @click="emit('mailboxPassword', row)" /></el-tooltip><span v-else class="muted">-</span></template>
      </el-table-column>
      <el-table-column label="2FA" width="62" align="center">
        <template #default="{ row }"><el-tooltip v-if="row.run_mode === 'free_register' && row.result?.has_totp" content="复制注册 2FA 密钥" placement="top"><el-button link :icon="CopyDocument" aria-label="复制注册 2FA 密钥" @click="emitFreeSecret('totp', [row])" /></el-tooltip><el-tooltip v-else-if="row.has_totp" content="复制临时 2FA 验证码" placement="top"><el-button link :icon="CopyDocument" :loading="loadingMailboxTotps.includes(row.task_id)" aria-label="复制临时 2FA 验证码" @click="emit('mailboxTotp', row)" /></el-tooltip><span v-else class="muted">-</span></template>
      </el-table-column>
      <el-table-column label="当前阶段 / 结果" min-width="340">
        <template #default="{ row }"><div class="result-cell"><TaskProgressCell :progress="row.progress" :timing="row.timing" :now-seconds="nowSeconds" :status="row.status" /><el-tag class="result-tag" :type="statusType(row.status, row)">{{ statusLabel(row.status, row) }}</el-tag></div></template>
      </el-table-column>
      <el-table-column label="待处理事项" min-width="280" show-overflow-tooltip>
        <template #default="{ row }"><span v-if="isRetryResolved(row.retry_resolved)" class="muted">已由重试解决</span><div v-else-if="row.failure" class="failure-actions"><el-tooltip :content="failureTooltip(row)" placement="top"><span class="failure-detail" :class="{ 'account-banned-detail': isAccountBanned(row) }"><template v-if="isAccountBanned(row)">{{ ACCOUNT_BANNED_DISPLAY_MESSAGE }}</template><template v-else><span class="failure-node">{{ failureIdentity(row).label || failureIdentity(row).code }}<code v-if="failureIdentity(row).showCode">{{ failureIdentity(row).code }}</code></span>{{ failureCause(row) }}</template></span></el-tooltip><el-button v-if="!isHistoricalDriver(row) && row.run_mode === 'free_register' && row.status === 'twofa_pending'" link type="warning" @click="emit('freeTwofaRetry', row)">重试 2FA</el-button></div><el-button v-else-if="!isHistoricalDriver(row) && row.run_mode === 'free_register' && row.status === 'twofa_pending'" link type="warning" @click="emit('freeTwofaRetry', row)">重试 2FA</el-button><TaskVerificationInput v-else-if="!isHistoricalDriver(row) && shouldShowManualVerification(row) && !acceptedVerificationKeys.has(verificationKey(row))" :task-id="row.task_id" :request="row.manual_verification" :now-seconds="nowSeconds" @accepted="markVerificationAccepted(row)" /><span v-else class="muted">-</span></template>
      </el-table-column>
      <el-table-column label="操作" width="150" fixed="right" align="center"><template #default="{ row }"><div class="task-operation-cell"><el-tooltip content="查看任务详情"><el-button link :icon="Document" aria-label="查看任务详情" @click="openDetails(row)" /></el-tooltip><el-tooltip content="打开取件网页"><el-button link :icon="View" :loading="openingMailboxUrls.includes(row.task_id)" aria-label="打开取件网页" @click="emit('mailboxUrl', row)" /></el-tooltip><el-tooltip content="提取并复制最新验证码"><el-button link :icon="CopyDocument" :loading="loadingMailboxLatestCodes.includes(row.task_id)" aria-label="提取并复制最新验证码" @click="emit('mailboxLatestCode', row)" /></el-tooltip><el-tooltip content="复制账号 Token"><el-button link :icon="CopyDocument" aria-label="复制账号 Token" @click="emitFreeSecret('token', [row])" /></el-tooltip><el-tooltip content="打开故障日志"><el-button link :icon="View" aria-label="打开故障日志" @click="emit('diagnostic', row)" /></el-tooltip></div></template></el-table-column>
      <template #empty><ContentEmptyState /></template>
    </el-table>
  </div>
  <TaskDetailsDrawer v-model="detailsOpen" :task="selectedTask" :now-seconds="nowSeconds" @diagnostic="emit('diagnostic', $event)" @copy-diagnostic-id="emit('copyDiagnosticId', $event)" />
</template>

<style scoped>
.task-results { display: flex; flex-direction: column; width: 100%; height: 100%; min-height: 0; }
.free-actions { display: flex; align-items: center; gap: 6px; min-height: 42px; padding: 0 10px; border-bottom: 1px solid var(--workspace-border); color: var(--el-text-color-secondary); font-size: 12px; }
.task-table { width: 100%; flex: 1; min-height: 0; }
.task-table :deep(.el-table__cell) { padding-top: 4px; padding-bottom: 4px; }
.copyable-account { display: flex; align-items: center; max-width: 100%; gap: 5px; overflow: hidden; padding: 0; border: 0; background: transparent; color: var(--el-color-primary); font: inherit; text-align: left; cursor: copy; }
.copyable-account > span { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.copyable-account > .el-icon { flex: 0 0 auto; color: var(--el-color-primary); }
.copyable-account:focus-visible { outline: 2px solid var(--el-color-primary-light-5); outline-offset: 2px; border-radius: 2px; }
.result-cell { display: flex; align-items: center; min-width: 0; gap: 8px; white-space: nowrap; }
.result-cell :deep(.el-tooltip__trigger) { display: block; min-width: 0; flex: 1 1 auto; overflow: hidden; }
.result-cell :deep(.progress-cell) { min-width: 0; overflow: hidden; text-overflow: ellipsis; }
.result-cell :deep(.progress-cell span) { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.result-tag { flex: 0 0 auto; margin-top: 0; }
.task-operation-cell { display: inline-flex; align-items: center; justify-content: center; gap: 0; min-width: 0; white-space: nowrap; }
.task-operation-cell :deep(.el-button) { width: 25px; height: 25px; margin-left: 0; padding: 4px; }
.failure-actions { display: flex; align-items: center; min-width: 0; gap: 6px; }
.failure-detail { display: inline-flex; max-width: 100%; gap: 6px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.failure-node { flex: none; color: var(--el-color-danger); font-weight: 600; }
.failure-node code { margin-left: 4px; color: var(--el-text-color-secondary); font-size: 10px; font-weight: 500; }
.muted { color: var(--el-text-color-secondary); }
</style>
