<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { ArrowDown, CircleCheck, CircleClose, CopyDocument, Delete, Document, Key, Link, Lock, MoreFilled, Refresh, RefreshLeft, RefreshRight, Setting, Tickets, VideoPause, VideoPlay, Warning } from '@element-plus/icons-vue'
import { closeFreeCamoufoxDebug, deleteFreeTasks, freeBatchRetry, getFreeConfig, getFreeState, preflightFree, rerunFreeTask, retryFreePassword, retryFreeTwofa, startFree, startFreePlanCheck, stopFree, type FreeConfig, type FreeState } from '../api/client'
import WorkspacePanel from '../components/WorkspacePanel.vue'
import ContentEmptyState from '../components/ContentEmptyState.vue'
import FreeTaskLogDialog from '../components/FreeTaskLogDialog.vue'
import TaskVerificationInput from '../components/TaskVerificationInput.vue'
import TaskProgressCell from '../components/TaskProgressCell.vue'
import StateDot from '../components/StateDot.vue'
import {
  ACCOUNT_BANNED_DISPLAY_MESSAGE,
  freeFailureCause,
  freeFailureDetails,
  freeFailureNodeIdentity,
  isCurrentAccountBanned,
  isRetryResolved,
} from '../utils/freeFailure'
import { useTaskProgressClock } from '../composables/useTaskProgressClock'
import { useColumnWidths } from '../composables/useColumnWidths'
import { useFreeTaskRowActions } from '../composables/useFreeTaskRowActions'
import {
  automaticOtpRemaining as automaticOtpRemainingPure,
  canRetryPassword,
  displayTaskStatus,
  isHistoricalDriver,
  taskCreatedText,
  taskDriverLabel,
  taskIncidentId,
  taskNeedsExistingPassword,
  taskPasswordLabel,
  taskPasswordType,
  taskPlanLabel,
  taskPlanType,
  taskRowClass,
  taskStatusType,
  taskTwofaLabel,
  taskTwofaType,
} from '../utils/freeTaskDisplay'

const defaultConfig: FreeConfig = {
  driver: 'protocol', flow_profile: 'reference_20260823', proxy_allocation_mode: 'healthy_random', target_count: 1, concurrency: 3, email_code_timeout: 90, account_password: 'Aa150010150010', auto_set_password: false, auto_set_2fa: true,
  mailbox_network_mode: 'local_proxy', mailbox_proxy_url: 'http://127.0.0.1:7897',
  mailbox_request_retries: 3, mailbox_retry_backoff_seconds: 1,
  proxy_probe_url: 'https://chatgpt.com/', proxy_socks5_dns_mode: 'remote', protocol: { node_runner: '', sentinel_version: '20260219f9f6', sentinel_timeout: 90, network_timeout: 20, network_preflight_retries: 3, security_challenge_wait_seconds: 60, anonymous_warmup: true, authenticated_warmup: true },
  proxy_default_scheme: 'socks5',
  camoufox: {
    debug_mode: true, headless: true, pool_size: 2, max_contexts_per_browser: 3, context_start_interval_ms: 175,
    startup_concurrency: 4, block_images: true, registration_timeout_seconds: 600,
    context_close_timeout_seconds: 15, browser_recycle_timeout_seconds: 45,
    browser_recycle_drain_timeout_seconds: 20, max_registrations_per_browser: 12,
    browser_launch_attempts: 3, existing_account_login: true,
  },
}

const emit = defineEmits<{ navigate: [string] }>()
const config = reactive<FreeConfig>(structuredClone(defaultConfig))
const state = ref<FreeState>({ running: false, tasks: [], summary: {}, pool: {} })
const selectedTaskId = ref('')
const taskSearch = ref('')
const taskStatusFilter = ref('all')
const taskDriverFilter = ref('')
const selectedTasks = ref<any[]>([])
const taskTable = ref<any>()
const logDialogOpen = ref(false)
const logDialog = ref<{ refresh: (options?: { forceLatest?: boolean; silent?: boolean }) => Promise<void> }>()
const loading = ref(false)
const busy = ref<'preflight' | 'start' | 'stop' | 'close-debug' | ''>('')
const planBusy = ref('')
const quickTargetCount = ref(defaultConfig.target_count)
const quickConcurrency = ref(defaultConfig.concurrency)
const quickRunDirty = ref(false)
const running = computed(() => Boolean(state.value.running))
const debugWindowsOpen = computed(() => Number(state.value.camoufox_debug?.open_contexts || 0) > 0)
const nowSeconds = useTaskProgressClock(() => state.value.tasks || [], () => Boolean(state.value.running))
const { colWidth: taskColWidth, handleHeaderDragend: onTaskHeaderDragend } = useColumnWidths('gptphone.table.widths.free-register')
function automaticOtpRemaining(task: any) {
  return automaticOtpRemainingPure(task, nowSeconds.value)
}

const {
  loadingEmailTaskIds,
  loadingLatestCodeTaskIds,
  openingMailboxUrlTaskIds,
  copyTaskSecret,
  copyTaskTokens,
  copyTaskToken,
  copyTaskEmail,
  openTaskMailboxUrl,
  copyTaskLatestCode,
} = useFreeTaskRowActions()
let timer = 0

const visibleTasks = computed(() => (state.value.tasks || []).slice().sort((a, b) => {
  const batchOrder = Number(b.created_at || 0) - Number(a.created_at || 0)
  if (batchOrder) return batchOrder
  const ordinalOrder = Number(a.ordinal || 0) - Number(b.ordinal || 0)
  return ordinalOrder || String(a.task_id || '').localeCompare(String(b.task_id || ''))
}))
const filteredTasks = computed(() => {
  const query = taskSearch.value.trim().toLowerCase()
  return visibleTasks.value.filter(task => {
    const haystack = [task.email, task.task_id, task.failure?.node_label, task.failure?.node_code].join(' ').toLowerCase()
    return (!query || haystack.includes(query))
      && (taskStatusFilter.value === 'all' || (taskStatusFilter.value === 'active' ? ['queued', 'running'].includes(task.status) : task.status === taskStatusFilter.value && !isRetryResolved(task.retry_resolved)))
      && (!taskDriverFilter.value || task.driver === taskDriverFilter.value)
  })
})
const taskCounts = computed(() => {
  const count = (status: string) => visibleTasks.value.filter(task => task.status === status && !isRetryResolved(task.retry_resolved)).length
  return { total: visibleTasks.value.length, running: count('running') + count('queued'), success: count('success') + count('partial_success'), partial: count('partial_success'), failed: count('failed'), pending: count('twofa_pending'), rerun: count('pending_rerun'), stopped: count('stopped') }
})
const statusFilters = computed(() => [
  { value: 'all', label: '全部', count: taskCounts.value.total, tone: 'info' },
  { value: 'active', label: '排队/运行', count: taskCounts.value.running, tone: 'primary' },
  { value: 'success', label: '成功', count: taskCounts.value.success - taskCounts.value.partial, tone: 'success' },
  { value: 'partial_success', label: '部分成功', count: taskCounts.value.partial, tone: 'warning' },
  { value: 'failed', label: '失败', count: taskCounts.value.failed, tone: 'danger' },
  { value: 'twofa_pending', label: '2FA', count: taskCounts.value.pending, tone: 'warning' },
  { value: 'pending_rerun', label: '待重跑', count: taskCounts.value.rerun, tone: 'warning' },
  { value: 'stopped', label: '已停止', count: taskCounts.value.stopped, tone: 'info' },
] as { value: string; label: string; count: number; tone: string }[])

function handleCopyCommand(command: string) {
  if (command === 'filtered-token') return void copyTaskTokens(filteredTasks.value)
  const kind = command as 'token' | 'password' | 'totp' | 'credential'
  const labels = { token: 'Token', password: '密码', totp: 'TOTP', credential: '完整凭据' } as const
  void copyTaskSecret(kind, selectedTasks.value, labels[kind])
}
const selectedTask = computed(() => visibleTasks.value.find(task => task.task_id === selectedTaskId.value))
function mergeConfig(value: any, forceQuickRun = false) {
  if (!value || typeof value !== 'object') return
  Object.assign(config, value)
  // Do not let removed legacy fields re-enter the reactive draft when loading
  // a pre-migration config from the server. Spreading this draft is
  // used for every new preflight/start request.
  const draft = config as Record<string, unknown>
  delete draft.roxybrowser
  delete draft.roxy_circuit_failure_threshold
  delete draft.roxy_circuit_recovery_seconds
  delete draft.roxy_api_key
  delete draft.roxy_workspace_id
  const proxySelection = draft.proxy_selection
  if (proxySelection && typeof proxySelection === 'object') {
    delete (proxySelection as Record<string, unknown>).roxybrowser
  }
  Object.assign(config.protocol, value.protocol || {})
  Object.assign(config.camoufox, value.camoufox || {})
  // Old persisted configs may still report a removed driver. Keep the editor
  // valid while historical task rows retain their original read-only metadata.
  if (!['protocol', 'camoufox'].includes(String(config.driver || '').trim().toLowerCase())) config.driver = 'protocol'
  config.target_count = Math.min(200, Math.max(1, Number(config.target_count) || 1))
  config.concurrency = Math.min(16, Math.max(1, Number(config.concurrency) || 1))
  if (forceQuickRun || !quickRunDirty.value) {
    quickTargetCount.value = config.target_count
    quickConcurrency.value = config.concurrency
  }
}
function quickRunConfig(): FreeConfig {
  const draft = {
    ...config,
    target_count: Math.min(200, Math.max(1, Number(quickTargetCount.value) || 1)),
    concurrency: Math.min(16, Math.max(1, Number(quickConcurrency.value) || 1)),
  }
  const sanitized = draft as FreeConfig & Record<string, unknown>
  delete sanitized.roxybrowser
  delete sanitized.roxy_circuit_failure_threshold
  delete sanitized.roxy_circuit_recovery_seconds
  delete sanitized.roxy_api_key
  delete sanitized.roxy_workspace_id
  return sanitized
}

function markQuickRunDirty() {
  quickRunDirty.value = true
}

async function refresh() {
  try {
    const result = await getFreeState()
    const serverRunning = Boolean(result.state?.running)
    if (serverRunning) quickRunDirty.value = false
    mergeConfig(result.config, serverRunning)
    state.value = result.state || state.value
    if (logDialogOpen.value && selectedTaskId.value) {
      await logDialog.value?.refresh({ silent: true })
    }
  } catch (error: any) {
    if (!loading.value) ElMessage.error(error?.message || 'Free 状态刷新失败')
  }
}

async function load() {
  loading.value = true
  try {
    const result = await getFreeConfig()
    mergeConfig(result.config, true)
    state.value = result.state || state.value
  } catch (error: any) {
    ElMessage.error(error?.message || 'Free 配置加载失败')
  } finally {
    loading.value = false
  }
}

async function preflight() {
  busy.value = 'preflight'
  try {
    const result = await preflightFree(quickRunConfig())
    state.value = result.state || state.value
    ElMessage.success(`预检通过：${Number(result.result?.target_count || 0)} 个邮箱，健康池 ${Number(result.result?.proxies || 0)} 个代理`)
  } catch (error: any) {
    ElMessage.error(error?.message || 'Free 预检失败')
  } finally {
    busy.value = ''
  }
}

async function start() {
  busy.value = 'start'
  try {
    const submittedConfig = quickRunConfig()
    const result = await startFree(submittedConfig)
    config.target_count = submittedConfig.target_count
    config.concurrency = submittedConfig.concurrency
    quickTargetCount.value = submittedConfig.target_count
    quickConcurrency.value = submittedConfig.concurrency
    quickRunDirty.value = false
    state.value = result.state || state.value
    ElMessage.success('Free 注册已启动')
  } catch (error: any) {
    ElMessage.error(error?.message || 'Free 注册启动失败')
  } finally {
    busy.value = ''
  }
}

async function stop() {
  busy.value = 'stop'
  try {
    const result = await stopFree()
    state.value = result.state || state.value
    ElMessage.success('已请求停止 Free 注册')
  } catch (error: any) {
    ElMessage.error(error?.message || '停止 Free 注册失败')
  } finally {
    busy.value = ''
  }
}

async function closeDebugWindows() {
  if (!debugWindowsOpen.value || busy.value) return
  busy.value = 'close-debug'
  try {
    const result = await closeFreeCamoufoxDebug()
    state.value = result.state || state.value
    ElMessage.success(`已关闭 ${Number(result.closed_contexts || 0)} 个调试窗口`)
  } catch (error: any) {
    ElMessage.error(error?.message || '关闭 Camoufox 调试窗口失败')
  } finally {
    busy.value = ''
  }
}

function openTaskLog(task: any) {
  selectedTaskId.value = String(task?.task_id || '')
  logDialogOpen.value = true
}

function openIncidentCenter(value: string) {
  const incidentId = String(value || '').trim()
  if (incidentId) emit('navigate', `/logs?incident_id=${encodeURIComponent(incidentId)}`)
}

function openTaskIncident(task: any) {
  const incidentId = taskIncidentId(task)
  if (!incidentId) {
    ElMessage.info('该任务尚未生成故障日志')
    return
  }
  openIncidentCenter(incidentId)
}

async function rerunTaskAction(task: any) {
  if (isHistoricalDriver(task)) {
    ElMessage.info('历史链路任务仅支持查看，不能重跑')
    return
  }
  if (!['failed', 'stopped', 'pending_rerun'].includes(String(task?.status || ''))) {
    ElMessage.info('该任务当前没有可重跑的失败节点')
    return
  }
  await rerunTask(task)
}

async function retryTwofaTaskAction(task: any) {
  if (isHistoricalDriver(task)) {
    ElMessage.info('历史链路任务不支持 2FA 重试')
    return
  }
  if (String(task?.status || '') !== 'twofa_pending') {
    ElMessage.info('该任务当前没有待重试的 2FA 节点')
    return
  }
  await retryTwofaTask(task)
}

async function retryPasswordTaskAction(task: any) {
  if (!canRetryPassword(task)) {
    ElMessage.info('该任务当前没有可重试的密码设置节点')
    return
  }
  await retryPasswordTask(task)
}

async function handleTaskAction(command: string, task: any) {
  if (command === 'details') return openTaskLog(task)
  if (command === 'mailbox_url') return openTaskMailboxUrl(task)
  if (command === 'latest_code') return copyTaskLatestCode(task)
  if (command === 'token') return copyTaskToken(task)
  if (command === 'incident') return openTaskIncident(task)
  if (command === 'rerun') return rerunTaskAction(task)
  if (command === 'twofa') return retryTwofaTaskAction(task)
  if (command === 'password') return retryPasswordTaskAction(task)
}

function handleTaskSelection(rows: any[]) {
  selectedTasks.value = rows
}

async function deleteSelectedTasks() {
  const taskIds = selectedTasks.value.map(task => String(task?.task_id || '')).filter(Boolean)
  if (!taskIds.length) return
  try {
    await ElMessageBox.confirm(
      `确定删除选中的 ${taskIds.length} 条 Free 任务记录及对应账号日志吗？邮箱池和注册结果会保留。`,
      '删除 Free 任务记录',
      { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  loading.value = true
  taskTable.value?.clearSelection()
  selectedTasks.value = []
  try {
    const result = await deleteFreeTasks(taskIds)
    state.value = result.state || state.value
    if (taskIds.includes(selectedTaskId.value)) {
      logDialogOpen.value = false
      selectedTaskId.value = ''
    }
    await refresh()
    ElMessage.success(`已删除 ${Number(result.deleted || 0)} 条 Free 任务记录`)
  } catch (error: any) {
    ElMessage.error(error?.message || 'Free 任务记录删除失败')
  } finally {
    taskTable.value?.clearSelection()
    selectedTasks.value = []
    loading.value = false
  }
}

async function rerunTask(task: any) {
  const taskId = String(task?.task_id || '')
  if (isHistoricalDriver(task) || !taskId || !['failed', 'stopped', 'pending_rerun'].includes(String(task?.status || ''))) return
  try {
    await ElMessageBox.confirm(
      `仅当该账号已恢复为可用时才会重跑。确定重跑 ${task.email || taskId} 吗？`,
      '重跑 Free 账号',
      { type: 'warning', confirmButtonText: '开始重跑', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  loading.value = true
  try {
    const result = await rerunFreeTask(taskId)
    state.value = result.state || state.value
    ElMessage.success(`已加入重试队列 ${result.task?.task_id || result.batch_id || ''}`)
    await refresh()
  } catch (error: any) {
    ElMessage.error(error?.message || 'Free 账号重跑失败')
  } finally {
    loading.value = false
  }
}

async function retryTwofaTask(task: any) {
  const taskId = String(task?.task_id || task?.row_id || '')
  if (isHistoricalDriver(task) || !taskId || String(task?.status || '') !== 'twofa_pending' || loading.value) return
  loading.value = true
  try {
    const result = await retryFreeTwofa(taskId)
    if (result.state) state.value = result.state as FreeState
    ElMessage.info(`已加入 2FA 重试队列 ${result.task?.task_id || ''}`)
    await refresh()
  } catch (error: any) {
    ElMessage.error(error?.message || '2FA 重试失败')
  } finally {
    loading.value = false
  }
}

async function retryPasswordTask(task: any) {
  const taskId = String(task?.task_id || task?.row_id || '')
  if (!canRetryPassword(task) || !taskId || loading.value) return
  loading.value = true
  try {
    const result = await retryFreePassword(taskId)
    if (result.state) state.value = result.state
    ElMessage.info(`已加入密码重试队列 ${result.task?.task_id || ''}`)
    await refresh()
  } catch (error: any) {
    ElMessage.error(error?.message || '密码设置重试失败')
  } finally {
    loading.value = false
  }
}

async function batchRetryCurrentNode() {
  const eligible = selectedTasks.value.filter(task => !isHistoricalDriver(task) && (
    ['failed', 'stopped', 'pending_rerun', 'twofa_pending'].includes(String(task?.status || ''))
    || canRetryPassword(task)
  ))
  if (!eligible.length) {
    ElMessage.warning('请选择失败、密码或 2FA 待重试任务')
    return
  }
  try {
    const result = await freeBatchRetry(eligible.map(task => String(task.task_id)).filter(Boolean))
    selectedTasks.value = []
    taskTable.value?.clearSelection()
    ElMessage.success(`已接受 ${Number(result.accepted_count || 0)} 条，跳过 ${Number(result.skipped_count || 0)} 条，拒绝 ${Number(result.rejected_count || 0)} 条`)
    await refresh()
  } catch (error: any) {
    ElMessage.error(error?.message || '批量重试失败')
  }
}

async function refreshPlan(task: any) {
  const rowId = String(task?.row_id || '')
  if (!rowId || !task?.result?.has_access_token || String(task?.result?.plan_check_status || '').toLowerCase() !== 'failed' || planBusy.value) return
  planBusy.value = String(task.task_id || rowId)
  try {
    await startFreePlanCheck([rowId])
    ElMessage.info('套餐查询已加入队列')
    await refresh()
  } catch (error: any) {
    ElMessage.error(error?.message || '重新查询套餐失败')
  } finally {
    planBusy.value = ''
  }
}

function taskFailureCause(task: any) {
  return freeFailureCause(task?.failure, { retryResolved: task?.retry_resolved })
}

function taskIsAccountBanned(task: any) {
  return isCurrentAccountBanned(task?.status, task?.failure, task?.retry_resolved)
}

function taskFailureDetails(task: any) {
  return freeFailureDetails(task?.failure)
}

function taskFailureNode(task: any) {
  return freeFailureNodeIdentity(task?.failure)
}

function scheduleRefresh() {
  timer = window.setTimeout(async () => {
    await refresh()
    scheduleRefresh()
  }, running.value || logDialogOpen.value ? 1000 : 3000)
}

onMounted(async () => {
  await load()
  scheduleRefresh()
})
onUnmounted(() => window.clearTimeout(timer))
</script>

<template>
  <div class="free-page">
    <div class="task-view">
      <WorkspacePanel fill body-padding="none">
        <div class="task-panel">
          <div class="task-start-bar">
            <el-tag effect="plain">{{ config.driver === 'camoufox' ? 'Camoufox' : '全协议' }}</el-tag>
            <label class="quick-run-field"><span>注册数量</span><el-input-number v-model="quickTargetCount" class="quick-run-number" :min="1" :max="200" controls-position="right" :disabled="running || Boolean(busy)" @update:model-value="markQuickRunDirty" /></label>
            <label class="quick-run-field"><span>并发</span><el-input-number v-model="quickConcurrency" class="quick-run-number" :min="1" :max="16" controls-position="right" :disabled="running || Boolean(busy)" @update:model-value="markQuickRunDirty" /></label>
            <span class="muted task-start-meta">可用邮箱 {{ Number(state.pool?.available || 0) }} · 代理 {{ Number(state.pool?.proxies || 0) }}</span>
            <el-button size="small" :icon="CircleCheck" :loading="busy === 'preflight'" :disabled="running" @click="preflight">预检</el-button>
            <el-button size="small" type="primary" :icon="VideoPlay" :loading="busy === 'start'" :disabled="running || !Number(state.pool?.available || 0)" @click="start">开始注册</el-button>
            <el-button size="small" type="danger" plain :icon="VideoPause" :loading="busy === 'stop'" :disabled="!running" @click="stop">停止</el-button>
            <el-tooltip content="关闭保留的 Camoufox 调试窗口" placement="top">
              <el-button size="small" plain :icon="CircleClose" :loading="busy === 'close-debug'" :disabled="!debugWindowsOpen || Boolean(busy)" aria-label="关闭 Camoufox 调试窗口" @click="closeDebugWindows">关闭调试窗口</el-button>
            </el-tooltip>
            <el-button size="small" :icon="Setting" @click="emit('navigate', '/settings#free-register')">运行配置</el-button>
          </div>
          <div class="task-filter-row">
            <div class="task-summary-strip" role="group" aria-label="任务状态筛选">
              <button v-for="item in statusFilters" :key="item.value" type="button" class="summary-cell is-filter" :class="{ 'is-active': taskStatusFilter === item.value, [`tone-${item.tone}`]: true }" :aria-pressed="taskStatusFilter === item.value" @click="taskStatusFilter = item.value">
                <span>{{ item.label }}</span><strong>{{ item.count }}</strong>
              </button>
            </div>
            <el-input v-model="taskSearch" size="small" clearable class="task-search" placeholder="搜索邮箱、任务 ID 或失败节点" />
            <el-select v-model="taskDriverFilter" size="small" clearable placeholder="链路" class="task-driver-filter"><el-option label="全协议" value="protocol" /><el-option label="Camoufox" value="camoufox" /></el-select>
            <div class="task-actions">
              <span class="muted">已选 {{ selectedTasks.length }} 个</span>
              <el-button v-if="['success', 'partial_success', 'twofa_pending', 'pending_rerun'].includes(taskStatusFilter)" size="small" type="warning" :icon="Refresh" :disabled="!selectedTasks.some(task => !isHistoricalDriver(task) && (['failed', 'stopped', 'pending_rerun', 'twofa_pending'].includes(String(task.status || '')) || canRetryPassword(task)))" @click="batchRetryCurrentNode">按当前失败节点批量重试</el-button>
              <el-dropdown trigger="click" @command="(command: string) => handleCopyCommand(command)">
                <el-button size="small" :icon="CopyDocument" :disabled="!selectedTasks.length" aria-label="批量复制账号凭据">复制<el-icon class="el-icon--right"><ArrowDown /></el-icon></el-button>
                <template #dropdown>
                  <el-dropdown-menu>
                    <el-dropdown-item command="token"><el-icon><Key /></el-icon>复制 Token</el-dropdown-item>
                    <el-dropdown-item command="password"><el-icon><Lock /></el-icon>复制密码</el-dropdown-item>
                    <el-dropdown-item command="totp"><el-icon><Tickets /></el-icon>复制 TOTP</el-dropdown-item>
                    <el-dropdown-item command="credential"><el-icon><Document /></el-icon>复制完整凭据</el-dropdown-item>
                    <el-dropdown-item command="filtered-token" divided :disabled="!filteredTasks.some(task => task.result?.has_access_token)"><el-icon><CopyDocument /></el-icon>复制当前筛选 Token</el-dropdown-item>
                  </el-dropdown-menu>
                </template>
              </el-dropdown>
              <el-button size="small" type="danger" plain :icon="Delete" :disabled="!selectedTasks.length || loading" @click="deleteSelectedTasks">删除选中</el-button>
              <el-button size="small" :icon="Refresh" @click="refresh">刷新任务</el-button>
            </div>
          </div>
          <el-table ref="taskTable" :data="filteredTasks" row-key="task_id" height="100%" size="small" border :row-class-name="taskRowClass" @header-dragend="(newWidth: number, oldWidth: number, column: any) => onTaskHeaderDragend(newWidth, oldWidth, column)" @selection-change="handleTaskSelection">
            <el-table-column type="selection" width="42" reserve-selection />
            <el-table-column label="账号" :min-width="taskColWidth('账号', 280)" show-overflow-tooltip>
              <template #default="{ row }">
                <div class="account-cell">
                  <el-tooltip v-if="row.email" :content="`${String(row.email)}${row.task_id ? ` · 任务 ${row.task_id}` : ''}`" placement="top"><el-button link class="email-copy" :loading="loadingEmailTaskIds.includes(String(row.task_id || ''))" @click.stop="copyTaskEmail(row)"><strong>{{ row.email }}</strong><el-icon v-if="!loadingEmailTaskIds.includes(String(row.task_id || ''))"><CopyDocument /></el-icon></el-button></el-tooltip>
                  <span v-else>-</span>
                  <span class="account-subline">{{ taskDriverLabel(row.driver) }}<template v-if="taskCreatedText(row)"> · {{ taskCreatedText(row) }}</template></span>
                </div>
              </template>
            </el-table-column>
            <el-table-column label="验证码" :width="taskColWidth('验证码', 110)" align="center"><template #default="{ row }"><TaskVerificationInput v-if="!isHistoricalDriver(row) && row.manual_verification?.can_submit" :task-id="row.task_id" :request="row.manual_verification" :now-seconds="nowSeconds" /><span v-else-if="!isHistoricalDriver(row) && row.mailbox_verification?.phase === 'automatic'" class="automatic-otp-wait">自动取码 <strong>{{ automaticOtpRemaining(row) }}s</strong></span><span v-else class="muted">-</span></template></el-table-column>
            <el-table-column label="阶段 / 耗时" :min-width="taskColWidth('阶段 / 耗时', 230)"><template #default="{ row }"><TaskProgressCell :progress="row.progress" :timing="row.timing" :now-seconds="nowSeconds" :status="row.status" /></template></el-table-column>
            <el-table-column label="状态" :width="taskColWidth('状态', 122)" align="center" show-overflow-tooltip><template #default="{ row }"><el-tag size="small" :type="isRetryResolved(row.retry_resolved) ? 'success' : taskStatusType(row.status)">{{ displayTaskStatus(row) }}</el-tag></template></el-table-column>
            <el-table-column label="套餐" :width="taskColWidth('套餐', 90)" align="center" show-overflow-tooltip><template #default="{ row }"><el-tag size="small" :type="taskPlanType(row)" effect="plain">{{ taskPlanLabel(row) }}</el-tag><el-tooltip v-if="!isHistoricalDriver(row) && row.result?.has_access_token && String(row.result?.plan_check_status || '').toLowerCase() === 'failed'" content="重新查询套餐"><el-button link size="small" :icon="Refresh" :loading="planBusy === String(row.task_id || row.row_id)" :disabled="Boolean(planBusy)" aria-label="重新查询套餐" @click.stop="refreshPlan(row)" /></el-tooltip></template></el-table-column>
            <el-table-column label="凭据" :width="taskColWidth('凭据', 112)"><template #default="{ row }"><div class="credential-cell"><StateDot :tone="taskTwofaType(row)" :label="`2FA ${taskTwofaLabel(row)}`" /><StateDot :tone="taskPasswordType(row)" :label="`密码 ${taskPasswordLabel(row)}`" /></div></template></el-table-column>
            <el-table-column label="错误" :min-width="taskColWidth('错误', 320)">
              <template #default="{ row }">
                <el-tooltip placement="top" :disabled="!taskFailureDetails(row).length">
                  <template #content><div class="failure-tooltip"><span v-for="item in taskFailureDetails(row)" :key="item">{{ item }}</span></div></template>
                  <div class="failure-cell">
                    <span class="failure-summary"><template v-if="isRetryResolved(row.retry_resolved)"><strong class="resolved-text">已由重试解决</strong></template><template v-else-if="taskIsAccountBanned(row)"><strong>{{ ACCOUNT_BANNED_DISPLAY_MESSAGE }}<code>{{ taskFailureNode(row).code || 'account_banned' }}</code></strong></template><template v-else><strong v-if="taskFailureNode(row).label || taskFailureNode(row).code">{{ taskFailureNode(row).label || taskFailureNode(row).code }}<code v-if="taskFailureNode(row).showCode">{{ taskFailureNode(row).code }}</code></strong><span>{{ taskFailureCause(row) }}</span><span v-if="taskNeedsExistingPassword(row)" class="failure-action-hint">需补录真实密码后再处理；不会使用注册默认密码</span></template></span>
                  </div>
                </el-tooltip>
              </template>
            </el-table-column>
            <el-table-column label="操作" :width="taskColWidth('操作', 64)" align="center" fixed="right">
              <template #default="{ row }">
                <el-dropdown trigger="click" @command="(command: string) => handleTaskAction(command, row)">
                  <el-button link class="row-action-button" aria-label="打开任务操作菜单" title="打开任务操作菜单"><el-icon><MoreFilled /></el-icon></el-button>
                  <template #dropdown>
                    <el-dropdown-menu>
                      <el-dropdown-item command="details"><el-icon><Document /></el-icon>查看任务详情 / 日志</el-dropdown-item>
                      <el-dropdown-item command="mailbox_url"><el-icon><Link /></el-icon>打开取件网页</el-dropdown-item>
                      <el-dropdown-item command="latest_code"><el-icon><Tickets /></el-icon>提取并复制最新验证码</el-dropdown-item>
                      <el-dropdown-item command="token"><el-icon><Key /></el-icon>复制账号 Token</el-dropdown-item>
                      <el-dropdown-item command="incident"><el-icon><Warning /></el-icon>打开故障日志</el-dropdown-item>
                      <el-dropdown-item command="rerun"><el-icon><RefreshRight /></el-icon>重跑该账号</el-dropdown-item>
                      <el-dropdown-item command="twofa"><el-icon><RefreshLeft /></el-icon>重试 2FA</el-dropdown-item>
                      <el-dropdown-item command="password"><el-icon><Lock /></el-icon>重试密码</el-dropdown-item>
                    </el-dropdown-menu>
                  </template>
                </el-dropdown>
              </template>
            </el-table-column>
            <template #empty><ContentEmptyState /></template>
          </el-table>
        </div>
      </WorkspacePanel>
    </div>
    <FreeTaskLogDialog ref="logDialog" v-model="logDialogOpen" :task="selectedTask" />
  </div>
</template>

<style scoped>
.free-page { width: 100%; height: 100%; min-width: 0; min-height: 0; }
.muted { color: var(--el-text-color-secondary); font-size: 12px; }
.task-view { min-width: 0; min-height: 0; height: 100%; }
.task-view :deep(.workspace-panel) { height: 100%; }
.task-panel { display: grid; grid-template-rows: auto auto minmax(0, 1fr); gap: var(--workspace-gap); height: 100%; min-height: 0; padding: 10px; }
.task-start-bar, .task-filter-row { display: flex; align-items: center; gap: var(--workspace-gap); min-width: 0; }
.task-start-bar { min-height: 32px; }
.task-start-bar .task-start-meta { margin-right: auto; }
.quick-run-field { display: inline-flex; align-items: center; gap: 8px; color: var(--el-text-color-regular); font-size: 14px; white-space: nowrap; }
/* Keep numeric controls compact while preserving Element Plus' native
   keyboard, validation, and spinner behavior. */
.quick-run-field :deep(.quick-run-number) {
  --el-input-height: 30px;
  --el-input-inner-height: 28px;
  width: 112px;
  height: 30px;
  line-height: 28px;
}
.quick-run-field :deep(.quick-run-number .el-input__wrapper) {
  min-height: 30px;
  height: 30px;
  padding-left: 8px;
  padding-right: 34px;
}
.quick-run-field :deep(.quick-run-number .el-input__inner) {
  height: 28px;
  line-height: 28px;
  font-size: 14px;
  text-align: center;
}
.quick-run-field :deep(.quick-run-number .el-input-number__increase),
.quick-run-field :deep(.quick-run-number .el-input-number__decrease) {
  --el-input-number-controls-height: 15px;
  width: 26px;
}
.task-filter-row { flex-wrap: nowrap; align-items: center; }
.task-summary-strip { display: flex; align-items: stretch; flex: 0 1 auto; height: 30px; min-width: 0; border: 1px solid var(--workspace-border); border-radius: var(--workspace-radius); overflow: hidden; background: var(--workspace-surface); }
.summary-cell { display: flex; align-items: center; justify-content: center; gap: 6px; flex: 1 1 0; min-width: 0; padding: 0 10px; border: 0; border-right: 1px solid var(--workspace-border); background: transparent; white-space: nowrap; }
.summary-cell:last-child { border-right: 0; }
.summary-cell span { color: var(--el-text-color-secondary); font-size: 12px; line-height: 16px; }
.summary-cell strong { color: var(--el-text-color-primary); font-size: 14px; line-height: 18px; font-variant-numeric: tabular-nums; }
.summary-cell.is-filter { cursor: pointer; font: inherit; }
.summary-cell.is-filter:hover { background: var(--workspace-subtle); }
.summary-cell.is-filter.is-active { background: var(--workspace-accent-soft); }
.summary-cell.is-filter.is-active span,
.summary-cell.is-filter.is-active strong { color: var(--el-color-primary-dark-2); }
.summary-cell.tone-success strong { color: var(--el-color-success); }
.summary-cell.tone-warning strong { color: var(--el-color-warning); }
.summary-cell.tone-danger strong { color: var(--el-color-danger); }
.summary-cell.is-filter.is-active strong { color: var(--el-color-primary-dark-2); }
.task-search { width: 220px; flex: 0 0 auto; }
.task-driver-filter { width: 118px; flex: 0 0 auto; }
.task-actions { display: flex; align-items: center; gap: var(--workspace-gap); margin-left: auto; min-width: 0; justify-content: flex-end; }
.task-panel :deep(.el-table) { min-height: 0; }
.task-panel :deep(.el-table .cell) { line-height: 18px; }
.account-cell { display: flex; flex-direction: column; gap: 1px; min-width: 0; }
.account-subline { display: block; overflow: hidden; color: var(--el-text-color-secondary); font-size: 11px; line-height: 15px; text-overflow: ellipsis; white-space: nowrap; }
.email-copy { display: inline-flex; max-width: 100%; min-width: 0; gap: 5px; height: auto; padding: 0; color: var(--el-text-color-primary); justify-content: flex-start; }
.email-copy strong { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.email-copy .el-icon { flex: 0 0 auto; color: var(--el-color-primary); }
.credential-cell { display: flex; flex-direction: column; align-items: flex-start; gap: 2px; min-width: 0; }
.automatic-otp-wait { display: inline-flex; align-items: center; justify-content: center; gap: 5px; width: 100%; min-width: 0; color: var(--el-text-color-secondary); font-size: 12px; white-space: nowrap; }
.automatic-otp-wait strong { color: var(--el-color-warning-dark-2); font-variant-numeric: tabular-nums; }
.failure-cell { min-width: 0; max-width: 100%; overflow: hidden; line-height: 16px; }
.failure-summary { display: block; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.failure-summary strong, .failure-summary span { white-space: nowrap; }
.failure-cell strong { color: var(--el-color-danger); font-size: 12px; font-weight: 650; }
.failure-cell code { margin-left: 5px; color: var(--el-text-color-secondary); font-size: 10px; font-weight: 500; }
.failure-cell span { color: var(--el-text-color-regular); font-size: 11px; }
.failure-cell .failure-action-hint { color: var(--el-color-warning-dark-2); font-size: 11px; }
.failure-tooltip { display: grid; max-width: 520px; gap: 4px; line-height: 18px; }
</style>
