<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { CircleCheck, Connection, CopyDocument, Delete, Document, Key, Link, Lock, MoreFilled, Refresh, RefreshLeft, RefreshRight, Setting, Tickets, VideoPause, VideoPlay, View, Warning } from '@element-plus/icons-vue'
import { closeFreeCamoufoxDebug, deleteFreeTasks, freeBatchRetry, getFreeConfig, getFreeMailboxUrl, getFreeSecret, getFreeState, getFreeTaskLatestCode, preflightFree, rerunFreeTask, retryFreePassword, retryFreeTwofa, startFree, startFreePlanCheck, stopFree, type FreeConfig, type FreeState } from '../api/client'
import PageToolbar from '../components/PageToolbar.vue'
import WorkspacePanel from '../components/WorkspacePanel.vue'
import ContentEmptyState from '../components/ContentEmptyState.vue'
import FreeTaskLogDialog from '../components/FreeTaskLogDialog.vue'
import TaskVerificationInput from '../components/TaskVerificationInput.vue'
import TaskProgressCell from '../components/TaskProgressCell.vue'
import {
  ACCOUNT_BANNED_DISPLAY_MESSAGE,
  freeFailureCause,
  freeFailureDetails,
  freeFailureNodeIdentity,
  isCurrentAccountBanned,
  isRetryResolved,
} from '../utils/freeFailure'
import { useTaskProgressClock } from '../composables/useTaskProgressClock'
import { freeTaskSecretLookup } from '../utils/freeSecretLookup'
import { safeMailboxUrl } from '../utils/safeMailboxUrl'
import { freeStageDetail, freeStageLabel, freeStageType } from '../utils/freeStage'

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
const busy = ref<'preflight' | 'start' | 'stop' | ''>('')
const planBusy = ref('')
const openingMailboxUrlTaskIds = ref<string[]>([])
const loadingLatestCodeTaskIds = ref<string[]>([])
const loadingEmailTaskIds = ref<string[]>([])
const quickTargetCount = ref(defaultConfig.target_count)
const quickConcurrency = ref(defaultConfig.concurrency)
const quickRunDirty = ref(false)
const running = computed(() => Boolean(state.value.running))
const nowSeconds = useTaskProgressClock(() => state.value.tasks || [], () => Boolean(state.value.running))
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

function taskDriverLabel(driver: unknown) {
  const value = String(driver || '').trim().toLowerCase()
  if (value === 'camoufox') return 'Camoufox'
  if (value === 'protocol') return '全协议'
  return value ? '历史链路' : '全协议'
}

function taskFlowLabel(task: any) {
  const flow = String(task?.result?.account_flow || '').trim().toLowerCase()
  if (!flow) return ''
  return flow === 'existing_login' ? '已有账号登录' : '新账号注册'
}

function taskStageLabel(task: any) {
  return freeStageLabel(task?.stage_label || task?.stage, '-', task?.status)
}

function taskStageType(task: any): 'primary' | 'success' | 'warning' | 'danger' | 'info' {
  return freeStageType(task?.stage || task?.stage_label, task?.status)
}

function taskStageTooltip(task: any) {
  return freeStageDetail(task?.stage, task?.stage_label, task?.status)
}

function taskChainTooltip(task: any) {
  return [
    taskDriverLabel(task?.driver),
    isHistoricalDriver(task) ? '仅历史记录' : '',
    taskFlowLabel(task),
  ].filter(Boolean).join(' · ')
}

function isHistoricalDriver(task: any) {
  const value = String(task?.driver || '').trim().toLowerCase()
  return Boolean(value) && value !== 'protocol' && value !== 'camoufox'
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

function openTaskLog(task: any) {
  selectedTaskId.value = String(task?.task_id || '')
  logDialogOpen.value = true
}

async function copyTaskTokens(tasks: any[]) {
  await copyTaskSecret('token', tasks, 'Token')
}

async function copyTaskEmail(task: any) {
  const taskId = String(task?.task_id || '').trim()
  if (!taskId || loadingEmailTaskIds.value.includes(taskId)) return
  if (!navigator.clipboard?.writeText) {
    ElMessage.error('当前浏览器不支持安全剪贴板写入')
    return
  }
  loadingEmailTaskIds.value = [...loadingEmailTaskIds.value, taskId]
  try {
    const rowId = String(task?.row_id || '').trim()
    const email = String((await getFreeSecret('email', freeTaskSecretLookup(taskId, rowId))).value || '').trim()
    if (!email) throw new Error('服务端未返回可复制邮箱')
    await navigator.clipboard.writeText(email)
    ElMessage.success('已复制真实邮箱')
  } catch (error: any) {
    ElMessage.error(error?.message || '邮箱复制失败')
  } finally {
    loadingEmailTaskIds.value = loadingEmailTaskIds.value.filter(id => id !== taskId)
  }
}

async function openTaskMailboxUrl(task: any) {
  const taskId = String(task?.task_id || '').trim()
  const rowId = String(task?.row_id || '').trim()
  if (!taskId || !rowId) {
    ElMessage.info('该任务尚未生成可用的任务标识')
    return
  }
  if (!task?.has_mailbox_url) {
    ElMessage.info('该任务暂无取件 URL')
    return
  }
  if (openingMailboxUrlTaskIds.value.includes(taskId)) return
  const target = window.open('', '_blank')
  if (!target) {
    ElMessage.error('浏览器阻止了新窗口，请允许弹出窗口后重试')
    return
  }
  target.opener = null
  openingMailboxUrlTaskIds.value = [...openingMailboxUrlTaskIds.value, taskId]
  try {
    const result = await getFreeMailboxUrl(rowId)
    const destination = safeMailboxUrl(result.mailbox_url)
    if (!destination) throw new Error('取件 URL 无效或协议不安全')
    target.location.replace(destination)
  } catch (error: any) {
    target.close()
    ElMessage.error(error?.message || '打开取件 URL 失败')
  } finally {
    openingMailboxUrlTaskIds.value = openingMailboxUrlTaskIds.value.filter(id => id !== taskId)
  }
}

async function copyTaskLatestCode(task: any) {
  const taskId = String(task?.task_id || '').trim()
  if (!taskId) {
    ElMessage.info('该任务尚未生成任务 ID')
    return
  }
  if (!task?.has_mailbox_url) {
    ElMessage.info('该任务暂无取件 URL，无法提取验证码')
    return
  }
  if (loadingLatestCodeTaskIds.value.includes(taskId)) return
  if (!navigator.clipboard?.writeText) {
    ElMessage.error('当前浏览器不支持安全剪贴板写入')
    return
  }
  loadingLatestCodeTaskIds.value = [...loadingLatestCodeTaskIds.value, taskId]
  try {
    const result = await getFreeTaskLatestCode(taskId)
    const code = String(result.code || '').trim()
    if (!code) {
      ElMessage.info('未找到新的 OpenAI 邮箱验证码')
      return
    }
    await navigator.clipboard.writeText(code)
    ElMessage.success('验证码已复制')
  } catch (error: any) {
    ElMessage.error(error?.message || '提取邮箱验证码失败')
  } finally {
    loadingLatestCodeTaskIds.value = loadingLatestCodeTaskIds.value.filter(id => id !== taskId)
  }
}

function automaticOtpRemaining(task: any) {
  const verification = task?.mailbox_verification
  if (verification?.phase !== 'automatic') return 0
  return Math.max(0, Math.floor(Number(verification.deadline_at || 0) - nowSeconds.value))
}

async function copyIncidentId(value: string) {
  await copyDebugReference(value, '日志 ID')
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

async function copyTaskToken(task: any) {
  if (!task?.result?.has_access_token) {
    ElMessage.info('该任务暂无可复制的账号 Token')
    return
  }
  await copyTaskTokens([task])
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

function taskIncidentId(task: any) {
  return String(task?.incident_id || task?.failure?.incident_id || '').trim()
}

function taskDebugSessionId(task: any) {
  return String(task?.failure?.debug_session_id || task?.debug_session_id || '').trim()
}

function taskDebugArtifactId(task: any) {
  return String(task?.failure?.debug_artifact_id || task?.failure?.artifact_id || task?.debug_artifact_id || task?.artifact_id || '').trim()
}

function taskPlanLabel(task: any) {
  const plan = String(task?.result?.subscription_plan || task?.result?.plan_type || '').trim()
  const normalized = plan.toLowerCase()
  const status = String(task?.result?.plan_check_status || '').toLowerCase()
  if (status === 'failed') return '查询失败'
  if (['queued', 'running'].includes(status)) return '查询中'
  if (!plan) return '未查询'
  if (normalized === 'free') {
    return task?.result?.plus_trial_eligible ? 'free(可Plus试用)' : 'free'
  }
  return plan
}

function taskPlanType(task: any) {
  const plan = String(task?.result?.subscription_plan || task?.result?.plan_type || '').toLowerCase()
  const status = String(task?.result?.plan_check_status || '').toLowerCase()
  if (status === 'failed') return 'danger'
  if (['queued', 'running'].includes(status)) return 'warning'
  if (task?.result?.plus_trial_eligible || plan.includes('plus') || plan.includes('pro') || plan.includes('team') || plan.includes('go')) return 'success'
  return 'info'
}

function taskTwofaLabel(task: any) {
  const status = String(task?.result?.twofa_status || '').toLowerCase()
  if (task?.result?.has_totp || task?.result?.totp_secret) return '已启用'
  if (['queued', 'running'].includes(String(task?.status || '').toLowerCase())) return '处理中'
  if (['pending', 'failed'].includes(status)) return '待重试'
  return '未启用'
}

function taskTwofaType(task: any) {
  const status = String(task?.result?.twofa_status || '').toLowerCase()
  if (task?.result?.has_totp || task?.result?.totp_secret) return 'success'
  if (['queued', 'running'].includes(String(task?.status || '').toLowerCase())) return 'warning'
  return ['pending', 'failed'].includes(status) ? 'warning' : 'info'
}

function taskPasswordLabel(task: any) {
  const status = String(task?.result?.password_status || '').toLowerCase()
  const flow = String(task?.result?.account_flow || '').toLowerCase()
  if (task?.result?.has_password || status === 'enabled') return '已设置'
  if (status === 'pending') return '待重试'
  if (status === 'disabled' && flow === 'signup') return '未设置（可补设）'
  return '未设置'
}

function taskPasswordType(task: any) {
  const status = String(task?.result?.password_status || '').toLowerCase()
  const flow = String(task?.result?.account_flow || '').toLowerCase()
  if (task?.result?.has_password || status === 'enabled') return 'success'
  if (status === 'pending' || (status === 'disabled' && flow === 'signup')) return 'warning'
  return 'info'
}

async function copyTaskSecret(kind: 'token' | 'password' | 'totp' | 'credential', tasks: any[], label: string) {
  const ids = tasks.map(task => String(task?.task_id || '')).filter(Boolean)
  if (!ids.length) {
    ElMessage.warning('请先勾选账号')
    return
  }
  const eligible = kind === 'token'
    ? tasks.filter(task => task?.result?.has_access_token)
    : tasks.filter(task => kind === 'password' ? task?.result?.has_password : kind === 'totp' ? task?.result?.has_totp : task?.result?.has_credential)
  if (!eligible.length) {
    ElMessage.warning(`选中的账号没有可复制 ${label}`)
    return
  }
  try {
    const value = (await getFreeSecret(kind, { task_ids: eligible.map(task => String(task.task_id)) })).value
    if (!value || !navigator.clipboard?.writeText) throw new Error('当前环境不支持复制')
    await navigator.clipboard.writeText(value)
    ElMessage.success(`已复制 ${eligible.length} 个 Free ${label}`)
  } catch (error: any) {
    ElMessage.error(error?.message || `Free ${label} 复制失败`)
  }
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

function canRetryPassword(task: any) {
  if (isHistoricalDriver(task)) return false
  const status = String(task?.result?.password_status || '').toLowerCase()
  const accountFlow = String(task?.result?.account_flow || '').toLowerCase()
  if (accountFlow === 'existing_login') return false
  const taskStatus = String(task?.status || '')
  return ['success', 'partial_success', 'twofa_pending', 'failed', 'pending_rerun'].includes(taskStatus)
    && (status === 'pending' || (status === 'disabled' && accountFlow === 'signup'))
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

const camoufoxDebug = computed(() => state.value.camoufox_debug || {})
const camoufoxDebugSessions = computed(() => Array.isArray(camoufoxDebug.value.sessions) ? camoufoxDebug.value.sessions : [])
const camoufoxDebugCapacity = computed(() => Number(camoufoxDebug.value.capacity || (Number(config.camoufox.pool_size || 0) * Number(config.camoufox.max_contexts_per_browser || 0))))
const camoufoxDebugBrowserCount = computed(() => Number(camoufoxDebug.value.browser_count || config.camoufox.pool_size || 0))
const camoufoxDebugUsed = computed(() => Number(camoufoxDebug.value.used ?? camoufoxDebugSessions.value.length))
const camoufoxDebugAvailable = computed(() => Math.max(0, Number(camoufoxDebug.value.available ?? camoufoxDebugCapacity.value - camoufoxDebugUsed.value)))
const camoufoxDebugOpenContexts = computed(() => Number(camoufoxDebug.value.open_contexts ?? camoufoxDebugUsed.value))
const camoufoxDebugClosingContexts = computed(() => Number(camoufoxDebug.value.closing_contexts || 0))
const camoufoxDebugHeadless = computed(() => typeof camoufoxDebug.value.headless === 'boolean' ? camoufoxDebug.value.headless : (Boolean(config.camoufox.debug_mode) ? false : Boolean(config.camoufox.headless)))

async function copyDebugReference(value: string, label: string) {
  const reference = String(value || '').trim()
  if (!reference) return
  if (!navigator.clipboard?.writeText) {
    ElMessage.warning('当前环境不支持复制')
    return
  }
  try {
    await navigator.clipboard.writeText(reference)
    ElMessage.success(`${label}已复制`)
  } catch {
    ElMessage.error(`${label}复制失败`)
  }
}

async function closeCamoufoxDebug(sessionId = '') {
  try {
    const result = await closeFreeCamoufoxDebug(sessionId)
    state.value = result.state || state.value
    ElMessage.success(sessionId ? '调试窗口已关闭' : '调试窗口已全部关闭')
    await refresh()
  } catch (error: any) {
    ElMessage.error(error?.message || '关闭 Camoufox 调试窗口失败')
  }
}

function taskStatusLabel(status: string) {
  return ({ queued: '排队', running: '运行中', success: '成功', partial_success: '部分成功', failed: '失败', pending_rerun: '待重跑', stopped: '已停止', twofa_pending: '2FA 待重试', account_banned: ACCOUNT_BANNED_DISPLAY_MESSAGE } as Record<string, string>)[status] || status || '-'
}

function displayTaskStatus(task: any) {
  if (isCurrentAccountBanned(task?.status, task?.failure, task?.retry_resolved)) {
    return ACCOUNT_BANNED_DISPLAY_MESSAGE
  }
  return isRetryResolved(task?.retry_resolved) ? '已由重试解决' : taskStatusLabel(String(task?.status || ''))
}

function taskStatusType(status: string) {
  return ['success'].includes(status) ? 'success' : ['partial_success', 'pending_rerun', 'twofa_pending'].includes(status) ? 'warning' : ['failed', 'account_banned'].includes(status) ? 'danger' : status === 'stopped' ? 'info' : 'warning'
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

function taskNeedsExistingPassword(task: any) {
  return String(task?.failure?.error_code || '').trim().toLowerCase() === 'free_existing_login_password_missing'
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
    <PageToolbar title="Free 注册中心" :status="running ? '运行中' : '独立链路'" :tone="running ? 'success' : 'info'">
      <el-tag effect="plain">配置入口：运行配置 &gt; Free 注册运行</el-tag>
      <el-tag type="success" effect="plain">后端 {{ state.runtime_version }} · OTP {{ state.otp_parser_revision }}</el-tag>
      <el-button size="small" :icon="Setting" @click="emit('navigate', '/settings#free-register')">打开运行配置</el-button>
    </PageToolbar>
    <div class="task-view">
      <WorkspacePanel title="Free 注册任务" :icon="Connection" fill body-padding="none">
        <div class="task-panel" :class="{ 'has-camoufox-debug': config.driver === 'camoufox' || camoufoxDebugSessions.length }">
          <div class="run-snapshot task-summary"><div><span>可用 Free 邮箱</span><strong class="is-good">{{ Number(state.pool?.available || 0) }}</strong></div><div><span>任务总数</span><strong>{{ taskCounts.total }}</strong></div><div><span>排队 / 运行</span><strong>{{ taskCounts.running }}</strong></div><div><span>成功</span><strong class="is-good">{{ taskCounts.success - taskCounts.partial }}</strong></div><div><span>部分成功</span><strong class="is-warn">{{ taskCounts.partial }}</strong></div><div><span>失败</span><strong class="is-bad">{{ taskCounts.failed }}</strong></div><div><span>待重跑</span><strong class="is-warn">{{ taskCounts.rerun }}</strong></div><div><span>2FA 待重试</span><strong class="is-warn">{{ taskCounts.pending }}</strong></div></div>
          <div class="task-start-bar">
            <el-tag effect="plain">{{ config.driver === 'camoufox' ? 'Camoufox' : '全协议' }}</el-tag>
            <label class="quick-run-field"><span>注册数量</span><el-input-number v-model="quickTargetCount" class="quick-run-number" :min="1" :max="200" controls-position="right" :disabled="running || Boolean(busy)" @update:model-value="markQuickRunDirty" /></label>
            <label class="quick-run-field"><span>并发</span><el-input-number v-model="quickConcurrency" class="quick-run-number" :min="1" :max="16" controls-position="right" :disabled="running || Boolean(busy)" @update:model-value="markQuickRunDirty" /></label>
            <span class="muted">配置并发 {{ quickConcurrency }} · 实际 Slot {{ Number(state.scheduler?.active_slots || 0) }}/{{ Number(state.scheduler?.concurrency || quickConcurrency) }} · 可用邮箱 {{ Number(state.pool?.available || 0) }} · 代理 {{ Number(state.pool?.proxies || 0) }}</span>
            <el-button size="small" :icon="CircleCheck" :loading="busy === 'preflight'" :disabled="running" @click="preflight">预检</el-button>
            <el-button size="small" type="primary" :icon="VideoPlay" :loading="busy === 'start'" :disabled="running || !Number(state.pool?.available || 0)" @click="start">开始注册</el-button>
            <el-button size="small" type="danger" plain :icon="VideoPause" :loading="busy === 'stop'" :disabled="!running" @click="stop">停止</el-button>
          </div>
          <div v-if="config.driver === 'camoufox' || camoufoxDebugSessions.length" class="camoufox-debug-bar">
            <div class="camoufox-debug-summary">
              <el-tag type="warning" effect="plain">Camoufox 调试窗口 {{ camoufoxDebugSessions.length }} / {{ camoufoxDebugCapacity || '-' }}</el-tag>
              <span class="muted">浏览器进程 {{ camoufoxDebugBrowserCount }} · 调试 context {{ camoufoxDebugUsed }} / {{ camoufoxDebugCapacity || '-' }} · 可用 {{ camoufoxDebugAvailable }} · 活动 context {{ camoufoxDebugOpenContexts }}<template v-if="camoufoxDebugClosingContexts"> · 正在关闭 {{ camoufoxDebugClosingContexts }}</template></span>
              <span v-if="!camoufoxDebugHeadless" class="muted">有头模式</span>
            </div>
            <span class="muted">失败页面和安全挑战会保留；超时、取消、成功和浏览器断开会回收。</span>
            <div v-if="camoufoxDebugSessions.length" class="camoufox-debug-session-list">
              <div v-for="session in camoufoxDebugSessions" :key="session.session_id" class="camoufox-debug-session">
                <div class="camoufox-debug-session-info">
                  <strong>{{ session.task_id || session.session_id }}</strong>
                  <span>{{ session.node_label || session.error_code || '失败页面' }}<template v-if="session.page_type"> · {{ session.page_type }}</template></span>
                  <small v-if="session.safe_page" class="task-subline">{{ session.safe_page }}</small>
                  <small class="task-subline">现场 {{ session.artifact_id || '-' }} · 日志 {{ session.incident_id || '-' }}</small>
                </div>
                <div class="camoufox-debug-session-actions">
                  <el-button v-if="session.artifact_id" text size="small" :icon="CopyDocument" aria-label="复制现场 ID" @click="copyDebugReference(session.artifact_id, '现场 ID')" />
                  <el-button v-if="session.incident_id" text size="small" :icon="View" aria-label="打开故障日志" @click="openIncidentCenter(session.incident_id)" />
                  <el-button text size="small" :icon="Delete" aria-label="关闭调试窗口" @click="closeCamoufoxDebug(session.session_id)" />
                </div>
              </div>
            </div>
            <el-button v-if="camoufoxDebugSessions.length" size="small" type="warning" plain :icon="Delete" @click="closeCamoufoxDebug()">关闭全部调试窗口</el-button>
          </div>
          <div class="task-filter-bar">
            <el-input v-model="taskSearch" size="small" clearable placeholder="搜索邮箱、任务 ID 或失败节点" />
            <el-radio-group v-model="taskStatusFilter" size="small" class="task-status-filter">
              <el-radio-button value="all">全部 {{ taskCounts.total }}</el-radio-button>
              <el-radio-button value="active">排队/运行 {{ taskCounts.running }}</el-radio-button>
              <el-radio-button value="success">成功 {{ taskCounts.success - taskCounts.partial }}</el-radio-button>
              <el-radio-button value="partial_success">部分成功 {{ taskCounts.partial }}</el-radio-button>
              <el-radio-button value="failed">失败 {{ taskCounts.failed }}</el-radio-button>
              <el-radio-button value="twofa_pending">2FA {{ taskCounts.pending }}</el-radio-button>
              <el-radio-button value="pending_rerun">待重跑 {{ taskCounts.rerun }}</el-radio-button>
            <el-radio-button value="stopped">已停止 {{ taskCounts.stopped }}</el-radio-button>
            </el-radio-group>
            <el-select v-model="taskDriverFilter" size="small" clearable placeholder="链路" class="task-driver-filter"><el-option label="全协议" value="protocol" /><el-option label="Camoufox" value="camoufox" /></el-select>
          </div>
          <div class="task-actions"><span class="muted">已选 {{ selectedTasks.length }} 个</span><el-button v-if="['success', 'partial_success', 'twofa_pending', 'pending_rerun'].includes(taskStatusFilter)" size="small" type="warning" :icon="Refresh" :disabled="!selectedTasks.some(task => !isHistoricalDriver(task) && (['failed', 'stopped', 'pending_rerun', 'twofa_pending'].includes(String(task.status || '')) || canRetryPassword(task)))" @click="batchRetryCurrentNode">按当前失败节点批量重试</el-button><el-button size="small" :icon="CopyDocument" :disabled="!selectedTasks.length" @click="copyTaskSecret('token', selectedTasks, 'Token')">复制 Token</el-button><el-button size="small" :icon="CopyDocument" :disabled="!selectedTasks.length" @click="copyTaskSecret('password', selectedTasks, '密码')">复制密码</el-button><el-button size="small" :icon="CopyDocument" :disabled="!selectedTasks.length" @click="copyTaskSecret('totp', selectedTasks, 'TOTP')">复制 TOTP</el-button><el-button size="small" :icon="CopyDocument" :disabled="!selectedTasks.length" @click="copyTaskSecret('credential', selectedTasks, '完整凭据')">复制完整凭据</el-button><el-button size="small" :icon="CopyDocument" :disabled="!filteredTasks.some(task => task.result?.has_access_token)" @click="copyTaskTokens(filteredTasks)">复制当前筛选 Token</el-button><el-button size="small" type="danger" plain :icon="Delete" :disabled="!selectedTasks.length || loading" @click="deleteSelectedTasks">删除选中</el-button><el-button size="small" :icon="Refresh" @click="refresh">刷新任务</el-button></div>
          <el-table ref="taskTable" :data="filteredTasks" row-key="task_id" height="100%" size="small" @selection-change="handleTaskSelection">
            <el-table-column type="selection" width="42" reserve-selection />
            <el-table-column label="账号" width="184" show-overflow-tooltip><template #default="{ row }"><el-tooltip v-if="row.email" :content="`${String(row.email)}${row.task_id ? ` · 任务 ${row.task_id}` : ''}`" placement="top"><el-button link class="email-copy" :loading="loadingEmailTaskIds.includes(String(row.task_id || ''))" @click.stop="copyTaskEmail(row)"><strong>{{ row.email }}</strong><el-icon v-if="!loadingEmailTaskIds.includes(String(row.task_id || ''))"><CopyDocument /></el-icon></el-button></el-tooltip><span v-else>-</span></template></el-table-column>
            <el-table-column label="验证码" width="154" align="center"><template #default="{ row }"><TaskVerificationInput v-if="!isHistoricalDriver(row) && row.manual_verification?.can_submit" :task-id="row.task_id" :request="row.manual_verification" :now-seconds="nowSeconds" /><span v-else-if="!isHistoricalDriver(row) && row.mailbox_verification?.phase === 'automatic'" class="automatic-otp-wait">自动取码 <strong>{{ automaticOtpRemaining(row) }}s</strong></span><span v-else class="muted">-</span></template></el-table-column>
            <el-table-column label="链路" min-width="118" show-overflow-tooltip><template #default="{ row }"><el-tooltip :content="taskChainTooltip(row)" placement="top"><div class="task-chain-cell"><el-tag size="small" effect="plain">{{ taskDriverLabel(row.driver) }}</el-tag></div></el-tooltip></template></el-table-column>
            <el-table-column label="阶段" min-width="168" show-overflow-tooltip><template #default="{ row }"><el-tooltip :content="taskStageTooltip(row)" placement="top"><span class="task-stage-cell"><el-tag size="small" effect="light" :type="taskStageType(row)">{{ taskStageLabel(row) }}</el-tag></span></el-tooltip></template></el-table-column>
            <el-table-column label="耗时" min-width="190"><template #default="{ row }"><TaskProgressCell :progress="row.progress" :timing="row.timing" :now-seconds="nowSeconds" :status="row.status" /></template></el-table-column>
            <el-table-column label="状态" width="180" align="center" show-overflow-tooltip><template #default="{ row }"><el-tag size="small" :type="isRetryResolved(row.retry_resolved) ? 'success' : taskStatusType(row.status)">{{ displayTaskStatus(row) }}</el-tag></template></el-table-column>
            <el-table-column label="套餐" min-width="155" show-overflow-tooltip><template #default="{ row }"><el-tag size="small" :type="taskPlanType(row)" effect="light">{{ taskPlanLabel(row) }}</el-tag><el-tooltip v-if="!isHistoricalDriver(row) && row.result?.has_access_token && String(row.result?.plan_check_status || '').toLowerCase() === 'failed'" content="重新查询套餐"><el-button link size="small" :icon="Refresh" :loading="planBusy === String(row.task_id || row.row_id)" :disabled="Boolean(planBusy)" aria-label="重新查询套餐" @click.stop="refreshPlan(row)" /></el-tooltip></template></el-table-column>
            <el-table-column label="2FA" width="92" align="center"><template #default="{ row }"><el-tag size="small" :type="taskTwofaType(row)" effect="plain">{{ taskTwofaLabel(row) }}</el-tag></template></el-table-column>
            <el-table-column label="密码" width="118" align="center"><template #default="{ row }"><el-tag size="small" :type="taskPasswordType(row)" effect="plain">{{ taskPasswordLabel(row) }}</el-tag></template></el-table-column>
            <el-table-column label="错误" min-width="280">
              <template #default="{ row }">
                <el-tooltip placement="top" :disabled="!taskFailureDetails(row).length">
                  <template #content><div class="failure-tooltip"><span v-for="item in taskFailureDetails(row)" :key="item">{{ item }}</span></div></template>
                  <div class="failure-cell">
                    <template v-if="isRetryResolved(row.retry_resolved)"><strong class="resolved-text">已由重试解决</strong></template>
                    <template v-else-if="taskIsAccountBanned(row)"><strong>{{ ACCOUNT_BANNED_DISPLAY_MESSAGE }}<code>{{ taskFailureNode(row).code || 'account_banned' }}</code></strong></template>
                    <template v-else>
                      <strong v-if="taskFailureNode(row).label || taskFailureNode(row).code">{{ taskFailureNode(row).label || taskFailureNode(row).code }}<code v-if="taskFailureNode(row).showCode">{{ taskFailureNode(row).code }}</code></strong>
                      <span>{{ taskFailureCause(row) }}</span>
                      <span v-if="taskNeedsExistingPassword(row)" class="failure-action-hint">需补录真实密码后再处理；不会使用注册默认密码</span>
                    </template>
                    <small v-if="taskIncidentId(row) || taskDebugSessionId(row) || taskDebugArtifactId(row)" class="task-incident">
                      <el-button v-if="taskIncidentId(row)" text size="small" :icon="CopyDocument" @click.stop="copyIncidentId(taskIncidentId(row))">日志 ID {{ taskIncidentId(row) }}</el-button>
                      <el-button v-if="taskIncidentId(row)" text size="small" :icon="View" aria-label="打开故障详情" @click.stop="openIncidentCenter(taskIncidentId(row))" />
                      <el-button v-if="taskDebugSessionId(row)" text size="small" :icon="CopyDocument" @click.stop="copyDebugReference(taskDebugSessionId(row), '调试会话 ID')">窗口 {{ taskDebugSessionId(row) }}</el-button>
                      <el-button v-if="taskDebugArtifactId(row)" text size="small" :icon="CopyDocument" @click.stop="copyDebugReference(taskDebugArtifactId(row), '现场 ID')">现场 {{ taskDebugArtifactId(row) }}</el-button>
                    </small>
                  </div>
                </el-tooltip>
              </template>
            </el-table-column>
            <el-table-column label="创建时间" width="156"><template #default="{ row }">{{ row.created_at ? new Date(typeof row.created_at === 'number' ? row.created_at * 1000 : row.created_at).toLocaleString() : '-' }}</template></el-table-column>
            <el-table-column label="操作" width="82" align="center" fixed="right">
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
.free-page { display: grid; grid-template-rows: 44px minmax(0, 1fr); gap: 6px; width: 100%; height: 100%; min-width: 0; min-height: 0; }
.muted { color: var(--el-text-color-secondary); font-size: 12px; }
.task-view { min-width: 0; min-height: 0; height: 100%; }
.task-view :deep(.workspace-panel) { height: 100%; }
.task-panel { display: grid; grid-template-rows: auto auto auto auto minmax(0, 1fr); gap: 8px; height: 100%; min-height: 0; padding: 10px; }
.task-panel.has-camoufox-debug { grid-template-rows: auto auto auto auto auto minmax(0, 1fr); }
.run-snapshot { display: grid; grid-template-columns: repeat(9, minmax(0, 1fr)); gap: 1px; border: 1px solid var(--workspace-border); border-radius: var(--workspace-radius); overflow: hidden; }
.run-snapshot > div { display: grid; grid-template-rows: 18px 22px; align-items: center; min-height: 48px; padding: 5px 10px; background: #f8fafc; }
.run-snapshot span { color: var(--el-text-color-secondary); font-size: 13px; }
.run-snapshot strong { font-size: 17px; font-variant-numeric: tabular-nums; }
.run-snapshot strong.is-good { color: #168363; }
.run-snapshot strong.is-bad { color: #c44754; }
.run-snapshot strong.is-warn { color: #bc761c; }
.task-start-bar, .task-filter-bar, .task-actions { display: flex; align-items: center; gap: 8px; min-width: 0; }
.task-start-bar { min-height: 32px; }
.task-start-bar .muted { margin-right: auto; }
.camoufox-debug-bar { display: flex; align-items: center; flex-wrap: wrap; gap: 6px 8px; min-width: 0; padding: 6px 8px; border: 1px solid var(--el-color-warning-light-5); background: var(--el-color-warning-light-9); }
.camoufox-debug-bar > .muted { margin-right: auto; }
.camoufox-debug-summary { display: inline-flex; align-items: center; flex-wrap: wrap; gap: 6px; min-width: 0; }
.camoufox-debug-session-list { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); flex: 1 1 100%; gap: 4px; min-width: min(100%, 360px); }
.camoufox-debug-session { display: flex; align-items: center; gap: 6px; min-width: 0; padding: 4px 6px; border: 1px solid var(--el-color-warning-light-7); background: rgb(255 255 255 / 0.55); }
.camoufox-debug-session-info { display: grid; min-width: 0; margin-right: auto; line-height: 15px; }
.camoufox-debug-session-info strong, .camoufox-debug-session-info span, .camoufox-debug-session-info small { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.camoufox-debug-session-info strong { color: var(--el-text-color-primary); font-size: 11px; }
.camoufox-debug-session-info span { color: var(--el-color-warning-dark-2); font-size: 11px; }
.camoufox-debug-session-info .task-subline { max-width: 100%; }
.camoufox-debug-session-actions { display: inline-flex; align-items: center; flex: 0 0 auto; gap: 2px; }
.camoufox-debug-session-actions :deep(.el-button) { height: 22px; padding: 0 3px; }
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
@media (max-width: 760px) {
  .quick-run-field :deep(.quick-run-number) { width: 106px; max-width: 100%; }
}
.task-filter-bar { display: grid; grid-template-columns: minmax(220px, 0.8fr) minmax(560px, 2fr) 118px; min-height: 30px; }
.task-filter-bar > .el-input, .task-filter-bar > .task-driver-filter { width: 100%; }
.task-status-filter { flex: 1; min-width: 0; }
.task-status-filter { display: flex; width: 100%; }
.task-status-filter :deep(.el-radio-button) { flex: 1 1 0; min-width: 0; }
.task-status-filter :deep(.el-radio-button__inner) { width: 100%; padding: 6px 8px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; line-height: 16px; }
.task-driver-filter { width: 180px; }
.task-actions { justify-content: flex-end; min-height: 30px; }
.task-actions .muted { margin-right: auto; }
.task-panel :deep(.el-table) { min-height: 0; }
.task-panel :deep(.el-table .cell) { line-height: 18px; }
.task-subline { display: block; overflow: hidden; color: var(--el-text-color-secondary); font-size: 11px; line-height: 15px; text-overflow: ellipsis; white-space: nowrap; }
.task-chain-cell { display: flex; align-items: center; width: 100%; min-width: 0; gap: 5px; overflow: hidden; white-space: nowrap; }
.task-chain-cell > .el-tag { flex: 0 0 auto; }
.task-chain-meta { min-width: 0; overflow: hidden; color: var(--el-text-color-secondary); font-size: 11px; text-overflow: ellipsis; white-space: nowrap; }
.task-stage-cell { display: inline-flex; max-width: 100%; min-width: 0; overflow: hidden; vertical-align: middle; }
.task-stage-cell :deep(.el-tag) { max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.task-operation-cell { display: inline-flex; align-items: center; justify-content: center; gap: 0; min-width: 0; white-space: nowrap; }
.task-operation-cell :deep(.el-button) { width: 26px; height: 26px; margin-left: 0; padding: 4px; }
.email-copy { display: inline-flex; max-width: 100%; min-width: 0; gap: 5px; color: var(--el-text-color-primary); }
.email-copy strong { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.email-copy .el-icon { flex: 0 0 auto; color: var(--el-color-primary); }
.failure-cell { display: grid; min-width: 0; line-height: 16px; }
.failure-cell strong, .failure-cell span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.failure-cell strong { color: var(--el-color-danger); font-size: 12px; font-weight: 650; }
.failure-cell code { margin-left: 5px; color: var(--el-text-color-secondary); font-size: 10px; font-weight: 500; }
.failure-cell span { color: var(--el-text-color-regular); font-size: 11px; }
.failure-cell .failure-action-hint { color: var(--el-color-warning-dark-2); font-size: 11px; }
.task-incident { display: flex; align-items: center; min-width: 0; gap: 2px; line-height: 16px; }
.task-incident .el-button { min-width: 0; padding: 0 2px; color: var(--el-color-primary); font-size: 10px; }
.task-incident .el-button:first-child { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.automatic-otp-wait { display: inline-flex; align-items: center; justify-content: center; gap: 5px; width: 100%; min-width: 0; color: var(--el-text-color-secondary); font-size: 12px; white-space: nowrap; }
.automatic-otp-wait strong { color: var(--el-color-warning-dark-2); font-variant-numeric: tabular-nums; }
.failure-tooltip { display: grid; max-width: 520px; gap: 4px; line-height: 18px; }
</style>
