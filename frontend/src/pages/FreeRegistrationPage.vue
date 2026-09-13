<script setup lang="ts">
import { freeLiveStateFingerprint, freePlanStateFingerprint, freeStateFingerprint } from '../utils/fingerprint'
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { incidentCenterUrl } from '../utils/incidentLink'
import { errorMessage } from '../utils/errorMessage'
import { ElMessage, ElMessageBox } from 'element-plus'
import { ArrowDown, Check, CircleCheck, CircleClose, CopyDocument, Delete, Document, Key, Link, Loading, Lock, MoreFilled, Refresh, RefreshLeft, RefreshRight, Setting, Tickets, VideoPause, VideoPlay, Warning } from '@element-plus/icons-vue'
import { closeFreeCamoufoxDebug, deleteFreeTasks, freeBatchRetry, getFreeConfig, getFreeLiveCheckState, getFreePlanCheckState, getFreeState, preflightFree, rerunFreeTask, retryFreePassword, retryFreeTwofa, startFree, startFreePlanCheck, stopFree, type FreeConfig, type FreeLiveCheckState, type FreePlanCheckState, type FreeState, type FreeTaskRow } from '../api/client'
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
import { useColumnWidths, type DragColumn } from '../composables/useColumnWidths'
import { usePolling } from '../composables/usePolling'
import { useFreeTaskRowActions } from '../composables/useFreeTaskRowActions'
import { liveStatusLabel, liveStatusType } from '../utils/freeLiveDisplay'
import { formatShortDateTime } from '../utils/datetime'
import { defaultFreeConfig, mergeFreeConfigDraft, stripLegacyFreeConfigDraft } from '../utils/freeConfigDefaults'
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

const defaultConfig: FreeConfig = defaultFreeConfig()

const emit = defineEmits<{ navigate: [string] }>()
const config = reactive<FreeConfig>(structuredClone(defaultConfig))
const state = ref<FreeState>({ running: false, tasks: [], summary: {}, pool: {} })
const liveState = ref<FreeLiveCheckState>({ running: false, workers: 3, queue_limit: 500, active: 0, jobs: [] })
const planState = ref<FreePlanCheckState>({ running: false, workers: 0, queue_limit: 0, active: 0, jobs: [] })
const runLogTask = ref<{ task_id: string; email: string; stage: string } | null>(null)
const runKindFilter = ref('')
const selectedTaskId = ref('')
const taskSearch = ref('')
const taskStatusFilter = ref('all')
const taskDriverFilter = ref('')
const selectedTasks = ref<FreeTaskRow[]>([])
const taskTable = ref<{ clearSelection: () => void } | null>(null)
const logDialogOpen = ref(false)
const logDialog = ref<{ refresh: (options?: { forceLatest?: boolean; silent?: boolean }) => Promise<void> }>()
const loading = ref(false)
const busy = ref<'preflight' | 'start' | 'stop' | 'close-debug' | ''>('')
const planBusy = ref('')
const quickTargetCount = ref(defaultConfig.target_count)
const quickConcurrency = ref(defaultConfig.concurrency)
const quickRunDirty = ref(false)
const running = computed(() => Boolean(state.value.running))
const startPending = computed(() => Boolean(state.value.starting))
const startFailure = computed(() => state.value.start_failure || null)
const startFailureDismissed = ref(false)
const startProgressOpen = ref(false)
const startProgressDone = ref(false)
const START_STAGES = [
  { key: 'owner', label: '校验熔断与运行归属' },
  { key: 'preflight', label: '网络与链路预检' },
  { key: 'mailbox', label: '校验邮箱池与账号证据' },
  { key: 'tunnel_mint', label: '铸造隧道替补代理' },
  { key: 'proxy_bind', label: '分配代理' },
  { key: 'tasks', label: '创建任务并上线' },
] as const

const startStageIndex = computed(() => {
  const stage = state.value.startup?.stage
  return START_STAGES.findIndex(item => item.key === stage)
})
const startProgressPercent = computed(() => {
  if (startProgressDone.value || state.value.running) return 100
  const index = startStageIndex.value
  if (index < 0) return 8
  return Math.round(((index + 1) / (START_STAGES.length + 1)) * 100)
})
const startProgressStatus = computed<'success' | 'exception' | undefined>(() => {
  if (state.value.start_failure) return 'exception'
  if (startProgressDone.value || state.value.running) return 'success'
  return undefined
})
const startElapsedSeconds = computed(() => {
  const at = Number(state.value.startup?.updated_at || 0)
  if (!at) return 0
  return Math.max(0, Math.floor(nowSeconds.value - at))
})

function startStageClass(index: number) {
  const current = startStageIndex.value
  if (startProgressDone.value || state.value.running || index < current) return 'is-done'
  if (index === current) return 'is-active'
  return 'is-todo'
}

watch(() => state.value.running, (value, previous) => {
  if (value && !previous && startProgressOpen.value) {
    startProgressDone.value = true
    window.setTimeout(() => {
      startProgressOpen.value = false
      startProgressDone.value = false
    }, 1400)
  }
})
const debugWindowsOpen = computed(() => Number(state.value.camoufox_debug?.open_contexts || 0) > 0)
const nowSeconds = useTaskProgressClock(() => state.value.tasks || [], () => Boolean(state.value.running || liveState.value.running || planState.value.running || state.value.starting))
const { colWidth: taskColWidth, handleHeaderDragend: onTaskHeaderDragend, resetWidths: resetTaskWidths } = useColumnWidths('gptphone.table.widths.free-register', { autoResetOnce: true })
function automaticOtpRemaining(task: FreeTaskRow) {
  return automaticOtpRemainingPure(task, nowSeconds.value)
}

const {
  loadingEmailTaskIds,
  copyTaskSecret,
  copyTaskTokens,
  copyTaskToken,
  copyTaskEmail,
  copyRunEmail,
  openTaskMailboxUrl,
  copyTaskLatestCode,
} = useFreeTaskRowActions()

const stateFingerprint = ref('')
const liveStateFingerprint = ref('')
const planStateFingerprint = ref('')

const visibleTasks = computed(() => (state.value.tasks || []).slice().sort((a, b) => {
  const batchOrder = Number(b.created_at || 0) - Number(a.created_at || 0)
  if (batchOrder) return batchOrder
  const ordinalOrder = Number(a.ordinal || 0) - Number(b.ordinal || 0)
  return ordinalOrder || String(a.task_id || '').localeCompare(String(b.task_id || ''))
}))
const taskPage = ref(1)
const taskPageSize = ref(50)
type RunKind = 'register' | 'register_rerun' | 'twofa_retry' | 'password_retry' | 'live_fast' | 'live_deep' | 'plan_recheck'
const RUN_KIND_LABELS: Record<RunKind, string> = {
  register: 'Free 注册',
  register_rerun: '注册重跑',
  twofa_retry: '2FA 重试',
  password_retry: '密码重跑',
  live_fast: '快速测活',
  live_deep: '401 重跑',
  plan_recheck: '重查套餐',
}
type UnifiedRunRow = {
  key: string
  kind: RunKind
  kindLabel: string
  createdAt: number
  task?: FreeTaskRow
  job?: FreeLiveCheckState['jobs'][number]
  plan?: FreePlanCheckState['jobs'][number]
  children?: UnifiedRunRow[]
}

function runKindOfTask(task: FreeTaskRow): RunKind {
  const mode = String(task.retry_mode || '').toLowerCase()
  if (mode === 'twofa') return 'twofa_retry'
  if (mode === 'password') return 'password_retry'
  if (task.retry_of) return 'register_rerun'
  return 'register'
}

function isAutoRetryTask(task: FreeTaskRow): boolean {
  return String(task.retry_trigger || '') === 'auto' && Boolean(task.retry_of)
}

function liveRunProgress(job: NonNullable<UnifiedRunRow['job']>) {
  return {
    code: String(job.stage || ''),
    label: job.stage_label || liveStatusLabel(job.status),
    group: 'free' as const,
    entered_at: Number(job.created_at || 0),
    finished_at: job.checked_at ?? null,
  }
}

function planRunProgress(job: NonNullable<UnifiedRunRow['plan']>) {
  return {
    code: 'free_plan_check',
    label: '套餐查询',
    group: 'free' as const,
    entered_at: Number(job.created_at || 0),
    finished_at: job.checked_at ?? null,
  }
}

function planStatusLabel(status = ''): string {
  return ({ queued: '排队', running: '查询中', success: '已查询', partial_success: '部分成功', stopped: '已停止', failed: '失败' } as Record<string, string>)[status] || '套餐查询'
}

function planStatusType(status = ''): string {
  if (['success', 'partial_success'].includes(status)) return status === 'success' ? 'success' : 'warning'
  if (status === 'failed') return 'danger'
  if (['queued', 'running'].includes(status)) return 'warning'
  return 'info'
}

const unifiedRuns = computed<UnifiedRunRow[]>(() => {
  // Fold automatically triggered retry subtasks under their parent row (the
  // table renders them as expandable tree children).  Manually retried rows
  // stay independent top-level rows so the operator keeps full visibility.
  const taskRows = new Map<string, UnifiedRunRow>()
  for (const task of visibleTasks.value) {
    const kind = runKindOfTask(task)
    const key = `task:${task.task_id}`
    const label = RUN_KIND_LABELS[kind]
    taskRows.set(key, {
      key,
      kind,
      kindLabel: isAutoRetryTask(task) ? `${label}（自动）` : label,
      createdAt: Number(task.created_at || 0),
      task,
    })
  }
  const rows: UnifiedRunRow[] = []
  for (const row of taskRows.values()) {
    const task = row.task as FreeTaskRow
    const parentKey = `task:${task.retry_of || ''}`
    const parentRow = isAutoRetryTask(task) ? taskRows.get(parentKey) : undefined
    if (parentRow && parentRow !== row) {
      (parentRow.children ||= []).push(row)
    } else {
      rows.push(row)
    }
  }
  for (const row of taskRows.values()) {
    if (row.children) row.children.sort((a, b) => a.createdAt - b.createdAt)
  }
  for (const job of liveState.value.jobs || []) {
    const kind: RunKind = job.mode === 'deep' ? 'live_deep' : 'live_fast'
    rows.push({ key: `live:${job.task_id}`, kind, kindLabel: RUN_KIND_LABELS[kind], createdAt: Number(job.created_at || 0), job })
  }
  for (const job of planState.value.jobs || []) {
    rows.push({ key: `plan:${job.task_id}`, kind: 'plan_recheck', kindLabel: RUN_KIND_LABELS.plan_recheck, createdAt: Number(job.created_at || 0), plan: job })
  }
  return rows.sort((a, b) => b.createdAt - a.createdAt)
})

function runStatusBucket(row: UnifiedRunRow): string {
  if (row.task) {
    const task = row.task
    if (isRetryResolved(task.retry_resolved)) return 'success'
    return String(task.status || '')
  }
  if (row.plan) {
    const status = String(row.plan.status || '')
    if (['queued', 'running'].includes(status)) return 'active'
    if (status === 'success') return 'success'
    if (status === 'partial_success') return 'partial_success'
    if (status === 'stopped') return 'stopped'
    return 'failed'
  }
  const status = String(row.job?.status || '')
  if (['queued', 'running'].includes(status)) return 'active'
  if (status === 'live') return 'success'
  return 'failed'
}

const runCounts = computed(() => {
  // Single pass over the runs: eight filters per poll tick reduced to one.
  const buckets: Record<string, number> = {}
  for (const row of unifiedRuns.value) {
    const bucket = runStatusBucket(row)
    buckets[bucket] = (buckets[bucket] || 0) + 1
  }
  return {
    total: unifiedRuns.value.length,
    active: buckets.active || 0,
    success: (buckets.success || 0) + (buckets.partial_success || 0),
    partial: buckets.partial_success || 0,
    failed: buckets.failed || 0,
    twofa: buckets.twofa_pending || 0,
    rerun: buckets.pending_rerun || 0,
    stopped: buckets.stopped || 0,
  }
})
const statusFilters = computed(() => [
  { value: 'all', label: '全部', count: runCounts.value.total, tone: 'info' },
  { value: 'active', label: '排队/运行', count: runCounts.value.active, tone: 'primary' },
  { value: 'success', label: '成功', count: runCounts.value.success - runCounts.value.partial, tone: 'success' },
  { value: 'partial_success', label: '部分成功', count: runCounts.value.partial, tone: 'warning' },
  { value: 'failed', label: '失败', count: runCounts.value.failed, tone: 'danger' },
  { value: 'twofa_pending', label: '2FA', count: runCounts.value.twofa, tone: 'warning' },
  { value: 'pending_rerun', label: '待重跑', count: runCounts.value.rerun, tone: 'warning' },
  { value: 'stopped', label: '已停止', count: runCounts.value.stopped, tone: 'info' },
] as { value: string; label: string; count: number; tone: string }[])

const filteredRuns = computed(() => {
  const query = taskSearch.value.trim().toLowerCase()
  return unifiedRuns.value.filter(row => {
    if (runKindFilter.value && row.kind !== runKindFilter.value) return false
    const task = row.task
    const haystack = task
      ? [task.email, task.task_id || '', task.failure?.node_label, task.failure?.node_code].join(' ').toLowerCase()
      : row.plan
        ? [row.plan.email || '', row.plan.task_id || '', row.plan.failure?.node_label || '', row.plan.failure?.node_code || ''].join(' ').toLowerCase()
        : [row.job?.email || '', row.job?.task_id || '', row.job?.failure?.node_label || '', row.job?.failure?.node_code || ''].join(' ').toLowerCase()
    if (query && !haystack.includes(query)) return false
    if (taskDriverFilter.value && (!task || task.driver !== taskDriverFilter.value)) return false
    if (taskStatusFilter.value !== 'all' && runStatusBucket(row) !== taskStatusFilter.value) return false
    return true
  })
})
const pagedRuns = computed(() => filteredRuns.value.slice((taskPage.value - 1) * taskPageSize.value, taskPage.value * taskPageSize.value))
watch(() => [filteredRuns.value.length, taskSearch.value, taskStatusFilter.value, taskDriverFilter.value, runKindFilter.value], () => {
  const maxPage = Math.max(1, Math.ceil(filteredRuns.value.length / taskPageSize.value))
  if (taskPage.value > maxPage) taskPage.value = maxPage
})
function kindTagType(kind: RunKind): string {
  if (kind === 'live_deep') return 'danger'
  if (kind === 'twofa_retry' || kind === 'password_retry' || kind === 'plan_recheck') return 'warning'
  if (kind === 'live_fast') return 'info'
  return 'primary'
}

function handleCopyCommand(command: string) {
  if (command === 'filtered-token') return void copyTaskTokens(filteredRuns.value.map(row => row.task).filter((task): task is FreeTaskRow => Boolean(task)))
  const kind = command as 'token' | 'password' | 'totp' | 'credential'
  const labels = { token: 'Token', password: '密码', totp: 'TOTP', credential: '完整凭据' } as const
  void copyTaskSecret(kind, selectedTasks.value, labels[kind])
}
const selectedTask = computed(() => visibleTasks.value.find(task => task.task_id === selectedTaskId.value))
function mergeConfig(value: FreeConfig, forceQuickRun = false) {
  mergeFreeConfigDraft(config, value)
  if (forceQuickRun || !quickRunDirty.value) {
    quickTargetCount.value = config.target_count
    quickConcurrency.value = config.concurrency
  }
}
function quickRunConfig(): FreeConfig {
  const sanitized: FreeConfig = {
    ...config,
    target_count: Math.min(200, Math.max(1, Number(quickTargetCount.value) || 1)),
    concurrency: Math.min(16, Math.max(1, Number(quickConcurrency.value) || 1)),
  }
  stripLegacyFreeConfigDraft(sanitized)
  return sanitized
}

function markQuickRunDirty() {
  quickRunDirty.value = true
}

async function refresh() {
  // 注册、测活与重查套餐任务并行拉取：合并列表一次性渲染，避免多路数据
  // 先后到达时行数跳变。
  const [stateSettled, liveSettled, planSettled] = await Promise.allSettled([getFreeState(), getFreeLiveCheckState(), getFreePlanCheckState()])
  if (stateSettled.status === 'fulfilled') {
    const result = stateSettled.value
    const serverRunning = Boolean(result.state?.running)
    if (serverRunning) quickRunDirty.value = false
    mergeConfig(result.config, serverRunning)
    // Skip the reactive assignment (and the whole derived computed/render
    // chain) when the polled payload equals the rendered one.
    const nextFingerprint = freeStateFingerprint(result.state)
    if (nextFingerprint !== stateFingerprint.value) {
      stateFingerprint.value = nextFingerprint
      state.value = result.state || state.value
    }
    if (logDialogOpen.value && selectedTaskId.value) {
      await logDialog.value?.refresh({ silent: true })
    }
  } else if (!loading.value) {
    ElMessage.error(errorMessage(stateSettled.reason) || 'Free 状态刷新失败')
  }
  if (liveSettled.status === 'fulfilled') {
    const nextLiveFingerprint = freeLiveStateFingerprint(liveSettled.value.state)
    if (nextLiveFingerprint !== liveStateFingerprint.value) {
      liveStateFingerprint.value = nextLiveFingerprint
      liveState.value = liveSettled.value.state || liveState.value
    }
  } else if (liveState.value.running) {
    ElMessage.error(errorMessage(liveSettled.reason) || 'Free 测活状态刷新失败')
  }
  if (planSettled.status === 'fulfilled') {
    const nextPlanFingerprint = freePlanStateFingerprint(planSettled.value.state)
    if (nextPlanFingerprint !== planStateFingerprint.value) {
      planStateFingerprint.value = nextPlanFingerprint
      planState.value = planSettled.value.state || planState.value
    }
  } else if (planState.value.running) {
    ElMessage.error(errorMessage(planSettled.reason) || 'Free 套餐查询状态刷新失败')
  }
  if (logDialogOpen.value && runLogTask.value) {
    await logDialog.value?.refresh({ silent: true })
  }
}

async function load() {
  loading.value = true
  // 首次进入同样并行拉取测活与套餐查询任务，避免页面先渲染注册任务、
  // 轮询到达之后再补入行的行数跳变。
  const [configResult, liveResult, planResult] = await Promise.allSettled([getFreeConfig(), getFreeLiveCheckState(), getFreePlanCheckState()])
  if (configResult.status === 'fulfilled') {
    mergeConfig(configResult.value.config, true)
    state.value = configResult.value.state || state.value
  } else {
    ElMessage.error(errorMessage(configResult.reason) || 'Free 配置加载失败')
  }
  if (liveResult.status === 'fulfilled') {
    liveState.value = liveResult.value.state || liveState.value
  }
  if (planResult.status === 'fulfilled') {
    planState.value = planResult.value.state || planState.value
  }
  loading.value = false
}

async function preflight() {
  busy.value = 'preflight'
  try {
    const result = await preflightFree(quickRunConfig())
    state.value = result.state || state.value
    ElMessage.success(`预检通过：${Number(result.result?.target_count || 0)} 个邮箱，健康池 ${Number(result.result?.proxies || 0)} 个代理`)
  } catch (error) {
    ElMessage.error(errorMessage(error) || 'Free 预检失败')
  } finally {
    busy.value = ''
  }
}

async function start() {
  startFailureDismissed.value = false
  busy.value = 'start'
  try {
    const submittedConfig = quickRunConfig()
    const result = await startFree(submittedConfig)
    config.target_count = submittedConfig.target_count
    config.concurrency = submittedConfig.concurrency
    quickTargetCount.value = submittedConfig.target_count
    quickConcurrency.value = submittedConfig.concurrency
    quickRunDirty.value = false
    const next = result.state
    if (next?.tasks?.length) {
      state.value = next
    } else if (next) {
      // 异步受理响应在后台准备期不带任务列表；保留现有列表避免整表闪空。
      state.value = { ...next, tasks: state.value.tasks }
    }
    if (result.async_start) {
      // 启动请求已受理，批次在后台准备中；立即进入 1s 快速轮询，
      // 任务渐进上线后 running 状态自然出现。
      scheduleRefresh()
      startProgressOpen.value = true
      ElMessage.success('启动已受理，批次正在后台准备，任务将陆续上线')
    } else {
      ElMessage.success('Free 注册已启动')
    }
  } catch (error) {
    ElMessage.error(errorMessage(error) || 'Free 注册启动失败')
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
  } catch (error) {
    ElMessage.error(errorMessage(error) || '停止 Free 注册失败')
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
  } catch (error) {
    ElMessage.error(errorMessage(error) || '关闭 Camoufox 调试窗口失败')
  } finally {
    busy.value = ''
  }
}

function openTaskLog(task: FreeTaskRow) {
  selectedTaskId.value = String(task?.task_id || '')
  runLogTask.value = null
  logDialogOpen.value = true
}

function openLiveRunLog(row: UnifiedRunRow) {
  const job = row.job
  if (!job) return
  selectedTaskId.value = ''
  runLogTask.value = { task_id: job.task_id, email: job.email, stage: job.stage_label || liveStatusLabel(job.status) }
  logDialogOpen.value = true
}

function openPlanRunLog(row: UnifiedRunRow) {
  const job = row.plan
  if (!job) return
  selectedTaskId.value = ''
  runLogTask.value = { task_id: job.task_id, email: job.email, stage: planStatusLabel(job.status) }
  logDialogOpen.value = true
}

function runRowClass({ row }: { row: UnifiedRunRow }): string {
  return row.task ? taskRowClass({ row: row.task }) : ''
}

function runSelectable(row: UnifiedRunRow): boolean {
  return Boolean(row.task)
}

function handleRunAction(command: string, row: UnifiedRunRow) {
  if (command === 'live_log') return openLiveRunLog(row)
  if (command === 'plan_log') return openPlanRunLog(row)
}

const dialogTask = computed(() => selectedTask.value ?? runLogTask.value ?? undefined)

function openIncidentCenter(value: string) {
  const incidentId = String(value || '').trim()
  if (incidentId) emit('navigate', incidentCenterUrl(incidentId))
}

function openTaskIncident(task: FreeTaskRow) {
  const incidentId = taskIncidentId(task)
  if (!incidentId) {
    ElMessage.info('该任务尚未生成故障日志')
    return
  }
  openIncidentCenter(incidentId)
}

async function rerunTaskAction(task: FreeTaskRow) {
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

async function retryTwofaTaskAction(task: FreeTaskRow) {
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

async function retryPasswordTaskAction(task: FreeTaskRow) {
  if (!canRetryPassword(task)) {
    ElMessage.info('该任务当前没有可重试的密码设置节点')
    return
  }
  await retryPasswordTask(task)
}

async function handleTaskAction(command: string, task: FreeTaskRow) {
  if (command === 'details') return openTaskLog(task)
  if (command === 'mailbox_url') return openTaskMailboxUrl(task)
  if (command === 'latest_code') return copyTaskLatestCode(task)
  if (command === 'token') return copyTaskToken(task)
  if (command === 'incident') return openTaskIncident(task)
  if (command === 'rerun') return rerunTaskAction(task)
  if (command === 'twofa') return retryTwofaTaskAction(task)
  if (command === 'password') return retryPasswordTaskAction(task)
}

function handleTaskSelection(rows: FreeTaskRow[]) {
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
  } catch (error) {
    ElMessage.error(errorMessage(error) || 'Free 任务记录删除失败')
  } finally {
    taskTable.value?.clearSelection()
    selectedTasks.value = []
    loading.value = false
  }
}

async function rerunTask(task: FreeTaskRow) {
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
  } catch (error) {
    ElMessage.error(errorMessage(error) || 'Free 账号重跑失败')
  } finally {
    loading.value = false
  }
}

async function retryTwofaTask(task: FreeTaskRow) {
  const taskId = String(task?.task_id || task?.row_id || '')
  if (isHistoricalDriver(task) || !taskId || String(task?.status || '') !== 'twofa_pending' || loading.value) return
  loading.value = true
  try {
    const result = await retryFreeTwofa(taskId)
    if (result.state) state.value = result.state as FreeState
    ElMessage.info(`已加入 2FA 重试队列 ${result.task?.task_id || ''}`)
    await refresh()
  } catch (error) {
    ElMessage.error(errorMessage(error) || '2FA 重试失败')
  } finally {
    loading.value = false
  }
}

async function retryPasswordTask(task: FreeTaskRow) {
  const taskId = String(task?.task_id || task?.row_id || '')
  if (!canRetryPassword(task) || !taskId || loading.value) return
  loading.value = true
  try {
    const result = await retryFreePassword(taskId)
    if (result.state) state.value = result.state
    ElMessage.info(`已加入密码重试队列 ${result.task?.task_id || ''}`)
    await refresh()
  } catch (error) {
    ElMessage.error(errorMessage(error) || '密码设置重试失败')
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
  } catch (error) {
    ElMessage.error(errorMessage(error) || '批量重试失败')
  }
}

async function refreshPlan(task: FreeTaskRow) {
  const rowId = String(task?.row_id || '')
  if (!rowId || !task?.result?.has_access_token || String(task?.result?.plan_check_status || '').toLowerCase() !== 'failed' || planBusy.value) return
  planBusy.value = String(task.task_id || rowId)
  try {
    await startFreePlanCheck([rowId])
    ElMessage.info('套餐查询已加入队列')
    await refresh()
  } catch (error) {
    ElMessage.error(errorMessage(error) || '重新查询套餐失败')
  } finally {
    planBusy.value = ''
  }
}

function effectiveTaskFailure(task: FreeTaskRow): FreeTaskRow['failure'] {
  // A folded automatic retry child surfaces its structured failure through the
  // parent ``retry_failure``; the parent's own failure (when present) wins.
  if (task?.failure) return task.failure
  if (isRetryResolved(task?.retry_resolved)) return null
  return task?.retry_failure || null
}

function taskFailureCause(task: FreeTaskRow) {
  return freeFailureCause(effectiveTaskFailure(task), { retryResolved: task?.retry_resolved })
}

function taskIsAccountBanned(task: FreeTaskRow) {
  return isCurrentAccountBanned(task?.status, effectiveTaskFailure(task), task?.retry_resolved)
}

function taskFailureDetails(task: FreeTaskRow) {
  return freeFailureDetails(effectiveTaskFailure(task))
}

function taskFailureNode(task: FreeTaskRow) {
  return freeFailureNodeIdentity(effectiveTaskFailure(task))
}

const polling = usePolling(refresh, () => (running.value || logDialogOpen.value || startPending.value || startProgressOpen.value ? 1000 : 3000))
const scheduleRefresh = polling.schedule

onMounted(async () => {
  await load()
  scheduleRefresh()
})
</script>

<template>
  <div class="free-page">
    <div class="task-view">
      <WorkspacePanel fill body-padding="none">
        <div class="task-panel">
          <div class="task-launch-column">
          <div class="task-start-bar">
            <el-radio-group v-model="config.driver" class="driver-inline-radio" :disabled="running || Boolean(busy)" size="small" @update:model-value="markQuickRunDirty">
              <el-radio-button value="protocol">全协议</el-radio-button>
              <el-radio-button value="camoufox">Camoufox</el-radio-button>
            </el-radio-group>
            <label class="quick-run-field"><span>注册数量</span><el-input-number v-model="quickTargetCount" class="quick-run-number" :min="1" :max="200" controls-position="right" :disabled="running || Boolean(busy)" @update:model-value="markQuickRunDirty"  size="small" /></label>
            <label class="quick-run-field"><span>并发</span><el-input-number v-model="quickConcurrency" class="quick-run-number" :min="1" :max="16" controls-position="right" :disabled="running || Boolean(busy)" @update:model-value="markQuickRunDirty"  size="small" /></label>
            <label class="quick-run-field quick-run-switch"><span>密码设置</span><el-switch v-model="config.auto_set_password" :disabled="running || Boolean(busy)" size="small" aria-label="注册后补设账号密码" @update:model-value="markQuickRunDirty" /></label>
            <label class="quick-run-field quick-run-switch"><span>2FA</span><el-switch v-model="config.auto_set_2fa" :disabled="running || Boolean(busy)" size="small" aria-label="注册后设置 2FA" @update:model-value="markQuickRunDirty" /></label>
            <span class="muted task-start-meta">可用邮箱 {{ Number(state.pool?.available || 0) }} · 代理 {{ Number(state.pool?.proxies || 0) }}</span>
            <el-button v-if="startPending && !startProgressOpen" size="small" link type="primary" @click="startProgressOpen = true" aria-label="查看启动进度">启动进度</el-button>
            <el-button size="small" :icon="CircleCheck" :loading="busy === 'preflight'" :disabled="running || startPending" @click="preflight" aria-label="预检">预检</el-button>
            <el-button size="small" type="primary" :icon="VideoPlay" :loading="busy === 'start' || startPending" :disabled="running || startPending || !Number(state.pool?.available || 0)" @click="start" aria-label="开始注册">开始注册</el-button>
            <el-button size="small" type="danger" plain :icon="VideoPause" :loading="busy === 'stop'" :disabled="!running" @click="stop" aria-label="停止">停止</el-button>
            <el-tooltip content="关闭保留的 Camoufox 调试窗口" placement="top" :show-after="250">
              <el-button size="small" plain :icon="CircleClose" :loading="busy === 'close-debug'" :disabled="!debugWindowsOpen || Boolean(busy)" aria-label="关闭 Camoufox 调试窗口" @click="closeDebugWindows">关闭调试窗口</el-button>
            </el-tooltip>
            <el-button size="small" :icon="Setting" @click="emit('navigate', '/settings#free-register')" aria-label="运行配置">运行配置</el-button>
            <el-tooltip content="撤销本表拖拽保存的列宽，恢复默认列宽" placement="top" :show-after="250">
              <el-button size="small" :icon="RefreshLeft" aria-label="重置列宽" @click="resetTaskWidths">重置列宽</el-button>
            </el-tooltip>
          </div>
          <el-alert
            v-if="startPending"
            class="task-start-status"
            type="info"
            :closable="false"
            title="启动已受理，批次正在后台准备，任务将陆续上线"
          />
          <el-alert
            v-else-if="startFailure && !startFailureDismissed"
            class="task-start-status"
            type="error"
            show-icon
            :title="`上次启动失败：${startFailure.node_label}（${startFailure.node_code}）`"
            :description="startFailure.public_message"
            @close="startFailureDismissed = true"
          />
          </div>
          <div class="task-filter-row">
            <div class="task-summary-strip" role="group" aria-label="任务状态筛选">
              <button v-for="item in statusFilters" :key="item.value" type="button" class="summary-cell is-filter" :class="{ 'is-active': taskStatusFilter === item.value, [`tone-${item.tone}`]: true }" :aria-pressed="taskStatusFilter === item.value" @click="taskStatusFilter = item.value">
                <span>{{ item.label }}</span><strong>{{ item.count }}</strong>
              </button>
            </div>
            <el-input v-model="taskSearch" size="small" clearable class="task-search" placeholder="搜索邮箱、任务 ID 或失败节点" />
            <el-select v-model="taskDriverFilter" size="small" clearable placeholder="链路" class="task-driver-filter"><el-option label="全协议" value="protocol" /><el-option label="Camoufox" value="camoufox" /></el-select>
            <el-select v-model="runKindFilter" size="small" clearable placeholder="类型" class="task-driver-filter"><el-option v-for="(label, kind) in RUN_KIND_LABELS" :key="kind" :label="label" :value="kind" /></el-select>
            <div class="task-actions">
              <span class="muted">已选 {{ selectedTasks.length }} 个</span>
              <el-button v-if="['success', 'partial_success', 'twofa_pending', 'pending_rerun'].includes(taskStatusFilter)" size="small" type="warning" :icon="Refresh" :disabled="!selectedTasks.some(task => !isHistoricalDriver(task) && (['failed', 'stopped', 'pending_rerun', 'twofa_pending'].includes(String(task.status || '')) || canRetryPassword(task)))" aria-label="按当前失败节点批量重试" @click="batchRetryCurrentNode">按当前失败节点批量重试</el-button>
              <el-dropdown trigger="click" @command="(command: string) => handleCopyCommand(command)">
                <el-button size="small" :icon="CopyDocument" :disabled="!selectedTasks.length" aria-label="批量复制账号凭据">复制<el-icon class="el-icon--right"><ArrowDown /></el-icon></el-button>
                <template #dropdown>
                  <el-dropdown-menu>
                    <el-dropdown-item command="token"><el-icon><Key /></el-icon>复制 Token</el-dropdown-item>
                    <el-dropdown-item command="password"><el-icon><Lock /></el-icon>复制密码</el-dropdown-item>
                    <el-dropdown-item command="totp"><el-icon><Tickets /></el-icon>复制 TOTP</el-dropdown-item>
                    <el-dropdown-item command="credential"><el-icon><Document /></el-icon>复制完整凭据</el-dropdown-item>
                    <el-dropdown-item command="filtered-token" divided :disabled="!filteredRuns.some(row => row.task?.result?.has_access_token)"><el-icon><CopyDocument /></el-icon>复制当前筛选 Token</el-dropdown-item>
                  </el-dropdown-menu>
                </template>
              </el-dropdown>
              <el-button size="small" type="danger" plain :icon="Delete" :disabled="!selectedTasks.length || loading" @click="deleteSelectedTasks" aria-label="删除选中">删除选中</el-button>
              <el-button size="small" :icon="Refresh" @click="refresh" aria-label="刷新任务">刷新任务</el-button>
            </div>
          </div>
          <el-table ref="taskTable" v-loading="loading" :data="pagedRuns" row-key="key" :tree-props="{ children: 'children' }" height="100%" size="small" border :row-class-name="runRowClass" @header-dragend="(newWidth: number, oldWidth: number, column: DragColumn) => onTaskHeaderDragend(newWidth, oldWidth, column)" @selection-change="handleTaskSelection">
            <el-table-column type="selection" width="42" reserve-selection :selectable="runSelectable" />
            <el-table-column type="index" label="序号" width="58" align="center" :index="(index: number) => index + 1 + (taskPage - 1) * taskPageSize" />
            <el-table-column label="类型" :width="taskColWidth('类型', 88)" align="center">
              <template #default="{ row }"><el-tag size="small" :type="kindTagType(row.kind)" effect="plain">{{ row.kindLabel }}</el-tag></template>
            </el-table-column>
            <el-table-column label="账号" :width="taskColWidth('账号', 240)" show-overflow-tooltip>
              <template #default="{ row }">
                <div v-if="row.task" class="account-cell">
                  <el-tooltip v-if="row.task.email" :content="`${String(row.task.email)}${row.task.task_id ? ` · 任务 ${row.task.task_id}` : ''}`" placement="top" :show-after="250"><el-button link class="email-copy" :loading="loadingEmailTaskIds.includes(String(row.task.task_id || ''))" @click.stop="copyTaskEmail(row.task)"><strong>{{ row.task.email }}</strong><el-icon v-if="!loadingEmailTaskIds.includes(String(row.task.task_id || ''))"><CopyDocument /></el-icon></el-button></el-tooltip>
                  <span class="account-subline">{{ taskDriverLabel(row.task.driver) }}<template v-if="taskCreatedText(row.task)"> · {{ taskCreatedText(row.task) }}</template></span>
                </div>
                <div v-else-if="row.plan" class="account-cell">
                  <el-tooltip :content="`${String(row.plan.email)}${row.plan.task_id ? ` · 任务 ${row.plan.task_id}` : ''}`" placement="top" :show-after="250"><el-button link class="email-copy" :loading="loadingEmailTaskIds.includes(String(row.plan.task_id || ''))" @click.stop="copyRunEmail(row.plan)"><strong>{{ row.plan.email }}</strong><el-icon v-if="!loadingEmailTaskIds.includes(String(row.plan.task_id || ''))"><CopyDocument /></el-icon></el-button></el-tooltip>
                  <span class="account-subline">{{ row.kindLabel }} · {{ formatShortDateTime(row.createdAt) }}</span>
                </div>
                <div v-else class="account-cell">
                  <el-tooltip :content="`${String(row.job?.email)}${row.job?.task_id ? ` · 任务 ${row.job.task_id}` : ''}`" placement="top" :show-after="250"><el-button link class="email-copy" :loading="loadingEmailTaskIds.includes(String(row.job?.task_id || ''))" @click.stop="copyRunEmail(row.job || {})"><strong>{{ row.job?.email }}</strong><el-icon v-if="!loadingEmailTaskIds.includes(String(row.job?.task_id || ''))"><CopyDocument /></el-icon></el-button></el-tooltip>
                  <span class="account-subline">{{ row.kindLabel }} · {{ formatShortDateTime(row.createdAt) }}</span>
                </div>
              </template>
            </el-table-column>
            <el-table-column label="验证码" :width="taskColWidth('验证码', 96)" align="center">
              <template #default="{ row }">
                <template v-if="row.task"><TaskVerificationInput v-if="!isHistoricalDriver(row.task) && row.task.manual_verification?.can_submit" :task-id="row.task.task_id" :request="row.task.manual_verification" :now-seconds="nowSeconds" /><span v-else-if="!isHistoricalDriver(row.task) && row.task.mailbox_verification?.phase === 'automatic'" class="automatic-otp-wait">自动取码 <strong>{{ automaticOtpRemaining(row.task) }}s</strong></span></template>
              </template>
            </el-table-column>
            <el-table-column label="阶段 / 耗时" :width="taskColWidth('阶段 / 耗时', 210)">
              <template #default="{ row }">
                <TaskProgressCell v-if="row.task" :progress="row.task.progress" :timing="row.task.timing" :now-seconds="nowSeconds" :status="row.task.status" />
                <TaskProgressCell v-else-if="row.job" :progress="liveRunProgress(row.job)" :timing="row.job.timing" :now-seconds="nowSeconds" :status="row.job.status" />
                <TaskProgressCell v-else-if="row.plan" :progress="planRunProgress(row.plan)" :now-seconds="nowSeconds" :status="row.plan.status" />
              </template>
            </el-table-column>
            <el-table-column label="状态" :width="taskColWidth('状态', 100)" align="center" show-overflow-tooltip>
              <template #default="{ row }">
                <el-tag v-if="row.plan" size="small" :type="planStatusType(row.plan.status)">{{ planStatusLabel(row.plan.status) }}</el-tag>
                <el-tag v-else-if="row.job" size="small" :type="liveStatusType(row.job?.status)">{{ liveStatusLabel(row.job?.status) }}</el-tag>
                <el-tag v-else size="small" :type="isRetryResolved(row.task?.retry_resolved) ? 'success' : taskStatusType(row.task?.status || '')">{{ displayTaskStatus(row.task) }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="套餐" :width="taskColWidth('套餐', 90)" align="center" show-overflow-tooltip>
              <template #default="{ row }">
                <template v-if="row.task"><el-tag size="small" :type="taskPlanType(row.task)" effect="plain">{{ taskPlanLabel(row.task) }}</el-tag><el-tooltip v-if="!isHistoricalDriver(row.task) && row.task.result?.has_access_token && String(row.task.result?.plan_check_status || '').toLowerCase() === 'failed'" content="重新查询套餐" placement="top" :show-after="250"><el-button link size="small" :icon="Refresh" :loading="planBusy === String(row.task.task_id || row.task.row_id)" :disabled="Boolean(planBusy)" aria-label="重新查询套餐" @click.stop="refreshPlan(row.task)" /></el-tooltip></template>
              </template>
            </el-table-column>
            <el-table-column label="凭据" :width="taskColWidth('凭据', 120)">
              <template #default="{ row }">
                <div v-if="row.task" class="credential-cell"><StateDot :tone="taskTwofaType(row.task)" :label="`2FA ${taskTwofaLabel(row.task)}`" /><StateDot :tone="taskPasswordType(row.task)" :label="`密码 ${taskPasswordLabel(row.task)}`" /></div>
              </template>
            </el-table-column>
            <el-table-column label="错误" :min-width="taskColWidth('错误', 260)">
              <template #default="{ row }">
                <template v-if="row.task">
                  <el-tooltip placement="top" :disabled="!taskFailureDetails(row.task).length" :show-after="250">
                    <template #content><div class="failure-tooltip"><span v-for="item in taskFailureDetails(row.task)" :key="item">{{ item }}</span></div></template>
                    <div class="failure-cell">
                      <span class="failure-summary"><template v-if="isRetryResolved(row.task.retry_resolved)"><strong class="resolved-text">已由重试解决</strong></template><template v-else-if="taskIsAccountBanned(row.task)"><strong>{{ ACCOUNT_BANNED_DISPLAY_MESSAGE }}<code>{{ taskFailureNode(row.task).code || 'account_banned' }}</code></strong></template><template v-else><strong v-if="taskFailureNode(row.task).label || taskFailureNode(row.task).code">{{ taskFailureNode(row.task).label || taskFailureNode(row.task).code }}<code v-if="taskFailureNode(row.task).showCode">{{ taskFailureNode(row.task).code }}</code></strong><span>{{ taskFailureCause(row.task) }}</span><span v-if="!row.task.failure && row.task.retry_failure" class="failure-action-hint">自动重试子任务失败（展开本行子任务查看子任务记录）</span><span v-if="taskNeedsExistingPassword(row.task)" class="failure-action-hint">需补录真实密码后再处理；不会使用注册默认密码</span></template></span>
                    </div>
                  </el-tooltip>
                </template>
                <div v-else-if="row.plan" class="failure-cell">
                  <el-tooltip v-if="row.plan?.failure" placement="top" :disabled="!freeFailureDetails(row.plan?.failure).length" :show-after="250">
                    <template #content><div class="failure-tooltip"><span v-for="item in freeFailureDetails(row.plan?.failure)" :key="item">{{ item }}</span></div></template>
                    <span class="failure-summary"><strong v-if="row.plan?.failure?.node_label || row.plan?.failure?.node_code">{{ row.plan?.failure?.node_label || row.plan?.failure?.node_code }}</strong><span v-if="row.plan?.failure?.public_message || row.plan?.failure?.technical_summary">{{ row.plan?.failure?.public_message || row.plan?.failure?.technical_summary }}</span></span>
                  </el-tooltip>
                </div>
                <div v-else class="failure-cell">
                  <el-tooltip v-if="row.job?.failure" placement="top" :disabled="!freeFailureDetails(row.job?.failure).length" :show-after="250">
                    <template #content><div class="failure-tooltip"><span v-for="item in freeFailureDetails(row.job?.failure)" :key="item">{{ item }}</span></div></template>
                    <span class="failure-summary"><strong v-if="row.job?.failure?.node_label || row.job?.failure?.node_code">{{ row.job?.failure?.node_label || row.job?.failure?.node_code }}</strong><span v-if="row.job?.failure?.public_message || row.job?.failure?.technical_summary">{{ row.job?.failure?.public_message || row.job?.failure?.technical_summary }}</span></span>
                  </el-tooltip>
                </div>
              </template>
            </el-table-column>
            <el-table-column label="操作" :width="taskColWidth('操作', 64)" align="center" fixed="right">
              <template #default="{ row }">
                <el-dropdown v-if="!row.task" trigger="click" @command="(command: string) => handleRunAction(command, row)">
                  <el-button link class="row-action-button" :aria-label="row.plan ? '打开套餐查询操作菜单' : '打开测活操作菜单'" :title="row.plan ? '打开套餐查询操作菜单' : '打开测活操作菜单'"><el-icon><MoreFilled /></el-icon></el-button>
                  <template #dropdown>
                    <el-dropdown-menu>
                      <el-dropdown-item v-if="row.job" command="live_log"><el-icon><Document /></el-icon>查看测活日志</el-dropdown-item>
                      <el-dropdown-item v-else-if="row.plan" command="plan_log"><el-icon><Document /></el-icon>查看运行日志</el-dropdown-item>
                    </el-dropdown-menu>
                  </template>
                </el-dropdown>
                <el-dropdown v-else trigger="click" @command="(command: string) => handleTaskAction(command, row.task)">
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
          <el-pagination
            v-model:current-page="taskPage"
            v-model:page-size="taskPageSize"
            class="task-pager"
            size="small"
            background
            layout="total, sizes, prev, pager, next"
            :page-sizes="[25, 50, 100]"
            :total="filteredRuns.length"
          />
        </div>
      </WorkspacePanel>
    </div>
    <FreeTaskLogDialog ref="logDialog" v-model="logDialogOpen" :task="dialogTask" />
    <el-dialog v-model="startProgressOpen" title="Free 注册启动进度" width="440px" append-to-body :close-on-click-modal="false">
      <div class="start-progress">
        <el-progress :percentage="startProgressPercent" :status="startProgressStatus" :stroke-width="10" />
        <ul class="start-progress-stages">
          <li v-for="(item, index) in START_STAGES" :key="item.key" :class="startStageClass(index)">
            <el-icon v-if="startStageClass(index) === 'is-done'"><Check /></el-icon>
            <el-icon v-else-if="startStageClass(index) === 'is-active'" class="is-spin"><Loading /></el-icon>
            <span v-else class="stage-dot"></span>
            <span class="stage-label">{{ item.label }}</span>
            <span v-if="startStageClass(index) === 'is-active' && state.startup?.detail" class="stage-detail">{{ state.startup.detail }}</span>
          </li>
        </ul>
        <p class="start-progress-elapsed">
          当前阶段：{{ state.startup?.label || '准备中' }}<template v-if="startElapsedSeconds > 0"> · 已进行 {{ startElapsedSeconds }} 秒</template>
        </p>
        <el-alert
          v-if="state.start_failure"
          class="start-progress-error"
          type="error"
          :closable="false"
          show-icon
          :title="`启动失败：${state.start_failure.node_label}（${state.start_failure.node_code}）`"
          :description="state.start_failure.public_message"
        />
      </div>
      <template #footer>
        <el-button size="small" @click="startProgressOpen = false">后台等待</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.free-page { width: 100%; height: 100%; min-width: 0; min-height: 0; }
.muted { color: var(--el-text-color-secondary); font-size: 12px; }
.task-view { min-width: 0; min-height: 0; height: 100%; }
.task-view :deep(.workspace-panel) { height: 100%; }
.task-panel { display: grid; grid-template-rows: auto auto minmax(0, 1fr) auto; gap: var(--workspace-gap); height: 100%; min-height: 0; padding: 10px; }
.task-pager { justify-content: flex-end; }
.task-start-bar, .task-filter-row { display: flex; align-items: center; gap: var(--workspace-gap); min-width: 0; }
.task-launch-column { display: grid; gap: 8px; }
.task-start-status { --el-alert-padding: 6px 12px; }
.start-progress { display: grid; gap: 12px; }
.start-progress-stages { list-style: none; margin: 0; padding: 0; display: grid; gap: 8px; }
.start-progress-stages li { display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--el-text-color-secondary); }
.start-progress-stages li.is-active { color: var(--el-color-primary); font-weight: 600; }
.start-progress-stages li.is-done { color: var(--el-text-color-regular); }
.start-progress-stages .stage-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--el-fill-color-darker); flex: 0 0 auto; }
.start-progress-stages .stage-detail { margin-left: auto; font-size: 12px; font-weight: 400; color: var(--el-text-color-secondary); }
.start-progress-elapsed { margin: 0; font-size: 12px; color: var(--el-text-color-secondary); }
.start-progress-error { --el-alert-padding: 6px 12px; }
.is-spin { animation: start-progress-spin 1s linear infinite; }
@keyframes start-progress-spin { to { transform: rotate(360deg); } }
.task-start-bar { min-height: 32px; }
.task-start-bar .task-start-meta { margin-right: auto; }
.quick-run-field { display: inline-flex; align-items: center; gap: 8px; color: var(--el-text-color-regular); font-size: 14px; white-space: nowrap; }
.quick-run-field.quick-run-switch span { font-size: 12px; color: var(--el-text-color-secondary); }
.driver-inline-radio { flex: 0 0 auto; white-space: nowrap; }
.driver-inline-radio :deep(.el-radio-button__inner) { padding: 5px 12px; font-size: 12px; }
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
.task-panel :deep(.el-table td.el-table__cell),
.task-panel :deep(.el-table th.el-table__cell) { padding-top: 3px; padding-bottom: 3px; }
.task-panel :deep(.el-table .cell) { line-height: 18px; }
.account-cell { display: flex; flex-direction: column; gap: 1px; min-width: 0; }
.account-subline { display: block; overflow: hidden; color: var(--el-text-color-secondary); font-size: 11px; line-height: 15px; text-overflow: ellipsis; white-space: nowrap; }
.email-copy { display: inline-flex; max-width: 100%; min-width: 0; gap: 5px; height: auto; padding: 0; color: var(--el-text-color-primary); justify-content: flex-start; }
.email-copy strong { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.email-copy .el-icon { flex: 0 0 auto; color: var(--el-color-primary); }
.credential-cell { display: flex; flex-direction: column; align-items: center; gap: 2px; min-width: 0; }
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
