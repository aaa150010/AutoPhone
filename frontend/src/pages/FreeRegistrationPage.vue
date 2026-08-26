<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { CircleCheck, Connection, CopyDocument, Delete, Refresh, Setting, VideoPause, VideoPlay, View } from '@element-plus/icons-vue'
import { deleteFreeTasks, getFreeConfig, getFreeMailboxUrl, getFreeSecret, getFreeState, preflightFree, rerunFreeTask, startFree, startFreePlanCheck, stopFree, type FreeConfig, type FreeState } from '../api/client'
import PageToolbar from '../components/PageToolbar.vue'
import WorkspacePanel from '../components/WorkspacePanel.vue'
import ContentEmptyState from '../components/ContentEmptyState.vue'
import FreeTaskLogDialog from '../components/FreeTaskLogDialog.vue'
import { currentRelease } from '../releaseNotes'
import { freeFailureCause, freeFailureDetails, freeFailureNodeIdentity } from '../utils/freeFailure'

const defaultConfig: FreeConfig = {
  driver: 'protocol', flow_profile: 'reference_20260823', proxy_allocation_mode: 'healthy_random', target_count: 1, concurrency: 3, email_code_timeout: 90, auto_set_2fa: true,
  mailbox_network_mode: 'local_proxy', mailbox_proxy_url: 'http://127.0.0.1:7897',
  mailbox_request_retries: 3, mailbox_retry_backoff_seconds: 1,
  proxy_probe_url: 'https://api.ipify.org', protocol: { node_runner: '', sentinel_version: '20260219f9f6', sentinel_timeout: 90, network_timeout: 20, network_preflight_retries: 3, security_challenge_wait_seconds: 60, anonymous_warmup: true, authenticated_warmup: true, geo_probe_url: 'https://ipwho.is/' },
  proxy_default_scheme: 'http',
  roxybrowser: {
    api_base: 'http://127.0.0.1:50000', api_key: '', workspace_id: '', project_id: '',
    workspace_list_path: '/browser/workspace', create_path: '/browser/create', open_path: '/browser/open',
    close_path: '/browser/close', delete_path: '/browser/delete', headless: true, force_open: false, keep_browser_open: false,
    one_profile_per_account: true, delete_profile_after_run: true, random_os: true, os_choices: ['Windows', 'macOS'],
    random_profile_name: true, profile_name_prefix: 'rb', proxy_check_channel: 'IPRust.io', selenium_timeout: 90,
    api_retries: 3, api_retry_delay: 2, humanize_delay: true, humanize_factor: 1,
    humanize_browser_actions: true, existing_account_login: true, post_registration_dwell_min: 18, post_registration_dwell_max: 45,
  },
  camoufox: {
    headless: true, pool_size: 2, max_contexts_per_browser: 3, context_start_interval_ms: 175,
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
const quickTargetCount = ref(defaultConfig.target_count)
const quickConcurrency = ref(defaultConfig.concurrency)
const quickRunDirty = ref(false)
let timer = 0

const running = computed(() => Boolean(state.value.running))
const pendingRoxyCleanup = computed(() => Math.max(0, Number(state.value.roxy_cleanup?.pending || 0)))
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
      && (taskStatusFilter.value === 'all' || (taskStatusFilter.value === 'active' ? ['queued', 'running'].includes(task.status) : task.status === taskStatusFilter.value))
      && (!taskDriverFilter.value || task.driver === taskDriverFilter.value)
  })
})
const taskCounts = computed(() => {
  const count = (status: string) => visibleTasks.value.filter(task => task.status === status).length
  return { total: visibleTasks.value.length, running: count('running') + count('queued'), success: count('success') + count('partial_success'), partial: count('partial_success'), failed: count('failed'), pending: count('twofa_pending'), rerun: count('pending_rerun'), stopped: count('stopped') }
})
const selectedTask = computed(() => visibleTasks.value.find(task => task.task_id === selectedTaskId.value))
const runtimeMismatch = computed(() => {
  const loaded = String(state.value.runtime_version || '').trim()
  const expected = currentRelease.freeRuntimeVersion || currentRelease.version
  return !loaded || loaded !== expected
})
function mergeConfig(value: any, forceQuickRun = false) {
  if (!value || typeof value !== 'object') return
  Object.assign(config, value)
  Object.assign(config.protocol, value.protocol || {})
  Object.assign(config.roxybrowser, value.roxybrowser || {})
  Object.assign(config.camoufox, value.camoufox || {})
  config.target_count = Math.min(200, Math.max(1, Number(config.target_count) || 1))
  config.concurrency = Math.min(16, Math.max(1, Number(config.concurrency) || 1))
  if (forceQuickRun || !quickRunDirty.value) {
    quickTargetCount.value = config.target_count
    quickConcurrency.value = config.concurrency
  }
}

function quickRunConfig(): FreeConfig {
  return {
    ...config,
    target_count: Math.min(200, Math.max(1, Number(quickTargetCount.value) || 1)),
    concurrency: Math.min(16, Math.max(1, Number(quickConcurrency.value) || 1)),
  }
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
  const email = String(task?.email || '').trim()
  if (!email) return
  try {
    await navigator.clipboard.writeText(email)
    ElMessage.success('已复制邮箱')
  } catch {
    ElMessage.error('邮箱复制失败')
  }
}

async function openTaskMailboxUrl(task: any) {
  const taskId = String(task?.task_id || '').trim()
  const rowId = String(task?.row_id || '').trim()
  if (!task?.has_mailbox_url || !taskId || !rowId || openingMailboxUrlTaskIds.value.includes(taskId)) return
  const target = window.open('', '_blank')
  if (!target) {
    ElMessage.error('浏览器阻止了新窗口，请允许弹出窗口后重试')
    return
  }
  target.opener = null
  openingMailboxUrlTaskIds.value = [...openingMailboxUrlTaskIds.value, taskId]
  try {
    const result = await getFreeMailboxUrl(rowId)
    const value = String(result.mailbox_url || '').trim()
    const destination = new URL(value)
    if (!['http:', 'https:'].includes(destination.protocol)) throw new Error('取件 URL 协议不安全')
    target.location.replace(destination.href)
  } catch (error: any) {
    target.close()
    ElMessage.error(error?.message || '打开取件 URL 失败')
  } finally {
    openingMailboxUrlTaskIds.value = openingMailboxUrlTaskIds.value.filter(id => id !== taskId)
  }
}

async function copyIncidentId(value: string) {
  const incidentId = String(value || '').trim()
  if (!incidentId) return
  if (!navigator.clipboard?.writeText) {
    ElMessage.warning('当前环境不支持复制')
    return
  }
  try {
    await navigator.clipboard.writeText(incidentId)
    ElMessage.success('日志 ID 已复制')
  } catch {
    ElMessage.error('日志 ID 复制失败')
  }
}

function openIncidentCenter(value: string) {
  const incidentId = String(value || '').trim()
  if (incidentId) emit('navigate', `/logs?incident_id=${encodeURIComponent(incidentId)}`)
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
  if (!taskId || !['failed', 'stopped'].includes(String(task?.status || ''))) return
  try {
    await ElMessageBox.confirm(
      `仅当该账号已自动恢复为可用时才会重跑。确定重跑 ${task.email || taskId} 吗？`,
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
    ElMessage.success(`已启动重跑批次 ${result.batch_id || ''}`)
    await refresh()
  } catch (error: any) {
    ElMessage.error(error?.message || 'Free 账号重跑失败')
  } finally {
    loading.value = false
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

function taskStatusLabel(status: string) {
  return ({ queued: '排队', running: '运行中', success: '成功', partial_success: '部分成功', failed: '失败', pending_rerun: '待重跑', stopped: '已停止', twofa_pending: '2FA 待重试' } as Record<string, string>)[status] || status || '-'
}

function taskStatusType(status: string) {
  return status === 'success' ? 'success' : ['partial_success', 'pending_rerun'].includes(status) ? 'warning' : status === 'failed' ? 'danger' : status === 'stopped' ? 'info' : 'warning'
}

function taskFailureCause(task: any) {
  return freeFailureCause(task?.failure)
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
    <PageToolbar title="Free 注册中心" :status="running ? '运行中' : '独立链路'" :tone="running ? 'success' : 'info'">
      <el-tag effect="plain">配置入口：运行配置 &gt; Free 注册运行</el-tag>
      <el-tag v-if="runtimeMismatch" type="warning" effect="plain">后端需要重启</el-tag>
      <el-tag v-else type="success" effect="plain">后端 {{ state.runtime_version }} · OTP {{ state.otp_parser_revision }}</el-tag>
      <el-button size="small" :icon="Setting" @click="emit('navigate', '/settings#free-register')">打开运行配置</el-button>
    </PageToolbar>
    <div class="task-view">
      <WorkspacePanel title="Free 注册任务" :icon="Connection" fill body-padding="none">
        <div class="task-panel">
          <div class="run-snapshot task-summary"><div><span>可用 Free 邮箱</span><strong class="is-good">{{ Number(state.pool?.available || 0) }}</strong></div><div><span>任务总数</span><strong>{{ taskCounts.total }}</strong></div><div><span>排队 / 运行</span><strong>{{ taskCounts.running }}</strong></div><div><span>成功</span><strong class="is-good">{{ taskCounts.success - taskCounts.partial }}</strong></div><div><span>部分成功</span><strong class="is-warn">{{ taskCounts.partial }}</strong></div><div><span>失败</span><strong class="is-bad">{{ taskCounts.failed }}</strong></div><div><span>待重跑</span><strong class="is-warn">{{ taskCounts.rerun }}</strong></div><div><span>2FA 待重试</span><strong class="is-warn">{{ taskCounts.pending }}</strong></div></div>
          <div class="task-start-bar">
            <el-tag effect="plain">{{ config.driver === 'roxybrowser' ? 'RoxyBrowser' : config.driver === 'camoufox' ? 'Camoufox' : '全协议' }}</el-tag>
            <el-tag v-if="pendingRoxyCleanup > 0" type="warning" effect="light">待清理 Profile {{ pendingRoxyCleanup }}</el-tag>
            <label class="quick-run-field"><span>注册数量</span><el-input-number v-model="quickTargetCount" class="quick-run-number" :min="1" :max="200" controls-position="right" :disabled="running || Boolean(busy)" @update:model-value="markQuickRunDirty" /></label>
            <label class="quick-run-field"><span>并发</span><el-input-number v-model="quickConcurrency" class="quick-run-number" :min="1" :max="16" controls-position="right" :disabled="running || Boolean(busy)" @update:model-value="markQuickRunDirty" /></label>
            <span class="muted">配置并发 {{ quickConcurrency }} · 实际 Slot {{ Number(state.scheduler?.active_slots || 0) }}/{{ Number(state.scheduler?.concurrency || quickConcurrency) }} · 可用邮箱 {{ Number(state.pool?.available || 0) }} · 代理 {{ Number(state.pool?.proxies || 0) }}</span>
            <el-button size="small" :icon="CircleCheck" :loading="busy === 'preflight'" :disabled="running" @click="preflight">预检</el-button>
            <el-button size="small" type="primary" :icon="VideoPlay" :loading="busy === 'start'" :disabled="running || !Number(state.pool?.available || 0)" @click="start">开始注册</el-button>
            <el-button size="small" type="danger" plain :icon="VideoPause" :loading="busy === 'stop'" :disabled="!running" @click="stop">停止</el-button>
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
            <el-select v-model="taskDriverFilter" size="small" clearable placeholder="链路" class="task-driver-filter"><el-option label="全协议" value="protocol" /><el-option label="RoxyBrowser" value="roxybrowser" /><el-option label="Camoufox" value="camoufox" /></el-select>
          </div>
          <div class="task-actions"><span class="muted">已选 {{ selectedTasks.length }} 个</span><el-button size="small" :icon="CopyDocument" :disabled="!selectedTasks.length" @click="copyTaskSecret('token', selectedTasks, 'Token')">复制 Token</el-button><el-button size="small" :icon="CopyDocument" :disabled="!selectedTasks.length" @click="copyTaskSecret('password', selectedTasks, '密码')">复制密码</el-button><el-button size="small" :icon="CopyDocument" :disabled="!selectedTasks.length" @click="copyTaskSecret('totp', selectedTasks, 'TOTP')">复制 TOTP</el-button><el-button size="small" :icon="CopyDocument" :disabled="!selectedTasks.length" @click="copyTaskSecret('credential', selectedTasks, '完整凭据')">复制完整凭据</el-button><el-button size="small" :icon="CopyDocument" :disabled="!filteredTasks.some(task => task.result?.has_access_token)" @click="copyTaskTokens(filteredTasks)">复制当前筛选 Token</el-button><el-button size="small" type="danger" plain :icon="Delete" :disabled="!selectedTasks.length || loading" @click="deleteSelectedTasks">删除选中</el-button><el-button size="small" :icon="Refresh" @click="refresh">刷新任务</el-button></div>
          <el-table ref="taskTable" :data="filteredTasks" row-key="task_id" height="100%" size="small" @selection-change="handleTaskSelection">
            <el-table-column type="selection" width="42" reserve-selection />
            <el-table-column type="index" label="序号" width="58" align="center" fixed="left" />
            <el-table-column label="账号" min-width="220" show-overflow-tooltip><template #default="{ row }"><el-tooltip v-if="row.email" content="点击复制邮箱" placement="top"><el-button link class="email-copy" @click.stop="copyTaskEmail(row)"><strong>{{ row.email }}</strong><el-icon><CopyDocument /></el-icon></el-button></el-tooltip><span v-else>-</span><small class="task-subline">{{ row.task_id }}</small></template></el-table-column>
            <el-table-column label="取件 URL" width="92" align="center"><template #default="{ row }"><el-tooltip v-if="row.has_mailbox_url" content="打开取件网页" placement="top"><el-button link :icon="View" :loading="openingMailboxUrlTaskIds.includes(String(row.task_id || ''))" aria-label="打开取件网页" @click.stop="openTaskMailboxUrl(row)">打开</el-button></el-tooltip><span v-else class="muted">-</span></template></el-table-column>
            <el-table-column label="链路 / 阶段" min-width="190" show-overflow-tooltip><template #default="{ row }"><el-tag size="small" effect="plain">{{ row.driver === 'roxybrowser' ? 'RoxyBrowser' : row.driver === 'camoufox' ? 'Camoufox' : '全协议' }}</el-tag><small v-if="row.result?.account_flow" class="task-subline">{{ row.result.account_flow === 'existing_login' ? '已有账号登录' : '新账号注册' }}</small><small class="task-subline">{{ row.stage_label || row.stage || '-' }}</small></template></el-table-column>
            <el-table-column label="Slot" width="78" align="center"><template #default="{ row }">{{ row.slot_index || '-' }} / {{ row.concurrency_limit || config.concurrency }}</template></el-table-column>
            <el-table-column label="代理池" min-width="180" show-overflow-tooltip><template #default="{ row }"><span>共享健康随机池</span><small class="task-subline">{{ row.proxy_scheme || '' }} · {{ row.proxy_masked || '' }}</small></template></el-table-column>
            <el-table-column label="状态" width="92" align="center"><template #default="{ row }"><el-tag size="small" :type="taskStatusType(row.status)">{{ taskStatusLabel(row.status) }}</el-tag></template></el-table-column>
            <el-table-column label="套餐" min-width="155" show-overflow-tooltip><template #default="{ row }"><el-tag size="small" :type="taskPlanType(row)" effect="light">{{ taskPlanLabel(row) }}</el-tag><el-tooltip v-if="row.result?.has_access_token && String(row.result?.plan_check_status || '').toLowerCase() === 'failed'" content="重新查询套餐"><el-button link size="small" :icon="Refresh" :loading="planBusy === String(row.task_id || row.row_id)" :disabled="Boolean(planBusy)" aria-label="重新查询套餐" @click.stop="refreshPlan(row)" /></el-tooltip></template></el-table-column>
            <el-table-column label="2FA" width="92" align="center"><template #default="{ row }"><el-tag size="small" :type="taskTwofaType(row)" effect="plain">{{ taskTwofaLabel(row) }}</el-tag></template></el-table-column>
            <el-table-column label="Profile" min-width="110" show-overflow-tooltip><template #default="{ row }">{{ row.profile_summary || '-' }}</template></el-table-column>
            <el-table-column label="Token" width="72" align="center"><template #default="{ row }"><el-button v-if="row.result?.has_access_token" link :icon="CopyDocument" aria-label="复制该账号 Token" @click.stop="copyTaskTokens([row])" /><span v-else class="muted">-</span></template></el-table-column>
            <el-table-column label="错误" min-width="280">
              <template #default="{ row }">
                <el-tooltip placement="top" :disabled="!taskFailureDetails(row).length">
                  <template #content><div class="failure-tooltip"><span v-for="item in taskFailureDetails(row)" :key="item">{{ item }}</span></div></template>
                  <div class="failure-cell">
                    <strong v-if="taskFailureNode(row).label || taskFailureNode(row).code">{{ taskFailureNode(row).label || taskFailureNode(row).code }}<code v-if="taskFailureNode(row).showCode">{{ taskFailureNode(row).code }}</code></strong>
                    <span>{{ taskFailureCause(row) }}</span>
                    <small v-if="row.incident_id" class="task-incident">
                      <el-button text size="small" :icon="CopyDocument" @click.stop="copyIncidentId(row.incident_id)">日志 ID {{ row.incident_id }}</el-button>
                      <el-button text size="small" :icon="View" aria-label="打开故障详情" @click.stop="openIncidentCenter(row.incident_id)" />
                    </small>
                  </div>
                </el-tooltip>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="92" align="center" fixed="right"><template #default="{ row }"><el-tooltip content="查看该账号日志"><el-button link :icon="View" aria-label="查看该账号日志" @click.stop="openTaskLog(row)" /></el-tooltip><el-tooltip v-if="['failed', 'stopped'].includes(String(row.status || ''))" content="重跑该账号"><el-button link :icon="Refresh" aria-label="重跑该账号" :disabled="loading" @click.stop="rerunTask(row)" /></el-tooltip></template></el-table-column>
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
.task-filter-bar { display: grid; grid-template-columns: minmax(260px, 1.2fr) minmax(420px, 2fr) repeat(3, 150px); min-height: 32px; }
.task-filter-bar > .el-input, .task-filter-bar > .task-driver-filter { width: 100%; }
.task-status-filter { flex: 1; min-width: 0; }
.task-status-filter :deep(.el-radio-button__inner) { padding: 7px 10px; }
.task-driver-filter { width: 180px; }
.task-actions { justify-content: flex-end; min-height: 30px; }
.task-actions .muted { margin-right: auto; }
.task-panel :deep(.el-table) { min-height: 0; }
.task-panel :deep(.el-table .cell) { line-height: 18px; }
.task-subline { display: block; overflow: hidden; color: var(--el-text-color-secondary); font-size: 11px; line-height: 15px; text-overflow: ellipsis; white-space: nowrap; }
.email-copy { max-width: 100%; gap: 5px; color: var(--el-text-color-primary); }
.email-copy strong { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.email-copy .el-icon { flex: 0 0 auto; color: var(--el-color-primary); }
.failure-cell { display: grid; min-width: 0; line-height: 16px; }
.failure-cell strong, .failure-cell span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.failure-cell strong { color: var(--el-color-danger); font-size: 12px; font-weight: 650; }
.failure-cell code { margin-left: 5px; color: var(--el-text-color-secondary); font-size: 10px; font-weight: 500; }
.failure-cell span { color: var(--el-text-color-regular); font-size: 11px; }
.task-incident { display: flex; align-items: center; min-width: 0; gap: 2px; line-height: 16px; }
.task-incident .el-button { min-width: 0; padding: 0 2px; color: var(--el-color-primary); font-size: 10px; }
.task-incident .el-button:first-child { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.failure-tooltip { display: grid; max-width: 520px; gap: 4px; line-height: 18px; }
</style>
