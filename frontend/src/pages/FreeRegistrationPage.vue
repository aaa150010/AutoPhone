<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { CircleCheck, Connection, CopyDocument, Refresh, Setting, VideoPause, VideoPlay, View } from '@element-plus/icons-vue'
import { getFreeConfig, getFreeLogs, getFreeSecret, getFreeState, preflightFree, startFree, stopFree, type FreeConfig, type FreeState } from '../api/client'
import PageToolbar from '../components/PageToolbar.vue'
import WorkspacePanel from '../components/WorkspacePanel.vue'
import ContentEmptyState from '../components/ContentEmptyState.vue'

const defaultConfig: FreeConfig = {
  driver: 'protocol', target_count: 0, concurrency: 3, email_code_timeout: 90, auto_set_2fa: true,
  proxy_probe_url: 'https://api.ipify.org', protocol: { node_runner: '', sentinel_timeout: 90 },
  proxy_default_scheme: 'http', proxy_selection: { protocol: { country: '', group: '' }, roxybrowser: { country: '', group: '' } },
  roxybrowser: {
    api_base: 'http://127.0.0.1:50000', api_key: '', workspace_id: '', project_id: '',
    workspace_list_path: '/browser/workspace', create_path: '/browser/create', open_path: '/browser/open',
    close_path: '/browser/close', delete_path: '/browser/delete', headless: false, keep_browser_open: false,
    one_profile_per_account: true, delete_profile_after_run: true, random_os: true, os_choices: ['Windows', 'macOS'],
    random_profile_name: true, profile_name_prefix: 'rb', proxy_check_channel: 'IPRust.io', selenium_timeout: 90,
    api_retries: 3, api_retry_delay: 2, humanize_delay: true, humanize_factor: 1,
    humanize_browser_actions: true, post_registration_dwell_min: 18, post_registration_dwell_max: 45,
  },
}

const emit = defineEmits<{ navigate: [string] }>()
const config = reactive<FreeConfig>(structuredClone(defaultConfig))
const state = ref<FreeState>({ running: false, tasks: [], summary: {}, pool: {} })
const logs = ref<Array<{ time?: string; level?: string; message?: string; task_id?: string; stage?: string; stage_label?: string }>>([])
const selectedTaskId = ref('')
const taskSearch = ref('')
const taskStatusFilter = ref('all')
const taskDriverFilter = ref('')
const taskCountryFilter = ref('')
const taskGroupFilter = ref('')
const selectedTasks = ref<any[]>([])
const taskTable = ref<any>()
const logDialogOpen = ref(false)
const logLoading = ref(false)
const loading = ref(false)
const busy = ref<'preflight' | 'start' | 'stop' | ''>('')
let timer = 0

const running = computed(() => Boolean(state.value.running))
const visibleTasks = computed(() => (state.value.tasks || []).slice().sort((a, b) => Number(a.ordinal || 0) - Number(b.ordinal || 0)))
const filteredTasks = computed(() => {
  const query = taskSearch.value.trim().toLowerCase()
  return visibleTasks.value.filter(task => {
    const haystack = [task.email, task.task_id, task.registration_ip, task.expected_exit_ip, task.failure?.node_label].join(' ').toLowerCase()
    return (!query || haystack.includes(query))
      && (taskStatusFilter.value === 'all' || (taskStatusFilter.value === 'active' ? ['queued', 'running'].includes(task.status) : task.status === taskStatusFilter.value))
      && (!taskDriverFilter.value || task.driver === taskDriverFilter.value)
      && (!taskCountryFilter.value || task.proxy_country === taskCountryFilter.value)
      && (!taskGroupFilter.value || task.proxy_group === taskGroupFilter.value)
  })
})
const taskCountries = computed(() => [...new Set(visibleTasks.value.map(task => task.proxy_country).filter(Boolean))])
const taskGroups = computed(() => [...new Set(visibleTasks.value.filter(task => !taskCountryFilter.value || task.proxy_country === taskCountryFilter.value).map(task => task.proxy_group).filter(Boolean))])
const taskCounts = computed(() => {
  const count = (status: string) => visibleTasks.value.filter(task => task.status === status).length
  return { total: visibleTasks.value.length, running: count('running') + count('queued'), success: count('success') + count('partial_success'), partial: count('partial_success'), failed: count('failed'), pending: count('twofa_pending'), stopped: count('stopped') }
})
const selectedTask = computed(() => visibleTasks.value.find(task => task.task_id === selectedTaskId.value))
const selectedLogs = computed(() => {
  return logs.value.slice(-160).reverse()
})

function mergeConfig(value: any) {
  if (!value || typeof value !== 'object') return
  Object.assign(config, value)
  Object.assign(config.protocol, value.protocol || {})
  Object.assign(config.roxybrowser, value.roxybrowser || {})
}

async function refresh() {
  try {
    const result = await getFreeState()
    mergeConfig(result.config)
    state.value = result.state || state.value
    if (logDialogOpen.value && selectedTaskId.value) {
      logs.value = (await getFreeLogs(selectedTaskId.value)).logs || logs.value
    }
  } catch (error: any) {
    if (!loading.value) ElMessage.error(error?.message || 'Free 状态刷新失败')
  }
}

async function load() {
  loading.value = true
  try {
    const result = await getFreeConfig()
    mergeConfig(result.config)
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
    const result = await preflightFree(config)
    state.value = result.state || state.value
    ElMessage.success(`预检通过：${Number(result.result?.target_count || 0)} 个邮箱，${Number(result.result?.proxies || 0)} 个固定代理`)
  } catch (error: any) {
    ElMessage.error(error?.message || 'Free 预检失败')
  } finally {
    busy.value = ''
  }
}

async function start() {
  busy.value = 'start'
  try {
    const result = await startFree(config)
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

async function loadTaskLogs(taskId = selectedTaskId.value) {
  if (!taskId) return
  logLoading.value = true
  try {
    logs.value = (await getFreeLogs(taskId)).logs || []
  } catch (error: any) {
    ElMessage.error(error?.message || 'Free 账号日志读取失败')
  } finally {
    logLoading.value = false
  }
}

async function openTaskLog(task: any) {
  selectedTaskId.value = String(task?.task_id || '')
  logDialogOpen.value = true
  await loadTaskLogs(selectedTaskId.value)
}

async function copyTaskTokens(tasks: any[]) {
  await copyTaskSecret('token', tasks, 'Token')
}

async function copyTaskSecret(kind: 'token' | 'password' | 'totp' | 'credential', tasks: any[], label: string) {
  const ids = tasks.map(task => String(task?.task_id || '')).filter(Boolean)
  if (!ids.length) {
    ElMessage.warning('请先勾选账号')
    return
  }
  const eligible = kind === 'token'
    ? tasks.filter(task => task?.result?.has_access_token)
    : tasks.filter(task => kind === 'password' ? task?.result?.has_credential : kind === 'totp' ? task?.result?.twofa_status === 'enabled' : task?.result?.has_credential)
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

function taskStatusLabel(status: string) {
  return ({ queued: '排队', running: '运行中', success: '成功', partial_success: '部分成功', failed: '失败', stopped: '已停止', twofa_pending: '2FA 待重试' } as Record<string, string>)[status] || status || '-'
}

function taskStatusType(status: string) {
  return status === 'success' ? 'success' : status === 'partial_success' ? 'warning' : status === 'failed' ? 'danger' : status === 'stopped' ? 'info' : 'warning'
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
      <el-button size="small" :icon="Setting" @click="emit('navigate', '/settings#free-register')">打开运行配置</el-button>
    </PageToolbar>
    <div class="task-view">
      <WorkspacePanel title="Free 注册任务" :icon="Connection" fill body-padding="none">
        <div class="task-panel">
          <div class="run-snapshot task-summary"><div><span>任务总数</span><strong>{{ taskCounts.total }}</strong></div><div><span>排队 / 运行</span><strong>{{ taskCounts.running }}</strong></div><div><span>成功</span><strong class="is-good">{{ taskCounts.success - taskCounts.partial }}</strong></div><div><span>部分成功</span><strong class="is-warn">{{ taskCounts.partial }}</strong></div><div><span>失败</span><strong class="is-bad">{{ taskCounts.failed }}</strong></div><div><span>2FA 待重试</span><strong class="is-warn">{{ taskCounts.pending }}</strong></div></div>
          <div class="task-start-bar">
            <el-tag effect="plain">{{ config.driver === 'roxybrowser' ? 'RoxyBrowser' : '全协议' }}</el-tag>
            <span class="muted">并发 {{ config.concurrency }} · Slot {{ Number(state.scheduler?.active_slots || 0) }}/{{ Number(state.scheduler?.concurrency || config.concurrency) }} · 可用邮箱 {{ Number(state.pool?.available || 0) }} · 固定代理 {{ Number(state.pool?.proxies || 0) }}</span>
            <el-button size="small" :icon="CircleCheck" :loading="busy === 'preflight'" :disabled="running" @click="preflight">预检</el-button>
            <el-button size="small" type="primary" :icon="VideoPlay" :loading="busy === 'start'" :disabled="running || !Number(state.pool?.available || 0)" @click="start">开始注册</el-button>
            <el-button size="small" type="danger" plain :icon="VideoPause" :loading="busy === 'stop'" :disabled="!running" @click="stop">停止</el-button>
          </div>
          <div class="task-filter-bar">
            <el-input v-model="taskSearch" size="small" clearable placeholder="搜索邮箱、任务 ID、注册 IP 或失败节点" />
            <el-radio-group v-model="taskStatusFilter" size="small" class="task-status-filter">
              <el-radio-button value="all">全部 {{ taskCounts.total }}</el-radio-button>
              <el-radio-button value="active">排队/运行 {{ taskCounts.running }}</el-radio-button>
              <el-radio-button value="success">成功 {{ taskCounts.success - taskCounts.partial }}</el-radio-button>
              <el-radio-button value="partial_success">部分成功 {{ taskCounts.partial }}</el-radio-button>
              <el-radio-button value="failed">失败 {{ taskCounts.failed }}</el-radio-button>
              <el-radio-button value="twofa_pending">2FA {{ taskCounts.pending }}</el-radio-button>
              <el-radio-button value="stopped">已停止 {{ taskCounts.stopped }}</el-radio-button>
            </el-radio-group>
            <el-select v-model="taskDriverFilter" size="small" clearable placeholder="链路" class="task-driver-filter"><el-option label="全协议" value="protocol" /><el-option label="RoxyBrowser" value="roxybrowser" /></el-select>
            <el-select v-model="taskCountryFilter" size="small" clearable filterable placeholder="国家" class="task-driver-filter"><el-option v-for="country in taskCountries" :key="country" :label="country" :value="country" /></el-select>
            <el-select v-model="taskGroupFilter" size="small" clearable filterable placeholder="代理分组" class="task-driver-filter"><el-option v-for="group in taskGroups" :key="group" :label="group" :value="group" /></el-select>
          </div>
          <div class="task-actions"><span class="muted">已选 {{ selectedTasks.length }} 个</span><el-button size="small" :icon="CopyDocument" :disabled="!selectedTasks.length" @click="copyTaskSecret('token', selectedTasks, 'Token')">复制 Token</el-button><el-button size="small" :icon="CopyDocument" :disabled="!selectedTasks.length" @click="copyTaskSecret('password', selectedTasks, '密码')">复制密码</el-button><el-button size="small" :icon="CopyDocument" :disabled="!selectedTasks.length" @click="copyTaskSecret('totp', selectedTasks, 'TOTP')">复制 TOTP</el-button><el-button size="small" :icon="CopyDocument" :disabled="!selectedTasks.length" @click="copyTaskSecret('credential', selectedTasks, '完整凭据')">复制完整凭据</el-button><el-button size="small" :icon="CopyDocument" :disabled="!filteredTasks.some(task => task.result?.has_access_token)" @click="copyTaskTokens(filteredTasks)">复制当前筛选 Token</el-button><el-button size="small" :icon="Refresh" @click="refresh">刷新任务</el-button></div>
          <el-table ref="taskTable" :data="filteredTasks" row-key="task_id" height="100%" size="small" @selection-change="handleTaskSelection">
            <el-table-column type="selection" width="42" reserve-selection />
            <el-table-column type="index" label="序号" width="58" align="center" />
            <el-table-column label="账号" min-width="220" show-overflow-tooltip><template #default="{ row }"><strong>{{ row.email || '-' }}</strong><small class="task-subline">{{ row.task_id }}</small></template></el-table-column>
            <el-table-column label="链路 / 阶段" min-width="190" show-overflow-tooltip><template #default="{ row }"><el-tag size="small" effect="plain">{{ row.driver === 'roxybrowser' ? 'RoxyBrowser' : '全协议' }}</el-tag><small class="task-subline">{{ row.stage_label || row.stage || '-' }}</small></template></el-table-column>
            <el-table-column label="Slot" width="78" align="center"><template #default="{ row }">{{ row.slot_index || '-' }} / {{ row.concurrency_limit || config.concurrency }}</template></el-table-column>
            <el-table-column label="代理池" min-width="150" show-overflow-tooltip><template #default="{ row }"><span>{{ row.proxy_country || '-' }} / {{ row.proxy_group || '-' }}</span><small class="task-subline">{{ row.proxy_scheme || '' }} · {{ row.proxy_masked || '' }}</small></template></el-table-column>
            <el-table-column label="状态" width="92" align="center"><template #default="{ row }"><el-tag size="small" :type="taskStatusType(row.status)">{{ taskStatusLabel(row.status) }}</el-tag></template></el-table-column>
            <el-table-column label="注册 IP" min-width="135" show-overflow-tooltip><template #default="{ row }">{{ row.registration_ip || row.expected_exit_ip || '-' }}</template></el-table-column>
            <el-table-column label="套餐 / 2FA" min-width="130" show-overflow-tooltip><template #default="{ row }"><span>{{ row.result?.subscription_plan || row.result?.plan_type || '-' }}</span><small class="task-subline">{{ row.result?.plus_trial_eligible ? 'Plus 可试用' : '无 Plus 资格' }} · {{ row.result?.twofa_status || '-' }}</small></template></el-table-column>
            <el-table-column label="Profile" min-width="110" show-overflow-tooltip><template #default="{ row }">{{ row.profile_summary || '-' }}</template></el-table-column>
            <el-table-column label="Token" width="72" align="center"><template #default="{ row }"><el-button v-if="row.result?.has_access_token" link :icon="CopyDocument" aria-label="复制该账号 Token" @click.stop="copyTaskTokens([row])" /><span v-else class="muted">-</span></template></el-table-column>
            <el-table-column label="操作" width="60" align="center"><template #default="{ row }"><el-tooltip content="查看该账号日志"><el-button link :icon="View" aria-label="查看该账号日志" @click.stop="openTaskLog(row)" /></el-tooltip></template></el-table-column>
            <el-table-column label="错误节点" min-width="220" show-overflow-tooltip><template #default="{ row }">{{ row.failure?.node_label || row.failure?.public_message || row.error || row.result?.twofa_error || '-' }}</template></el-table-column>
            <template #empty><ContentEmptyState /></template>
          </el-table>
        </div>
      </WorkspacePanel>
    </div>
    <el-dialog v-model="logDialogOpen" :title="`${selectedTask?.email || 'Free 账号'} · ${selectedTask?.driver === 'roxybrowser' ? 'RoxyBrowser' : '全协议'} 日志`" width="900px" destroy-on-close>
      <div class="log-dialog-meta"><span>任务 {{ selectedTask?.task_id || '-' }}</span><span>阶段 {{ selectedTask?.stage_label || selectedTask?.stage || '-' }}</span><span>注册 IP {{ selectedTask?.registration_ip || selectedTask?.expected_exit_ip || '-' }}</span><el-button size="small" :icon="Refresh" :loading="logLoading" @click="loadTaskLogs()">刷新</el-button></div>
      <div v-loading="logLoading" class="log-dialog-list"><div v-for="(row, index) in selectedLogs" :key="`${row.time}-${index}-${row.message}`" :class="`log-${row.level || 'info'}`"><small>{{ row.time || '' }}</small><span><b v-if="row.stage_label || row.stage">{{ row.stage_label || row.stage }}</b> {{ row.message || '' }}</span></div><ContentEmptyState v-if="!selectedLogs.length && !logLoading" /></div>
    </el-dialog>
  </div>
</template>

<style scoped>
.free-page { display: grid; grid-template-rows: 44px minmax(0, 1fr); gap: 6px; width: 100%; height: 100%; min-width: 0; min-height: 0; }
.muted { color: var(--el-text-color-secondary); font-size: 12px; }
.task-view { min-width: 0; min-height: 0; height: 100%; }
.task-view :deep(.workspace-panel) { height: 100%; }
.task-panel { display: grid; grid-template-rows: auto auto auto auto minmax(0, 1fr); gap: 8px; height: 100%; min-height: 0; padding: 10px; }
.run-snapshot { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 1px; border: 1px solid var(--workspace-border); border-radius: var(--workspace-radius); overflow: hidden; }
.run-snapshot > div { display: grid; grid-template-rows: 18px 22px; align-items: center; min-height: 48px; padding: 5px 10px; background: #f8fafc; }
.run-snapshot span { color: var(--el-text-color-secondary); font-size: 13px; }
.run-snapshot strong { font-size: 17px; font-variant-numeric: tabular-nums; }
.run-snapshot strong.is-good { color: #168363; }
.run-snapshot strong.is-bad { color: #c44754; }
.run-snapshot strong.is-warn { color: #bc761c; }
.task-start-bar, .task-filter-bar, .task-actions { display: flex; align-items: center; gap: 8px; min-width: 0; }
.task-start-bar { min-height: 32px; }
.task-start-bar .muted { margin-right: auto; }
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
.log-dialog-meta { display: flex; align-items: center; gap: 18px; margin-bottom: 8px; color: var(--el-text-color-secondary); font-size: 12px; }
.log-dialog-meta .el-button { margin-left: auto; }
.log-dialog-list { height: 560px; overflow: auto; padding: 9px 10px; border: 1px solid var(--workspace-border); border-radius: 4px; background: #101923; color: #dbe7f2; font: 12px/18px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; scrollbar-width: thin; scrollbar-color: #577b9d #101923; }
.log-dialog-list > div { display: grid; grid-template-columns: 160px minmax(0, 1fr); gap: 10px; padding: 2px 0; white-space: pre-wrap; word-break: break-word; }
.log-dialog-list small { color: #8ca0b5; }
.log-error { color: #c44754; }
.log-warn { color: #bc761c; }
.log-dialog-list b { margin-right: 7px; color: #78b4ef; font-weight: 650; }
</style>
