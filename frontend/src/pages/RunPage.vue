<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { errorMessage } from '../utils/errorMessage'
import { useRowClipboard } from '../composables/useRowClipboard'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  Document,
  Setting,
  Tickets,
  Upload,
  VideoPause,
  VideoPlay,
  WarningFilled,
} from '@element-plus/icons-vue'
import {
  getFreeSecret,
  getRuntimeTaskMailboxPassword,
  getRuntimeTaskMailboxTotp,
  getRuntimeTaskMailboxUrl,
  getRuntimeTaskLatestCode,
  retryFreeTwofa,
} from '../api/client'
import LogPanel from '../components/LogPanel.vue'
import MailboxImportDialog from '../components/MailboxImportDialog.vue'
import OpenAIConnectivityBanner from '../components/OpenAIConnectivityBanner.vue'
import TaskResultsPanel from '../components/TaskResultsPanel.vue'
import WorkspacePanel from '../components/WorkspacePanel.vue'
import { useAppController } from '../composables/useAppController'
import type { MailboxMutationResult, RuntimeTask } from '../types/api'
import { buildOpenAIConnectivityView } from '../utils/openAIConnectivity'
import { TASK_TERMINAL_STATUSES } from '../utils/taskResultViews'
import { freeTaskSecretLookup } from '../utils/freeSecretLookup'
import { safeMailboxUrl } from '../utils/safeMailboxUrl'
import {
  MAX_RUN_LOG_PANEL_WIDTH,
  MIN_RUN_LOG_PANEL_WIDTH,
  readRunLogPanelWidth,
  saveRunLogPanelWidth,
} from '../utils/runLogPanel'

const emit = defineEmits<{ navigate: [string] }>()
const controller = useAppController()
const mailboxImportDialog = ref<InstanceType<typeof MailboxImportDialog>>()
const openingMailboxUrlTaskIds = ref<string[]>([])
const { loadingIds: loadingFreeTaskEmailIds, copyForRow: copyFreeTaskEmailRow } = useRowClipboard()
const { loadingIds: loadingMailboxPasswordTaskIds, copyForRow: copyMailboxPasswordRow } = useRowClipboard()
const { loadingIds: loadingMailboxTotpTaskIds, copyForRow: copyMailboxTotpRow } = useRowClipboard()
const remaining = ref(0)
const { loadingIds: loadingMailboxLatestCodeTaskIds, copyForRow: copyMailboxLatestCodeRow } = useRowClipboard()
const taskView = ref<'pending' | 'running' | 'all'>('pending')
const taskCounts = ref({ pending: 0, running: 0, all: 0 })
const connectivityView = computed(() => buildOpenAIConnectivityView(controller.runtime.value))
const logPanelWidth = ref(700)
const resizingLogPanel = ref(false)
const visibleLogPanelWidth = computed(() => Math.min(logPanelWidth.value, 560))

function updateLogPanelWidth(clientX: number) {
  const next = Math.round(window.innerWidth - clientX - 5)
  logPanelWidth.value = Math.min(MAX_RUN_LOG_PANEL_WIDTH, Math.max(MIN_RUN_LOG_PANEL_WIDTH, next))
}

function finishLogResize() {
  if (!resizingLogPanel.value) return
  resizingLogPanel.value = false
  saveRunLogPanelWidth(window.localStorage, logPanelWidth.value)
  document.body.style.cursor = ''
  window.removeEventListener('pointermove', moveLogResize)
  window.removeEventListener('pointerup', finishLogResize)
}

function moveLogResize(event: PointerEvent) {
  if (resizingLogPanel.value) updateLogPanelWidth(event.clientX)
}

function startLogResize(event: PointerEvent) {
  event.preventDefault()
  resizingLogPanel.value = true
  document.body.style.cursor = 'col-resize'
  window.addEventListener('pointermove', moveLogResize)
  window.addEventListener('pointerup', finishLogResize)
}

function adjustLogPanelWidth(event: KeyboardEvent) {
  const delta = event.key === 'ArrowLeft' ? 20 : event.key === 'ArrowRight' ? -20 : 0
  if (!delta) return
  event.preventDefault()
  logPanelWidth.value = Math.min(MAX_RUN_LOG_PANEL_WIDTH, Math.max(MIN_RUN_LOG_PANEL_WIDTH, logPanelWidth.value + delta))
  saveRunLogPanelWidth(window.localStorage, logPanelWidth.value)
}

onMounted(() => {
  logPanelWidth.value = readRunLogPanelWidth(window.localStorage)
})

onUnmounted(finishLogResize)

const terminalStatuses = TASK_TERMINAL_STATUSES

const tasks = computed(() => controller.runtime.value.tasks || [])
const summary = computed(() => {
  const current = controller.runtime.value.summary || {}
  const success = current.success ?? tasks.value.filter(task => task.status === 'success').length
  const stopped = current.stopped ?? tasks.value.filter(task => String(task.status).startsWith('stopped')).length
  const active = current.active ?? tasks.value.filter(task => !terminalStatuses.has(String(task.status || ''))).length
  const failed = current.failed ?? Math.max(0, tasks.value.length - success - stopped - active)
  const smsCostCny = current.sms_cost_cny ?? tasks.value.reduce(
    (total, task) => total + Number(task.result?.sms_cost_cny || 0),
    0,
  )
  const smsCostUsd = current.sms_cost_usd ?? tasks.value.reduce(
    (total, task) => total + Number(task.result?.sms_cost_usd || 0),
    0,
  )
  return {
    ...current,
    success,
    stopped,
    active,
    failed,
    sms_cost_cny: smsCostCny,
    sms_cost_usd: smsCostUsd,
  }
})

const batchId = computed(() => {
  const summarized = String(summary.value.batch_id || '').trim()
  if (summarized) return summarized
  return String(tasks.value.find(task => task.batch_id)?.batch_id || '').trim()
})

const batchTarget = computed(() => {
  const summarized = Math.floor(Number(summary.value.target || 0))
  if (Number.isFinite(summarized) && summarized > 0) return summarized
  return tasks.value.reduce(
    (target, task) => Math.max(target, Math.floor(Number(task.ordinal || 0))),
    tasks.value.length,
  )
})

const batchCompleted = computed(() => Math.min(
  batchTarget.value,
  Math.max(
    0,
    Number(summary.value.success || 0)
      + Number(summary.value.failed || 0)
      + Number(summary.value.stopped || 0),
  ),
))

const summaryStrip = computed(() => [
  { key: 'pool', label: '可用邮箱', value: Number(controller.runtime.value.pool?.available || 0), tone: 'info', detail: '接码 / OAuth 独立邮箱池' },
  { key: 'active', label: '运行中', value: Number(summary.value.active || 0), tone: 'warning', detail: '' },
  { key: 'success', label: '成功', value: Number(summary.value.success || 0), tone: 'success', detail: '' },
  { key: 'unsuccess', label: '未成功', value: Number(summary.value.failed || 0) + Number(summary.value.stopped || 0), tone: 'danger', detail: '' },
  { key: 'cost', label: '运行成本', value: `¥${Number(summary.value.sms_cost_cny || 0).toFixed(2)}`, tone: 'info', detail: `$${Number(summary.value.sms_cost_usd || 0).toFixed(4)}` },
  { key: 'avg', label: '接码均成本', value: `¥${Number(summary.value.sms_cost_history?.average_cny || 0).toFixed(2)}/号`, tone: 'success', detail: `${Number(summary.value.sms_cost_history?.account_count || 0)} 个账号 / ¥${Number(summary.value.sms_cost_history?.total_cny || 0).toFixed(2)}` },
] as { key: string; label: string; value: number | string; tone: string; detail: string }[])

async function start() {
  if (controller.dirty.value) {
    emit('navigate', '/settings')
    ElMessage.warning('请先保存运行配置')
    return
  }
  try {
    const result = await controller.start(false, 'register')
    if (!result) return
    ElMessage.success('任务已启动')
  } catch (error) {
    ElMessage.error(errorMessage(error) || '启动失败')
  }
}

async function stop() {
  try {
    await controller.stop()
    ElMessage.success('已发送停止请求')
  } catch (error) {
    ElMessage.error(errorMessage(error) || '停止失败')
  }
}

function applyImportedMailboxes(result: MailboxMutationResult) {
  if (result?.state) controller.syncState(result.state)
  void controller.refresh()
}

async function copyTaskAccount(task: RuntimeTask) {
  const taskId = String(task.task_id || '').trim()
  if (task.run_mode === 'free_register') {
    await copyFreeTaskEmailRow({
      rowId: taskId,
      produce: async () => {
        const rowId = String((task as RuntimeTask & { row_id?: string }).row_id || '').trim()
        const value = String((await getFreeSecret('email', freeTaskSecretLookup(taskId, rowId))).value || '').trim()
        if (!value) throw new Error('服务端未返回可复制邮箱')
        return value
      },
      successMessage: '已复制真实邮箱',
      errorMessage: '邮箱复制失败',
    })
    return
  }
  const value = String(task.account || task.email || '').trim()
  if (!value) return
  if (!navigator.clipboard?.writeText) {
    ElMessage.error('当前浏览器不支持安全剪贴板写入')
    return
  }
  try {
    await navigator.clipboard.writeText(value)
    ElMessage.success('已复制账号或邮箱')
  } catch {
    ElMessage.error('复制账号或邮箱失败')
  }
}

async function copyDiagnosticId(value: string) {
  const incidentId = String(value || '').trim()
  if (!incidentId) {
    ElMessage.info('该任务尚未生成日志 ID')
    return
  }
  if (!navigator.clipboard?.writeText) {
    ElMessage.error('当前浏览器不支持安全剪贴板写入')
    return
  }
  try {
    await navigator.clipboard.writeText(incidentId)
    ElMessage.success('日志 ID 已复制')
  } catch {
    ElMessage.error('日志 ID 复制失败')
  }
}

function openDiagnostic(task: RuntimeTask) {
  const incidentId = String(task.incident_id || '').trim()
  if (!incidentId) {
    ElMessage.info('该任务尚未生成日志 ID')
    return
  }
  emit('navigate', `/logs?incident_id=${encodeURIComponent(incidentId)}`)
}

async function copyFreeTaskSecret(payload: { kind: 'token' | 'password' | 'totp' | 'credential'; tasks: RuntimeTask[] }) {
  if (!navigator.clipboard?.writeText) {
    ElMessage.error('当前浏览器不支持安全剪贴板写入')
    return
  }
  const eligible = payload.tasks.filter((task) => {
    if (payload.kind === 'token') return task.result?.has_access_token
    if (payload.kind === 'password') return task.result?.has_password
    if (payload.kind === 'totp') return task.result?.has_totp
    return task.result?.has_credential
  })
  const taskIds = [...new Set(eligible.map(task => String(task.task_id || '').trim()).filter(Boolean))]
  if (!taskIds.length) {
    ElMessage.warning('选中的 Free 账号没有可复制内容')
    return
  }
  try {
    const result = await getFreeSecret(payload.kind, { task_ids: taskIds })
    const value = String(result.value || '')
    if (!value) throw new Error('服务端未返回可复制内容')
    await navigator.clipboard.writeText(value)
    ElMessage.success(`已复制 ${taskIds.length} 个 Free 账号敏感字段`)
  } catch (error) {
    ElMessage.error(errorMessage(error) || 'Free 敏感字段复制失败')
  }
}

async function retryFreeTaskTwofa(task: RuntimeTask) {
  const taskId = String(task.task_id || '').trim()
  if (!taskId) return
  try {
    await retryFreeTwofa(taskId)
    ElMessage.info('已重新加入 2FA 设置任务')
    await controller.refresh()
  } catch (error) {
    ElMessage.error(errorMessage(error) || '2FA 重试失败')
  }
}

async function copyTaskPassword(task: RuntimeTask) {
  const taskId = String(task.task_id || '').trim()
  await copyMailboxPasswordRow({
    rowId: taskId,
    produce: async () => String((await getRuntimeTaskMailboxPassword(taskId)).password || ''),
    successMessage: '已复制密码',
    errorMessage: '复制密码失败',
  })
}

async function copyTaskTotp(task: RuntimeTask) {
  const taskId = String(task.task_id || '').trim()
  await copyMailboxTotpRow({
    rowId: taskId,
    produce: async () => {
      const result = await getRuntimeTaskMailboxTotp(taskId)
      remaining.value = Number(result.remaining || 0)
      return String(result.code || '')
    },
    successMessage: () => `已复制临时 2FA 验证码，约 ${remaining.value} 秒后刷新`,
    errorMessage: '复制临时 2FA 验证码失败',
  })
}

async function copyTaskLatestCode(task: RuntimeTask) {
  const taskId = String(task.task_id || '').trim()
  if (!taskId) {
    ElMessage.info('该任务尚未生成任务 ID')
    return
  }
  if (!task.has_mailbox_url) {
    ElMessage.info('该任务暂无取件 URL，无法提取验证码')
    return
  }
  await copyMailboxLatestCodeRow({
    rowId: taskId,
    produce: async () => String((await getRuntimeTaskLatestCode(taskId)).code || ''),
    successMessage: '验证码已复制',
    errorMessage: '提取邮箱验证码失败',
    emptyMessage: '未找到新的 OpenAI 邮箱验证码',
  })
}

async function openTaskMailboxUrl(task: RuntimeTask) {
  const taskId = String(task.task_id || '').trim()
  if (!taskId) {
    ElMessage.info('该任务尚未生成任务 ID')
    return
  }
  if (!task.has_mailbox_url) {
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
    const result = await getRuntimeTaskMailboxUrl(taskId)
    const destination = safeMailboxUrl(result.mailbox_url)
    if (!destination) throw new Error('取件 URL 无效或协议不安全')
    target.location.replace(destination)
  } catch (error) {
    target.close()
    ElMessage.error(errorMessage(error) || '打开取件 URL 失败')
  } finally {
    openingMailboxUrlTaskIds.value = openingMailboxUrlTaskIds.value.filter(id => id !== taskId)
  }
}

async function disableConnectivityGuard() {
  try {
    await ElMessageBox.confirm(
      '关闭后将立即恢复新的 OpenAI 请求，并发将按当前运行策略恢复。',
      '关闭 OpenAI 链路保护',
      { type: 'warning', confirmButtonText: '关闭保护', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  try {
    await controller.setOpenAIConnectivityGuard(false)
    ElMessage.warning('OpenAI 链路保护已关闭')
  } catch (error) {
    ElMessage.error(errorMessage(error) || '关闭 OpenAI 链路保护失败')
  }
}
</script>

<template>
  <div
    class="run-page"
    :class="{
      'has-connectivity-banner': Boolean(connectivityView.banner),
    }"
  >
    <OpenAIConnectivityBanner
      :view="connectivityView"
      :disabling-guard="controller.actions.updatingConnectivityGuard"
      @disable-guard="disableConnectivityGuard"
      @diagnose="controller.openConnectivityDiagnostics('手动检查当前 OpenAI 授权链路')"
    />

    <div class="console-grid">
      <div class="run-toolbar">
        <div class="run-toolbar-main">
          <el-button size="small" :icon="Setting" @click="emit('navigate', '/settings')" aria-label="运行配置">运行配置</el-button>
          <el-button size="small" :icon="Upload" @click="mailboxImportDialog?.open()" aria-label="导入邮箱">导入邮箱</el-button>
          <el-tooltip v-if="controller.dirty.value" content="存在未保存配置，请先进入运行配置保存" placement="bottom" :show-after="250">
            <span><el-button size="small" type="primary" :icon="VideoPlay" disabled aria-label="开始运行">开始运行</el-button></span>
          </el-tooltip>
          <el-button v-else size="small" type="primary" :icon="VideoPlay" :loading="controller.actions.starting" :disabled="controller.running.value || !controller.hasPool.value" @click="start" aria-label="开始运行">开始运行</el-button>
          <el-button size="small" type="danger" plain :icon="VideoPause" :loading="controller.actions.stopping" :disabled="!controller.running.value" @click="stop" aria-label="停止">停止</el-button>
        </div>
        <div v-if="batchId" class="batch-identity">
          <span>运行批次</span>
          <strong>{{ batchId }}</strong>
          <b>已完成 {{ batchCompleted }}/{{ batchTarget }}</b>
        </div>
        <span v-else class="batch-placeholder" />
      </div>
      <div class="summary-strip" aria-label="运行指标">
        <div v-for="item in summaryStrip" :key="item.key" class="summary-cell" :class="[`tone-${item.tone}`, { 'has-detail': item.detail }]" :title="item.detail || item.label">
          <span>{{ item.label }}</span>
          <strong>{{ item.value }}</strong>
          <small v-if="item.detail">{{ item.detail }}</small>
        </div>
      </div>

      <div class="run-workspace" :style="{ gridTemplateColumns: `minmax(660px, 1fr) 7px minmax(360px, ${visibleLogPanelWidth}px)` }">
        <WorkspacePanel class="task-workspace" title="任务结果" :icon="Tickets" fill body-padding="none">
          <div class="task-workspace-toolbar">
            <div class="task-toolbar-main">
            <div class="task-summary-tabs" role="tablist" aria-label="任务结果分类">
              <button type="button" role="tab" :aria-selected="taskView === 'pending'" :class="{ active: taskView === 'pending', urgent: taskCounts.pending }" @click="taskView = 'pending'"><el-icon><WarningFilled /></el-icon><span>待处理</span><b>{{ taskCounts.pending }}</b></button>
              <button type="button" role="tab" :aria-selected="taskView === 'running'" :class="{ active: taskView === 'running' }" @click="taskView = 'running'"><el-icon><VideoPlay /></el-icon><span>运行中</span><b>{{ taskCounts.running }}</b></button>
              <button type="button" role="tab" :aria-selected="taskView === 'all'" :class="{ active: taskView === 'all' }" @click="taskView = 'all'"><el-icon><Tickets /></el-icon><span>全部</span><b>{{ taskCounts.all }}</b></button>
            </div>
            </div>
          </div>
          <TaskResultsPanel
            :tasks="tasks as RuntimeTask[]"
            :opening-mailbox-urls="openingMailboxUrlTaskIds"
            :loading-mailbox-passwords="loadingMailboxPasswordTaskIds"
            :loading-mailbox-totps="loadingMailboxTotpTaskIds"
            :loading-mailbox-latest-codes="loadingMailboxLatestCodeTaskIds"
            :loading-account-emails="loadingFreeTaskEmailIds"
            :active-view="taskView"
            @copy-account="copyTaskAccount"
            @mailbox-password="copyTaskPassword"
            @mailbox-totp="copyTaskTotp"
            @mailbox-url="openTaskMailboxUrl"
            @mailbox-latest-code="copyTaskLatestCode"
            @free-secret="copyFreeTaskSecret"
            @free-twofa-retry="retryFreeTaskTwofa"
            @diagnostic="openDiagnostic"
            @copy-diagnostic-id="copyDiagnosticId"
            @update:active-view="taskView = $event"
            @counts="taskCounts = $event"
          />
        </WorkspacePanel>
        <el-tooltip content="拖拽调整日志宽度，方向键微调" placement="top" :show-after="250">
          <div class="log-resizer" role="separator" aria-label="调整运行日志宽度" aria-orientation="vertical" :aria-valuemin="MIN_RUN_LOG_PANEL_WIDTH" :aria-valuemax="MAX_RUN_LOG_PANEL_WIDTH" :aria-valuenow="logPanelWidth" tabindex="0" @pointerdown="startLogResize" @keydown="adjustLogPanelWidth" />
        </el-tooltip>
        <WorkspacePanel class="log-workspace" title="运行日志" :icon="Document" fill body-padding="none">
          <LogPanel :logs="controller.state.value.logs || []" :auto-scroll="true" />
        </WorkspacePanel>
      </div>
    </div>

    <MailboxImportDialog ref="mailboxImportDialog" @imported="applyImportedMailboxes" />
  </div>
</template>

<style scoped>
.run-page {
  display: grid;
  grid-template-rows: minmax(0, 1fr);
  gap: var(--workspace-gap);
  width: 100%;
  height: 100%;
  min-width: 0;
  min-height: 0;
}
.run-page.has-connectivity-banner { grid-template-rows: 40px minmax(0, 1fr); }
.console-grid { display: grid; grid-template-rows: auto auto minmax(0, 1fr); gap: var(--workspace-gap); min-width: 0; min-height: 0; }
.run-toolbar { display: flex; align-items: center; gap: var(--workspace-gap); min-width: 0; min-height: 32px; }
.run-toolbar-main { display: flex; align-items: center; gap: var(--workspace-gap); min-width: 0; }
.batch-identity { display: flex; align-items: center; gap: var(--workspace-gap); min-width: 0; margin-left: auto; }
.batch-placeholder { flex: 1 1 auto; }
.summary-strip { display: flex; align-items: stretch; min-width: 0; border: 1px solid var(--workspace-border); border-radius: var(--workspace-radius); overflow-x: auto; overflow-y: hidden; background: var(--workspace-surface); }
.summary-cell { display: flex; flex-direction: column; justify-content: center; gap: 1px; flex: 1 0 auto; min-width: 0; min-height: 48px; padding: 5px 14px; border-right: 1px solid var(--workspace-border); white-space: nowrap; }
.summary-cell:last-child { border-right: 0; }
.summary-cell span { color: var(--el-text-color-secondary); font-size: 12px; line-height: 16px; }
.summary-cell strong { color: var(--el-text-color-primary); font-size: 16px; line-height: 21px; font-variant-numeric: tabular-nums; }
.summary-cell small { max-width: 260px; overflow: hidden; color: var(--el-text-color-secondary); font-size: 11px; line-height: 14px; text-overflow: ellipsis; }
.summary-cell.tone-success strong { color: var(--el-color-success); }
.summary-cell.tone-warning strong { color: var(--el-color-warning); }
.summary-cell.tone-danger strong { color: var(--el-color-danger); }
.task-workspace,
.log-workspace { min-width: 0; min-height: 0; }
.run-workspace { display: grid; min-width: 0; min-height: 0; gap: 0; }
.log-resizer { position: relative; min-width: 0; cursor: col-resize; }
.log-resizer::after { position: absolute; top: 8px; bottom: 8px; left: 3px; width: 1px; background: var(--workspace-border); content: ''; transition: background-color .15s ease, width .15s ease; }
.log-resizer:hover::after,
.log-resizer:focus-visible::after { left: 2px; width: 3px; background: var(--el-color-primary-light-5); }
.log-resizer:focus-visible { outline: none; }
.task-workspace-toolbar { flex: 0 0 auto; min-width: 0; padding: 6px 10px; border-bottom: 1px solid var(--workspace-border); background: var(--workspace-surface); }
.task-toolbar-main { display: flex; align-items: center; gap: var(--workspace-gap); min-width: 0; }
.task-summary-tabs { display: grid; grid-template-columns: repeat(3, minmax(76px, 92px)); align-content: center; justify-content: start; gap: 3px; min-width: 0; flex: 0 1 auto; }
.task-summary-tabs button { display: inline-flex; align-items: center; justify-content: center; gap: 5px; min-width: 0; height: 26px; border: 1px solid transparent; border-radius: 4px; padding: 0 6px; background: transparent; color: var(--el-text-color-regular); font-size: 12px; font-weight: 600; cursor: pointer; }
.task-summary-tabs button:hover { background: var(--workspace-subtle); color: var(--el-color-primary-dark-2); }
.task-summary-tabs button.active { border-color: var(--el-color-primary-light-5); background: var(--el-color-primary-light-9); color: var(--el-color-primary-dark-2); font-weight: 700; }
.task-summary-tabs button.active.urgent { border-color: var(--el-color-danger-light-5, #efb9b9); background: var(--el-color-danger-light-9, #fef0f0); color: var(--el-color-danger); }
.task-summary-tabs button .el-icon { width: 14px; height: 14px; font-size: 14px; }
.task-summary-tabs button span { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.task-summary-tabs b { display: inline-grid; place-items: center; min-width: 18px; height: 16px; padding: 0 4px; border-radius: 8px; background: var(--workspace-border); color: var(--el-text-color-regular); font-size: 9px; }
.task-summary-tabs button.active b { background: var(--el-color-primary); color: #fff; }
.task-summary-tabs button.urgent, .task-summary-tabs button.active.urgent { color: var(--el-color-danger); }
.task-summary-tabs button.urgent b, .task-summary-tabs button.active.urgent b { background: var(--el-color-danger); color: #fff; }
.batch-identity span { color: var(--el-text-color-secondary); font-size: 11px; white-space: nowrap; }
.batch-identity strong {
  min-width: 0;
  max-width: 320px;
  overflow: hidden;
  color: var(--el-color-primary-dark-2);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
  font-weight: 650;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.batch-identity b {
  padding-left: 8px;
  border-left: 1px solid var(--workspace-border);
  color: var(--el-text-color-regular);
  font-size: 12px;
  font-weight: 650;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}

.run-page :deep(.workspace-panel) { border-color: var(--workspace-border); }
.run-page :deep(.workspace-panel > .el-card__header) { border-bottom-color: var(--workspace-border); background: var(--workspace-subtle); }
.run-page :deep(.workspace-panel .panel-title .el-icon) { color: var(--el-color-primary); }
.task-workspace :deep(.copyable-account) { color: var(--el-color-primary-dark-2); }
.task-workspace :deep(.task-actions .el-button) { color: var(--el-color-primary-dark-2); }
.task-workspace :deep(.task-actions .el-button:hover) { color: var(--el-color-primary); background: var(--el-color-primary-light-9); }
.log-workspace :deep(.log-line b.error) { color: var(--el-color-danger); }

</style>
