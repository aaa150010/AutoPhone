<script setup lang="ts">
import { computed, ref } from 'vue'
import { ElMessage } from 'element-plus'
import {
  CircleCheckFilled,
  CircleCloseFilled,
  Coin,
  Connection,
  DataAnalysis,
  FirstAidKit,
  Message,
  Monitor,
  Tickets,
  Upload,
  VideoPause,
} from '@element-plus/icons-vue'
import { getRuntimeTaskMailboxUrl } from '../api/client'
import LogPanel from '../components/LogPanel.vue'
import MailboxImportDialog from '../components/MailboxImportDialog.vue'
import PageToolbar from '../components/PageToolbar.vue'
import RunOverview from '../components/RunOverview.vue'
import RunPipelineMonitor from '../components/RunPipelineMonitor.vue'
import RunServiceHealth from '../components/RunServiceHealth.vue'
import RunUploadDialog from '../components/RunUploadDialog.vue'
import TaskResultsPanel from '../components/TaskResultsPanel.vue'
import WorkspacePanel from '../components/WorkspacePanel.vue'
import { useAppController } from '../composables/useAppController'
import type { RuntimeTask } from '../types/api'

const emit = defineEmits<{ navigate: [string] }>()
const controller = useAppController()
const mailboxImportDialog = ref<InstanceType<typeof MailboxImportDialog>>()
const uploadDialog = ref<InstanceType<typeof RunUploadDialog>>()
const openingMailboxUrlTaskIds = ref<string[]>([])

const terminalStatuses = new Set([
  'success', 'failed', 'stopped', 'stopped_before_start', 'retryable_infra',
  'retryable_email', 'repair_pending', 'email_damaged', 'account_banned',
])

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
  return { ...current, success, stopped, active, failed, sms_cost_cny: smsCostCny }
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

const metrics = computed(() => [
  { title: '可用邮箱', value: Number(controller.runtime.value.pool?.available || 0), icon: Message, tone: 'primary' },
  { title: '运行中', value: Number(summary.value.active || 0), icon: Monitor, tone: 'warning' },
  { title: '成功', value: Number(summary.value.success || 0), icon: CircleCheckFilled, tone: 'success' },
  { title: '未成功', value: Number(summary.value.failed || 0) + Number(summary.value.stopped || 0), icon: CircleCloseFilled, tone: 'danger' },
  { title: '运行成本', value: `¥${Number(summary.value.sms_cost_cny || 0).toFixed(2)}`, icon: Coin, tone: 'primary' },
] as const)

const pipelineActiveCount = computed(() => {
  const summarized = Number(summary.value.active)
  if (Number.isFinite(summarized) && summarized > 0) return summarized
  return Object.values(controller.runtime.value.stage_counts || {}).reduce(
    (total, value) => total + Math.max(0, Number(value || 0)),
    0,
  )
})

const statusLabel = computed(() => {
  if (controller.runtime.value.stop_requested) return controller.running.value ? '正在停止' : '已停止'
  return controller.running.value ? '运行中' : '空闲'
})
const statusTone = computed(() => controller.runtime.value.stop_requested ? 'warning' : controller.running.value ? 'success' : 'info')
const nvConfigured = computed(() => Boolean(
  String(controller.form.nv_import?.endpoint || '').trim()
  && String(controller.form.nv_import?.api_key || '').trim(),
))

function openStartDialog() {
  if (controller.dirty.value) {
    emit('navigate', '/settings')
    ElMessage.warning('请先保存运行配置')
    return
  }
  uploadDialog.value?.open()
}

async function start(uploadTargets: { pixel: boolean; nv: boolean }) {
  try {
    const result = await controller.start(false, uploadTargets)
    if (!result) return
    ElMessage.success('任务已启动')
  } catch (error: any) {
    ElMessage.error(error?.message || '启动失败')
  }
}

async function stop() {
  try {
    await controller.stop()
    ElMessage.success('已发送停止请求')
  } catch (error: any) {
    ElMessage.error(error?.message || '停止失败')
  }
}

function applyImportedMailboxes(result: any) {
  controller.syncState(result)
}

async function copyTaskAccount(task: RuntimeTask) {
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

async function openTaskMailboxUrl(task: RuntimeTask) {
  const taskId = String(task.task_id || '').trim()
  if (!task.has_mailbox_url || !taskId || openingMailboxUrlTaskIds.value.includes(taskId)) return
  const target = window.open('', '_blank')
  if (!target) {
    ElMessage.error('浏览器阻止了新窗口，请允许弹出窗口后重试')
    return
  }
  target.opener = null
  openingMailboxUrlTaskIds.value = [...openingMailboxUrlTaskIds.value, taskId]
  try {
    const result = await getRuntimeTaskMailboxUrl(taskId)
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
</script>

<template>
  <div
    class="run-page"
    :class="{
      'is-running': controller.running.value && !controller.runtime.value.stop_requested,
      'is-stopping': controller.runtime.value.stop_requested,
    }"
  >
    <PageToolbar title="运行中心" :status="statusLabel" :tone="statusTone">
      <el-button @click="emit('navigate', '/settings')"><el-icon><Setting /></el-icon>运行配置</el-button>
      <el-button @click="mailboxImportDialog?.open()"><el-icon><Upload /></el-icon>导入邮箱</el-button>
      <el-tooltip v-if="controller.dirty.value" content="存在未保存配置，请先进入运行配置保存" placement="bottom">
        <span><el-button type="primary" disabled><el-icon><VideoPlay /></el-icon>开始运行</el-button></span>
      </el-tooltip>
      <el-button v-else type="primary" :loading="controller.actions.starting" :disabled="controller.running.value || !controller.hasPool.value" @click="openStartDialog">
        <el-icon><VideoPlay /></el-icon>开始运行
      </el-button>
      <el-button type="danger" plain :loading="controller.actions.stopping" :disabled="!controller.running.value" @click="stop">
        <el-icon><VideoPause /></el-icon>停止
      </el-button>
    </PageToolbar>

    <div class="console-grid">
      <div class="dashboard-row">
        <WorkspacePanel class="overview-workspace" title="实时概览" :icon="DataAnalysis" fill body-padding="none">
          <RunOverview :metrics="metrics" />
        </WorkspacePanel>

        <WorkspacePanel class="pipeline-workspace" title="运行管线" :icon="Connection" fill body-padding="none">
          <template #actions>
            <span class="pipeline-live" :class="{ idle: !pipelineActiveCount }">
              <i />{{ pipelineActiveCount ? `${pipelineActiveCount} 个任务处理中` : '当前无处理中任务' }}
            </span>
          </template>
          <RunPipelineMonitor :runtime="controller.runtime.value" />
        </WorkspacePanel>

        <WorkspacePanel class="health-workspace" title="服务健康" :icon="FirstAidKit" fill body-padding="none">
          <RunServiceHealth
            :runtime="controller.runtime.value"
            :alerts="controller.state.value.sms_alerts || controller.runtime.value.sms_alerts"
          />
        </WorkspacePanel>
      </div>

      <WorkspacePanel class="task-workspace" title="任务结果" :icon="Tickets" fill body-padding="none">
        <template #actions>
          <div v-if="batchId" class="batch-identity">
            <span>运行批次</span>
            <strong>{{ batchId }}</strong>
            <b>已完成 {{ batchCompleted }}/{{ batchTarget }}</b>
          </div>
        </template>
        <TaskResultsPanel
          :tasks="tasks as RuntimeTask[]"
          :opening-mailbox-urls="openingMailboxUrlTaskIds"
          @copy-account="copyTaskAccount"
          @mailbox-url="openTaskMailboxUrl"
        />
      </WorkspacePanel>

      <WorkspacePanel class="log-workspace" fill body-padding="none">
        <LogPanel :logs="controller.state.value.logs || []" :auto-scroll="true" />
      </WorkspacePanel>
    </div>

    <RunUploadDialog
      ref="uploadDialog"
      :nv-configured="nvConfigured"
      :loading="controller.actions.starting"
      @confirm="start"
    />
    <MailboxImportDialog ref="mailboxImportDialog" @imported="applyImportedMailboxes" />
  </div>
</template>

<style scoped>
.run-page {
  --run-blue: #287fd8;
  --run-blue-soft: #eaf4ff;
  --run-green: #247d50;
  --run-green-soft: #edf9f2;
  --run-orange: #b66b00;
  --run-orange-soft: #fff5e8;
  --run-red: #be4545;
  --run-red-soft: #fff0f0;
  display: grid;
  grid-template-rows: 44px minmax(0, 1fr);
  gap: 6px;
  width: 100%;
  height: 100%;
  min-width: 0;
  min-height: 0;
}
.console-grid { display: grid; grid-template-rows: 220px repeat(2, minmax(0, 1fr)); gap: 6px; min-width: 0; min-height: 0; }
.dashboard-row { display: grid; grid-template-columns: minmax(270px, .9fr) minmax(520px, 1.8fr) minmax(270px, .9fr); gap: 6px; min-width: 0; min-height: 0; }
.task-workspace,
.log-workspace { min-width: 0; min-height: 0; }
.pipeline-live { display: flex; align-items: center; gap: 5px; color: var(--run-blue); font-size: 10px; white-space: nowrap; }
.pipeline-live i { flex: 0 0 6px; width: 6px; height: 6px; border-radius: 50%; background: var(--run-blue); box-shadow: 0 0 0 3px rgba(40, 127, 216, .1); }
.pipeline-live.idle { color: var(--el-text-color-secondary); }
.pipeline-live.idle i { background: #a5afbd; box-shadow: none; }
.batch-identity { display: flex; align-items: center; gap: 8px; min-width: 0; }
.batch-identity span { color: var(--el-text-color-secondary); font-size: 11px; white-space: nowrap; }
.batch-identity strong {
  max-width: 260px;
  overflow: hidden;
  color: var(--run-blue);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
  font-weight: 650;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.batch-identity b {
  padding-left: 8px;
  border-left: 1px solid #d5e0ec;
  color: #344055;
  font-size: 12px;
  font-weight: 650;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}

.run-page :deep(.page-toolbar) {
  padding: 0 10px;
  border: 1px solid #dbe5f0;
  border-radius: 6px;
  background: #fff;
  box-shadow: 0 1px 3px rgba(22, 34, 51, .05);
}
.run-page.is-running :deep(.page-toolbar .el-tag--success) {
  --el-tag-bg-color: var(--run-blue-soft);
  --el-tag-border-color: #b7d7f6;
  --el-tag-text-color: var(--run-blue);
}
.run-page :deep(.workspace-panel) { border-color: #dbe5f0; box-shadow: 0 1px 4px rgba(31, 56, 88, .05); }
.run-page :deep(.workspace-panel > .el-card__header) { border-bottom-color: #e2eaf3; background: #f8fbff; }
.run-page :deep(.workspace-panel .panel-title .el-icon) { color: var(--run-blue); }
.task-workspace :deep(.el-table__header-wrapper th.el-table__cell) { background: #f4f8fc; color: #526074; }
.task-workspace :deep(.el-table__inner-wrapper::before) { background-color: #dbe5f0; }
.task-workspace :deep(.el-table__empty-block) { background: #fbfdff; }
.task-workspace :deep(.el-tag--primary) {
  --el-tag-bg-color: var(--run-blue-soft);
  --el-tag-border-color: #b7d7f6;
  --el-tag-text-color: var(--run-blue);
}
.task-workspace :deep(.el-tag--success) {
  --el-tag-bg-color: var(--run-green-soft);
  --el-tag-border-color: #b9e5cc;
  --el-tag-text-color: var(--run-green);
}
.task-workspace :deep(.el-tag--warning) {
  --el-tag-bg-color: var(--run-orange-soft);
  --el-tag-border-color: #f0cf99;
  --el-tag-text-color: var(--run-orange);
}
.task-workspace :deep(.el-tag--danger) {
  --el-tag-bg-color: var(--run-red-soft);
  --el-tag-border-color: #efb9b9;
  --el-tag-text-color: var(--run-red);
}
.task-workspace :deep(.content-empty),
.log-workspace :deep(.content-empty) { background: #fbfdff; }
.log-workspace :deep(.log-line) { border-bottom-color: #e7edf4; }
.log-workspace :deep(.log-line b) { color: #3d6f9f; }
.log-workspace :deep(.log-line b.success) { color: var(--run-green); }
.log-workspace :deep(.log-line b.warning),
.log-workspace :deep(.log-line b.warn) { color: var(--run-orange); }
.log-workspace :deep(.log-line b.error) { color: var(--run-red); }

@media (max-height: 820px) {
  .console-grid { grid-template-rows: 204px repeat(2, minmax(0, 1fr)); }
}

@media (max-width: 1450px) {
  .dashboard-row { grid-template-columns: minmax(250px, .9fr) minmax(470px, 1.8fr) minmax(250px, .9fr); }
}
</style>
