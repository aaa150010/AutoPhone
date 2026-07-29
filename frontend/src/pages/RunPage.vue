<script setup lang="ts">
import { computed, ref } from 'vue'
import { ElMessage } from 'element-plus'
import {
  CircleCheckFilled,
  CircleCloseFilled,
  Close,
  Coin,
  Document,
  FullScreen,
  List,
  Message,
  Monitor,
  Search,
} from '@element-plus/icons-vue'
import { api } from '../api/client'
import DashboardMetricCard from '../components/DashboardMetricCard.vue'
import LogPanel from '../components/LogPanel.vue'
import PageToolbar from '../components/PageToolbar.vue'
import RunDiagnostics from '../components/RunDiagnostics.vue'
import TaskResultsPanel from '../components/TaskResultsPanel.vue'
import WorkspacePanel from '../components/WorkspacePanel.vue'
import { useAppController } from '../composables/useAppController'
import type { RuntimeTask } from '../types/api'

const emit = defineEmits<{ navigate: [string] }>()
const controller = useAppController()
const taskSearch = ref('')
const taskFilter = ref('all')
const logSearch = ref('')
const logFilter = ref('all')
const focus = ref<'tasks' | 'logs' | null>(null)

const terminalStatuses = new Set([
  'success', 'failed', 'stopped', 'stopped_before_start', 'retryable_infra',
  'retryable_email', 'repair_pending', 'email_damaged',
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

const metrics = computed(() => [
  { title: '可用邮箱', value: Number(controller.runtime.value.pool?.available || 0), icon: Message, tone: 'primary' },
  { title: '运行中', value: Number(summary.value.active || 0), icon: Monitor, tone: 'warning' },
  { title: '成功', value: Number(summary.value.success || 0), icon: CircleCheckFilled, tone: 'success' },
  { title: '未成功', value: Number(summary.value.failed || 0) + Number(summary.value.stopped || 0), icon: CircleCloseFilled, tone: 'danger' },
  { title: '运行成本', value: `¥${Number(summary.value.sms_cost_cny || 0).toFixed(2)}`, icon: Coin, tone: 'primary' },
] as const)

const statusLabel = computed(() => {
  if (controller.runtime.value.stop_requested) return controller.running.value ? '正在停止' : '已停止'
  return controller.running.value ? '运行中' : '空闲'
})
const statusTone = computed(() => controller.runtime.value.stop_requested ? 'warning' : controller.running.value ? 'success' : 'info')

const filteredTasks = computed(() => tasks.value.filter((task) => {
  const status = String(task.status || '')
  const matchesStatus = taskFilter.value === 'all'
    || (taskFilter.value === 'active' && !terminalStatuses.has(status))
    || (taskFilter.value === 'unsuccessful' && terminalStatuses.has(status) && status !== 'success')
    || status === taskFilter.value
  const query = taskSearch.value.trim().toLowerCase()
  const text = [task.task_id, task.account, task.email, task.status, task.error, task.reason, task.progress?.label]
    .join(' ')
    .toLowerCase()
  return matchesStatus && (!query || text.includes(query))
}))

const filteredLogs = computed(() => (controller.state.value.logs || []).filter((log: any) => {
  const level = String(log?.level || log?.type || '').toLowerCase()
  const matchesLevel = logFilter.value === 'all' || level === logFilter.value
  const query = logSearch.value.trim().toLowerCase()
  const text = [log?.time, log?.message, log?.text, level].join(' ').toLowerCase()
  return matchesLevel && (!query || text.includes(query))
}))

async function start() {
  if (controller.dirty.value) {
    emit('navigate', '/settings')
    ElMessage.warning('请先保存运行配置')
    return
  }
  try {
    await controller.start()
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

async function exportTasks(kind: 'success' | 'failed' | 'all') {
  try {
    const result: any = await api(`/api/export/${kind}`)
    const records = Array.isArray(result.records) ? result.records : []
    const blob = new Blob([records.map((item: any) => JSON.stringify(item)).join('\n')], { type: 'application/x-ndjson' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `gptphone-${kind}-${new Date().toISOString().slice(0, 10)}.jsonl`
    link.click()
    URL.revokeObjectURL(url)
    ElMessage.success(`已导出 ${records.length} 条记录`)
  } catch (error: any) {
    ElMessage.error(error?.message || '导出失败')
  }
}

function toggleFocus(value: 'tasks' | 'logs') {
  focus.value = focus.value === value ? null : value
}
</script>

<template>
  <div class="run-page">
    <PageToolbar title="运行中心" :status="statusLabel" :tone="statusTone">
      <el-button @click="emit('navigate', '/settings')"><el-icon><Setting /></el-icon>运行配置</el-button>
      <el-tooltip v-if="controller.dirty.value" content="存在未保存配置，请先进入运行配置保存" placement="bottom">
        <span><el-button type="primary" disabled><el-icon><VideoPlay /></el-icon>开始运行</el-button></span>
      </el-tooltip>
      <el-button v-else type="primary" :loading="controller.actions.starting" :disabled="controller.running.value || !controller.hasPool.value" @click="start">
        <el-icon><VideoPlay /></el-icon>开始运行
      </el-button>
      <el-button type="danger" plain :loading="controller.actions.stopping" :disabled="!controller.running.value" @click="stop">
        <el-icon><VideoPause /></el-icon>停止
      </el-button>
    </PageToolbar>

    <div class="metric-grid">
      <DashboardMetricCard
        v-for="metric in metrics"
        :key="metric.title"
        :title="metric.title"
        :value="metric.value"
        :icon="metric.icon"
        :tone="metric.tone"
      />
    </div>

    <RunDiagnostics
      :runtime="controller.runtime.value"
      :alerts="controller.state.value.sms_alerts || controller.runtime.value.sms_alerts"
    />

    <div class="work-grid" :class="focus ? `focus-${focus}` : ''">
      <WorkspacePanel v-show="focus !== 'logs'" title="任务结果" :icon="List" fill body-padding="none">
        <template #actions>
          <el-input v-model="taskSearch" class="task-search" clearable placeholder="搜索任务" :prefix-icon="Search" />
          <el-select v-model="taskFilter" class="task-filter">
            <el-option label="全部状态" value="all" />
            <el-option label="运行中" value="active" />
            <el-option label="成功" value="success" />
            <el-option label="未成功" value="unsuccessful" />
          </el-select>
          <el-dropdown @command="exportTasks">
            <el-button><el-icon><Download /></el-icon>导出</el-button>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="success">成功记录</el-dropdown-item>
                <el-dropdown-item command="failed">未成功记录</el-dropdown-item>
                <el-dropdown-item command="all">全部记录</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
          <el-tooltip :content="focus === 'tasks' ? '退出聚焦' : '聚焦任务'">
            <el-button circle :icon="focus === 'tasks' ? Close : FullScreen" @click="toggleFocus('tasks')" />
          </el-tooltip>
        </template>
        <TaskResultsPanel :tasks="filteredTasks as RuntimeTask[]" />
      </WorkspacePanel>

      <WorkspacePanel v-show="focus !== 'tasks'" title="运行日志" :icon="Document" fill body-padding="compact">
        <template #actions>
          <el-input v-model="logSearch" class="log-search" clearable placeholder="搜索日志" :prefix-icon="Search" />
          <el-select v-model="logFilter" class="log-filter">
            <el-option label="全部级别" value="all" />
            <el-option label="信息" value="info" />
            <el-option label="成功" value="success" />
            <el-option label="警告" value="warning" />
            <el-option label="错误" value="error" />
          </el-select>
          <el-tooltip :content="focus === 'logs' ? '退出聚焦' : '聚焦日志'">
            <el-button circle :icon="focus === 'logs' ? Close : FullScreen" @click="toggleFocus('logs')" />
          </el-tooltip>
        </template>
        <LogPanel :logs="filteredLogs" />
      </WorkspacePanel>
    </div>
  </div>
</template>

<style scoped>
.run-page { display: grid; grid-template-rows: 44px 78px 202px minmax(0, 1fr); gap: 6px; width: 100%; height: 100%; min-width: 0; min-height: 0; }
.metric-grid { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 7px; min-width: 0; min-height: 0; }
.work-grid { display: grid; grid-template-columns: minmax(0, 3fr) minmax(390px, 2fr); gap: 8px; min-width: 0; min-height: 0; }
.work-grid.focus-tasks,
.work-grid.focus-logs { grid-template-columns: minmax(0, 1fr); }
.task-search { width: 165px; }
.task-filter { width: 110px; }
.log-search { width: 150px; }
.log-filter { width: 105px; }
</style>
