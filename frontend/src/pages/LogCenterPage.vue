<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { CopyDocument, Delete, Download, Document, Refresh, Search, Warning } from '@element-plus/icons-vue'
import {
  clearDiagnostics,
  deleteDiagnostics,
  exportDiagnostics,
  getDiagnosticIncident,
  getDiagnosticsHealth,
  searchDiagnostics,
  type DiagnosticEvent,
  type DiagnosticIncident,
} from '../api/client'

const props = defineProps<{ locationKey?: string }>()

const loading = ref(false)
const healthLoading = ref(false)
const incidents = ref<DiagnosticIncident[]>([])
const selected = ref<DiagnosticIncident[]>([])
const detail = ref<DiagnosticIncident | null>(null)
const detailOpen = ref(false)
const health = ref<Record<string, any>>({})
const searchError = ref('')
let refreshTimer = 0
const query = ref({
  incident_id: '', task_id: '', batch_id: '', subject: '', from: '', to: '',
  chain: '', driver: '', outcome: '', first_node_code: '', limit: 100,
})

const statusOptions = [
  { label: '全部状态', value: '' },
  { label: '失败', value: 'error' },
  { label: '停止', value: 'stopped' },
  { label: '运行中', value: 'open' },
  { label: '警告', value: 'warn' },
  { label: '成功', value: 'success' },
]
const driverOptions = [
  { label: '全部驱动', value: '' },
  { label: '短信 / OAuth', value: 'sms_oauth' },
  { label: '协议', value: 'protocol' },
  { label: 'RoxyBrowser', value: 'roxybrowser' },
  { label: 'Camoufox', value: 'camoufox' },
  { label: '支付适配器', value: 'payment' },
  { label: '网络工具', value: 'network' },
]
const chainOptions = [
  { label: '全部链路', value: '' },
  { label: '普通流程', value: 'ordinary' },
  { label: 'Free 注册', value: 'free' },
  { label: 'Free 换绑', value: 'free_rebind' },
  { label: '支付', value: 'payment' },
  { label: '网络', value: 'network' },
]
const filteredCount = computed(() => incidents.value.length)

function outcomeLabel(value: any, status?: any) {
  if (String(status || '').toLowerCase() === 'open' && !['error', 'failed', 'failure'].includes(String(value || '').toLowerCase())) return '运行中'
  return ({ error: '失败', failed: '失败', failure: '失败', stopped: '已停止', partial: '部分成功', partial_success: '部分成功', warn: '警告', success: '成功', info: '信息' } as Record<string, string>)[String(value || '').toLowerCase()] || String(value || '未知')
}
function outcomeType(value: any, status?: any) {
  const normalized = String(value || '').toLowerCase()
  if (String(status || '').toLowerCase() === 'open') return 'warning'
  if (['error', 'failed', 'failure'].includes(normalized)) return 'danger'
  if (normalized === 'success') return 'success'
  if (normalized === 'partial' || normalized === 'partial_success') return 'warning'
  if (normalized === 'warn' || normalized === 'stopped') return 'warning'
  return 'info'
}
function chainLabel(value: any) {
  return ({ ordinary: '普通流程', free: 'Free', free_rebind: 'Free 换绑', payment: '支付', network: '网络' } as Record<string, string>)[String(value || '')] || String(value || '未知链路')
}
function formatTime(value: any) {
  if (!value) return '-'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString()
}
function formatDuration(event: DiagnosticEvent) {
  if (event.elapsed_ms == null) return '-'
  return event.elapsed_ms < 1000 ? `${event.elapsed_ms} ms` : `${(event.elapsed_ms / 1000).toFixed(1)} s`
}
function searchWindow(hours: number) {
  const now = new Date()
  const start = new Date(now.getTime() - hours * 3600 * 1000)
  query.value.from = start.toISOString()
  query.value.to = now.toISOString()
  void runSearch()
}
async function runSearch() {
  loading.value = true
  searchError.value = ''
  try {
    const payload = Object.fromEntries(Object.entries(query.value).filter(([, value]) => value !== ''))
    const result = await searchDiagnostics(payload)
    incidents.value = Array.isArray(result.results) ? result.results : []
    selected.value = []
  } catch (error: any) {
    searchError.value = error?.message || '日志检索失败'
    ElMessage.error(error?.message || '日志检索失败')
  } finally {
    loading.value = false
  }
}
async function refreshHealth() {
  healthLoading.value = true
  try { health.value = (await getDiagnosticsHealth()).health || {} } catch (error: any) { ElMessage.error(error?.message || '日志中心状态读取失败') } finally { healthLoading.value = false }
}
async function openIncident(row: DiagnosticIncident) {
  try {
    detail.value = (await getDiagnosticIncident(row.incident_id)).incident
    detailOpen.value = true
  } catch (error: any) { ElMessage.error(error?.message || '日志详情读取失败') }
}
async function copyText(value: string, success = '已复制') {
  if (!navigator.clipboard?.writeText) return ElMessage.warning('当前环境不支持复制')
  try {
    await navigator.clipboard.writeText(value)
    ElMessage.success(success)
  } catch (error: any) {
    ElMessage.error(error?.message || '复制失败')
  }
}
async function copyIncidentId(row: DiagnosticIncident) { await copyText(row.incident_id, '日志 ID 已复制') }
async function copyGpt(row: DiagnosticIncident) {
  try {
    const result = await exportDiagnostics([row.incident_id], 'markdown')
    await copyText(result.content, 'GPT 脱敏诊断已复制')
  } catch (error: any) {
    ElMessage.error(error?.message || 'GPT 诊断复制失败')
  }
}
async function downloadJson(row: DiagnosticIncident) {
  try {
    const result = await exportDiagnostics([row.incident_id], 'json')
    const blob = new Blob([result.content], { type: 'application/json;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `${row.incident_id}.json`
    anchor.click()
    URL.revokeObjectURL(url)
  } catch (error: any) {
    ElMessage.error(error?.message || 'JSON 下载失败')
  }
}
async function deleteSelected() {
  const ids = selected.value.map(row => row.incident_id)
  if (!ids.length) return
  try {
    await ElMessageBox.confirm(`将删除选中的 ${ids.length} 条诊断日志，不会删除账号、邮箱池或任务结果。`, '确认删除日志', { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' })
    await deleteDiagnostics(ids)
    ElMessage.success('诊断日志已删除')
    await runSearch()
    await refreshHealth()
  } catch (error: any) {
    if (!['cancel', 'close', '取消'].includes(String(error))) ElMessage.error(error?.message || '诊断日志删除失败')
  }
}
async function clearAll() {
  try {
    await ElMessageBox.confirm('将清空全部诊断日志，不会删除账号、邮箱池、代理池或任务结果。此操作不可恢复。', '确认清空日志中心', { type: 'warning', confirmButtonText: '清空全部', cancelButtonText: '取消' })
    const result = await clearDiagnostics()
    ElMessage.success(`已清空 ${result.deleted || 0} 条诊断日志`)
    await runSearch()
    await refreshHealth()
  } catch (error: any) {
    if (!['cancel', 'close', '取消'].includes(String(error))) ElMessage.error(error?.message || '清空诊断日志失败')
  }
}
function selectRows(rows: DiagnosticIncident[]) { selected.value = rows }

async function loadFromLocation(locationKey = '') {
  const current = new URL(locationKey || window.location.href, window.location.origin)
  const incidentId = String(current.searchParams.get('incident_id') || current.searchParams.get('log_id') || '').trim().toUpperCase()
  if (incidentId) query.value.incident_id = incidentId
  await runSearch()
  if (incidentId) {
    const match = incidents.value.find(row => row.incident_id === incidentId)
    if (match) await openIncident(match)
  }
}

onMounted(() => {
  // The page is mounted only for /logs, so a missing or stale location prop
  // must not suppress the initial query and make an existing log store look empty.
  void loadFromLocation(props.locationKey || '/logs')
  void refreshHealth()
  refreshTimer = window.setInterval(() => {
    if (!loading.value) void runSearch()
    if (!healthLoading.value) void refreshHealth()
  }, 15000)
})
onUnmounted(() => { window.clearInterval(refreshTimer) })
watch(() => props.locationKey, (value, previous) => {
  if (value && value !== previous) void loadFromLocation(value)
})
</script>

<template>
  <div class="log-center">
    <div class="page-toolbar">
      <div><h2>日志中心</h2><span class="subtitle">统一检索普通流程、Free 链路和换绑故障档案</span></div>
      <div class="toolbar-actions"><el-button :icon="Refresh" :loading="loading" @click="runSearch">刷新</el-button><el-button :icon="Warning" :loading="healthLoading" @click="refreshHealth">健康状态</el-button><el-button type="danger" plain :icon="Delete" :disabled="!incidents.length" @click="clearAll">清空全部</el-button></div>
    </div>
    <el-card shadow="never" class="search-panel">
      <el-form :model="query" label-position="top" @submit.prevent="runSearch">
        <div class="search-grid">
          <el-form-item label="日志 ID"><el-input v-model="query.incident_id" clearable placeholder="LOG-20260825-..." /></el-form-item>
          <el-form-item label="任务 ID"><el-input v-model="query.task_id" clearable /></el-form-item>
          <el-form-item label="批次 ID"><el-input v-model="query.batch_id" clearable /></el-form-item>
          <el-form-item label="账号 / 邮箱"><el-input v-model="query.subject" clearable /></el-form-item>
          <el-form-item label="开始时间"><el-input v-model="query.from" clearable placeholder="2026-08-25T00:00:00" /></el-form-item>
          <el-form-item label="结束时间"><el-input v-model="query.to" clearable placeholder="2026-08-25T23:59:59" /></el-form-item>
          <el-form-item label="状态"><el-select v-model="query.outcome" class="full-width"><el-option v-for="item in statusOptions" :key="item.value" :label="item.label" :value="item.value" /></el-select></el-form-item>
          <el-form-item label="链路"><el-select v-model="query.chain" class="full-width"><el-option v-for="item in chainOptions" :key="item.value" :label="item.label" :value="item.value" /></el-select></el-form-item>
          <el-form-item label="驱动"><el-select v-model="query.driver" class="full-width"><el-option v-for="item in driverOptions" :key="item.value" :label="item.label" :value="item.value" /></el-select></el-form-item>
          <el-form-item label="节点"><el-input v-model="query.first_node_code" clearable placeholder="例如 free_email_otp_wait" /></el-form-item>
        </div>
        <div class="search-actions"><el-button type="primary" :icon="Search" :loading="loading" @click="runSearch">检索</el-button><el-button @click="searchWindow(0.25)">最近 15 分钟</el-button><el-button @click="searchWindow(1)">最近 1 小时</el-button><el-button @click="searchWindow(24)">最近 24 小时</el-button><span class="search-count">找到 {{ filteredCount }} 条</span></div>
      </el-form>
    </el-card>
    <div class="health-strip"><span>诊断库：{{ health.incidents ?? '-' }} 条故障 / {{ health.events ?? '-' }} 条事件</span><span :class="health.integrity_failures ? 'health-danger' : 'health-ok'">完整性异常 {{ health.integrity_failures ?? 0 }}</span><span class="health-path">详细事件默认保留 30 天</span></div>
    <el-card shadow="never" class="result-panel">
      <div class="result-actions"><span>已选 {{ selected.length }} 条</span><el-button size="small" :icon="Delete" type="danger" plain :disabled="!selected.length" @click="deleteSelected">删除选中</el-button></div>
      <el-alert v-if="searchError" class="search-error" type="error" :closable="false" show-icon :title="searchError" />
      <el-table v-else class="incident-table" :data="incidents" v-loading="loading" height="100%" stripe @selection-change="selectRows">
        <el-table-column type="selection" width="46" fixed="left" />
        <el-table-column label="日志 ID" min-width="188" fixed="left"><template #default="{ row }"><div class="incident-id"><el-link type="primary" @click="openIncident(row)">{{ row.incident_id }}</el-link><el-button text size="small" :icon="CopyDocument" aria-label="复制日志 ID" @click="copyIncidentId(row)" /></div></template></el-table-column>
        <el-table-column label="状态" width="78"><template #default="{ row }"><el-tag size="small" :type="outcomeType(row.outcome, row.status)">{{ outcomeLabel(row.outcome, row.status) }}</el-tag></template></el-table-column>
        <el-table-column prop="subject_display" label="账号" min-width="150" show-overflow-tooltip />
        <el-table-column label="链路" min-width="150"><template #default="{ row }">{{ chainLabel(row.chain) }} / {{ row.driver || '-' }}</template></el-table-column>
        <el-table-column label="匹配依据" min-width="150" show-overflow-tooltip><template #default="{ row }">{{ (row.match_basis || []).join('、') || '最近发生时间' }}</template></el-table-column>
        <el-table-column label="首个失败节点" min-width="210" show-overflow-tooltip><template #default="{ row }"><span class="failure-node">{{ row.first_node_label || '-' }}</span><code>{{ row.first_node_code || '' }}</code></template></el-table-column>
        <el-table-column prop="task_id" label="任务 ID" min-width="150" show-overflow-tooltip />
        <el-table-column label="发生时间" min-width="170"><template #default="{ row }">{{ formatTime(row.updated_at) }}</template></el-table-column>
        <el-table-column label="操作" width="170" fixed="right"><template #default="{ row }"><el-button text size="small" @click="copyGpt(row)">复制 GPT 诊断</el-button><el-button text size="small" :icon="Download" aria-label="下载 JSON" @click="downloadJson(row)" /></template></el-table-column>
        <template #empty><el-empty :description="health.incidents ? '已连接诊断库，但当前筛选条件没有匹配记录' : '暂无诊断日志记录'" /></template>
      </el-table>
    </el-card>
    <el-drawer v-model="detailOpen" :title="detail ? `日志详情 · ${detail.incident_id}` : '日志详情'" size="720px" destroy-on-close>
      <template v-if="detail">
        <div class="detail-actions"><el-button size="small" :icon="CopyDocument" @click="copyIncidentId(detail)">复制日志 ID</el-button><el-button size="small" @click="copyGpt(detail)">复制 GPT 诊断</el-button><el-button size="small" :icon="Download" @click="downloadJson(detail)">下载 JSON</el-button></div>
        <el-descriptions :column="2" border size="small" class="detail-summary"><el-descriptions-item label="日志 ID">{{ detail.incident_id }}</el-descriptions-item><el-descriptions-item label="最终状态">{{ outcomeLabel(detail.outcome, detail.status) }}</el-descriptions-item><el-descriptions-item label="完整性">{{ detail.integrity_status || '-' }}</el-descriptions-item><el-descriptions-item label="链路">{{ chainLabel(detail.chain) }}</el-descriptions-item><el-descriptions-item label="驱动">{{ detail.driver || '-' }}</el-descriptions-item><el-descriptions-item label="任务 ID">{{ detail.task_id || '-' }}</el-descriptions-item><el-descriptions-item label="批次 ID">{{ detail.batch_id || '-' }}</el-descriptions-item><el-descriptions-item label="首个失败节点" :span="2">{{ detail.first_node_label || '-' }} / {{ detail.first_node_code || '-' }}</el-descriptions-item><el-descriptions-item label="错误代码">{{ detail.first_error_code || '-' }}</el-descriptions-item><el-descriptions-item label="HTTP 状态">{{ detail.failure?.http_status || '-' }}</el-descriptions-item><el-descriptions-item label="Provider Code">{{ detail.failure?.provider_code || '-' }}</el-descriptions-item><el-descriptions-item label="事件数">{{ detail.event_count || 0 }}</el-descriptions-item></el-descriptions>
        <section class="detail-section"><h3>已确认事实</h3><p class="fact-note">以下内容来自本地脱敏审计事件，不代表未记录内容。</p></section>
        <section class="detail-section"><h3>关键时间线</h3><el-timeline><el-timeline-item v-for="event in detail.events || []" :key="event.event_id" :timestamp="formatTime(event.occurred_at)" :type="outcomeType(event.outcome)"><div class="event-row"><strong>{{ event.node_label || event.node_code || '未命名节点' }}</strong><el-tag size="small" :type="outcomeType(event.outcome)">{{ outcomeLabel(event.outcome) }}</el-tag><span v-if="event.attempt">第 {{ event.attempt }} 次</span><span v-if="event.elapsed_ms != null">耗时 {{ formatDuration(event) }}</span></div><code v-if="event.node_code">{{ event.node_code }}</code><p v-if="event.message">{{ event.message }}</p></el-timeline-item></el-timeline></section>
        <section class="detail-section"><h3>未确认信息</h3><p class="unknown-note">历史原始日志可能已经按保留策略清理；当前详情只使用已进入诊断索引的脱敏事件。</p></section>
      </template>
    </el-drawer>
  </div>
</template>

<style scoped>
.log-center { display: grid; grid-template-rows: auto auto auto minmax(0, 1fr); gap: 8px; width: 100%; height: 100%; min-height: 0; padding: 8px; }
.page-toolbar, .result-actions, .search-actions, .health-strip, .detail-actions, .incident-id, .event-row { display: flex; align-items: center; }
.page-toolbar { justify-content: space-between; gap: 12px; min-height: 38px; }
.page-toolbar h2 { margin: 0; color: var(--el-text-color-primary); font-size: 18px; line-height: 24px; }
.subtitle, .health-strip, .fact-note, .unknown-note { color: var(--el-text-color-secondary); font-size: 12px; }
.toolbar-actions, .search-actions, .detail-actions { gap: 8px; }
.search-panel { border: 1px solid var(--workspace-border); }
.search-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 0 12px; }
.search-grid :deep(.el-form-item) { margin-bottom: 8px; }
.full-width { width: 100%; }
.search-count { margin-left: auto; color: var(--el-text-color-secondary); font-size: 12px; }
.health-strip { gap: 16px; min-height: 24px; padding: 0 4px; }
.health-ok { color: var(--el-color-success); }.health-danger { color: var(--el-color-danger); }.health-path { margin-left: auto; }
.result-panel { display: flex; min-height: 0; height: 100%; flex-direction: column; border: 1px solid var(--workspace-border); }
.result-panel :deep(.el-card__body) { display: flex; min-width: 0; min-height: 0; flex: 1 1 auto; flex-direction: column; overflow: hidden; padding: 8px; }
.result-panel :deep(.search-error) { flex: 0 0 auto; margin: 8px; }
.result-actions { justify-content: space-between; padding: 0 8px; color: var(--el-text-color-secondary); font-size: 12px; }
.result-actions { flex: 0 0 32px; }
.incident-table { width: 100%; min-height: 0; flex: 1 1 auto; }
.incident-id { gap: 4px; }.failure-node { color: var(--el-color-danger); }.failure-node + code { margin-left: 5px; color: var(--el-text-color-secondary); font-size: 10px; }
.detail-actions { margin-bottom: 14px; }.detail-summary { margin-bottom: 18px; }.detail-section { margin-top: 18px; }.detail-section h3 { margin: 0 0 7px; font-size: 14px; }.event-row { gap: 8px; flex-wrap: wrap; }.event-row span { color: var(--el-text-color-secondary); font-size: 12px; }.detail-section code { color: var(--el-text-color-secondary); font-size: 11px; }.detail-section p { margin: 5px 0 0; color: var(--el-text-color-regular); font-size: 12px; line-height: 18px; }
@media (max-width: 1150px) { .search-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
</style>
