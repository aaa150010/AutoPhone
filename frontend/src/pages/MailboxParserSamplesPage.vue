<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { CircleCheck, CopyDocument, Delete, Download, Refresh, Search, View, Warning } from '@element-plus/icons-vue'
import {
  cleanupMailboxParserSamples,
  deleteMailboxParserSamples,
  exportMailboxParserSample,
  getMailboxParserSample,
  getMailboxParserSamples,
  reparseMailboxParserSample,
  revealMailboxParserSample,
  updateMailboxParserSampleStatus,
} from '../api/client'
import PageToolbar from '../components/PageToolbar.vue'
import WorkspacePanel from '../components/WorkspacePanel.vue'
import type { MailboxParserSample, MailboxParserSampleReparse } from '../types/api'

const loading = ref(false)
const samples = ref<MailboxParserSample[]>([])
const selected = ref<MailboxParserSample[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = 100
const query = ref({ scope: '', status: '', chain: '', driver: '', reason: '', q: '' })
const detail = ref<MailboxParserSample | null>(null)
const detailOpen = ref(false)
const rawOpen = ref(false)
const reparse = ref<MailboxParserSampleReparse | null>(null)
const health = ref<Record<string, any>>({})

const healthSummary = computed(() => Object.values(health.value).reduce((sum: number, item: any) => sum + Number(item?.samples || 0), 0))
const statusOptions = [
  { label: '全部状态', value: '' },
  { label: '待处理', value: 'new' },
  { label: '处理中', value: 'in_review' },
  { label: '已解决', value: 'resolved' },
  { label: '忽略', value: 'ignored' },
]
const scopeOptions = [{ label: '全部链路', value: '' }, { label: '普通流程', value: 'ordinary' }, { label: 'Free', value: 'free' }]
const driverOptions = [{ label: '全部驱动', value: '' }, { label: '短信 / OAuth', value: 'sms_oauth' }, { label: '协议', value: 'protocol' }, { label: 'Camoufox', value: 'camoufox' }]

function formatTime(value: any) {
  if (!value) return '-'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString()
}
function formatBytes(value: any) {
  const bytes = Number(value || 0)
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}
function statusLabel(value: string) { return ({ new: '待处理', in_review: '处理中', resolved: '已解决', ignored: '忽略' } as Record<string, string>)[value] || value || '-' }
function statusType(value: string) { return value === 'resolved' ? 'success' : value === 'ignored' ? 'info' : value === 'in_review' ? 'warning' : 'danger' }
function scopeLabel(value: string) { return value === 'free' ? 'Free' : '普通' }
function driverLabel(value: unknown) {
  const driver = String(value || '').trim().toLowerCase()
  if (driver === 'protocol') return '协议'
  if (driver === 'camoufox') return 'Camoufox'
  return driver ? '历史链路' : '-'
}

async function load() {
  loading.value = true
  try {
    const result = await getMailboxParserSamples({ ...query.value, limit: pageSize, offset: (page.value - 1) * pageSize })
    samples.value = result.samples || []
    total.value = Number(result.total || 0)
    health.value = result.health || {}
    selected.value = []
  } catch (error: any) { ElMessage.error(error?.message || '解析样本读取失败') } finally { loading.value = false }
}
function search() { page.value = 1; void load() }
function selectRows(rows: MailboxParserSample[]) { selected.value = rows }
async function openDetail(row: MailboxParserSample) {
  try {
    const result = await getMailboxParserSample(row.sample_id, row.scope)
    detail.value = result.sample
    detailOpen.value = true
    rawOpen.value = false
    reparse.value = null
  } catch (error: any) { ElMessage.error(error?.message || '解析样本详情读取失败') }
}
async function revealRaw() {
  if (!detail.value) return
  try {
    await ElMessageBox.confirm('原始 URL 和响应可能包含邮箱访问凭据、邮件内容或验证码，仅用于本机排查。确认查看？', '查看原始样本', { type: 'warning', confirmButtonText: '查看原文', cancelButtonText: '取消' })
    const result = await revealMailboxParserSample(detail.value.sample_id, detail.value.scope)
    detail.value = result.sample
    rawOpen.value = true
  } catch (error: any) { if (!['cancel', 'close', '取消'].includes(String(error))) ElMessage.error(error?.message || '原始样本读取失败') }
}
async function runReparse() {
  if (!detail.value) return
  try {
    reparse.value = (await reparseMailboxParserSample(detail.value.sample_id, detail.value.scope)).reparse
    ElMessage.success('已使用当前解析器离线重跑')
  } catch (error: any) { ElMessage.error(error?.message || '离线重解析失败') }
}
async function copyText(value: string, message: string) {
  if (!navigator.clipboard?.writeText) return ElMessage.warning('当前环境不支持复制')
  try { await navigator.clipboard.writeText(value); ElMessage.success(message) } catch (error: any) { ElMessage.error(error?.message || '复制失败') }
}
async function exportSample(format: 'sanitized' | 'fixture') {
  if (!detail.value) return
  if (format === 'fixture') {
    try { await ElMessageBox.confirm('原文夹具将包含完整 URL 和响应正文，仅保存到本机。确认导出？', '导出原文夹具', { type: 'warning', confirmButtonText: '导出', cancelButtonText: '取消' }) } catch { return }
  }
  try {
    const result = await exportMailboxParserSample(detail.value.sample_id, format, detail.value.scope)
    await copyText(result.content, format === 'fixture' ? '原文夹具已复制' : '脱敏夹具已复制')
  } catch (error: any) { ElMessage.error(error?.message || '样本导出失败') }
}
async function updateStatus(status: string) {
  const ids = selected.value.length ? selected.value.map(item => item.sample_id) : detail.value ? [detail.value.sample_id] : []
  if (!ids.length) return
  const scope = selected.value.length ? '' : detail.value?.scope || ''
  try { await updateMailboxParserSampleStatus(ids, status, scope); ElMessage.success('样本状态已更新'); await load(); if (detail.value && ids.includes(detail.value.sample_id)) detail.value.status = status; } catch (error: any) { ElMessage.error(error?.message || '样本状态更新失败') }
}
async function removeSelected() {
  const ids = selected.value.map(item => item.sample_id)
  if (!ids.length) return
  try { await ElMessageBox.confirm(`确定删除选中的 ${ids.length} 条解析样本？`, '删除解析样本', { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' }); await deleteMailboxParserSamples(ids); ElMessage.success('解析样本已删除'); await load() } catch (error: any) { if (!['cancel', 'close', '取消'].includes(String(error))) ElMessage.error(error?.message || '样本删除失败') }
}
async function cleanup() {
  try { const result = await cleanupMailboxParserSamples(); health.value = result.health || {}; await load(); ElMessage.success(`已清理 ${result.deleted || 0} 条过期样本`) } catch (error: any) { ElMessage.error(error?.message || '样本清理失败') }
}
function downloadFixture() {
  if (!detail.value) return
  void exportMailboxParserSample(detail.value.sample_id, 'sanitized', detail.value.scope).then(result => {
    const blob = new Blob([result.content], { type: 'application/json;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = `${detail.value?.sample_id || 'sample'}.json`; anchor.click(); URL.revokeObjectURL(url)
  }).catch((error: any) => ElMessage.error(error?.message || '夹具下载失败'))
}
function downloadSample(format: 'sanitized' | 'fixture') {
  if (!detail.value) return
  const sample = detail.value
  const run = async () => {
    if (format === 'fixture') {
      try { await ElMessageBox.confirm('原文夹具将包含完整 URL 和响应正文，仅保存到本机。确认导出？', '导出原文夹具', { type: 'warning', confirmButtonText: '导出', cancelButtonText: '取消' }) } catch { return }
    }
    try {
      const result = await exportMailboxParserSample(sample.sample_id, format, sample.scope)
      const blob = new Blob([result.content], { type: 'application/json;charset=utf-8' })
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a'); anchor.href = url; anchor.download = `${sample.sample_id || 'sample'}-${format}.json`; anchor.click(); URL.revokeObjectURL(url)
    } catch (error: any) { ElMessage.error(error?.message || '夹具下载失败') }
  }
  void run()
}

onMounted(() => { void load() })
</script>

<template>
  <div class="sample-page">
    <PageToolbar title="邮箱解析样本" :status="`${healthSummary} 条样本`" tone="warning">
      <el-button :icon="Refresh" :loading="loading" @click="load">刷新</el-button>
      <el-button :icon="Warning" @click="cleanup">清理过期</el-button>
    </PageToolbar>
    <WorkspacePanel title="筛选" :icon="Search" body-padding="normal">
      <el-form :model="query" inline @submit.prevent="search">
        <el-form-item label="链路"><el-select v-model="query.scope" style="width: 130px"><el-option v-for="item in scopeOptions" :key="item.value" v-bind="item" /></el-select></el-form-item>
        <el-form-item label="状态"><el-select v-model="query.status" style="width: 130px"><el-option v-for="item in statusOptions" :key="item.value" v-bind="item" /></el-select></el-form-item>
        <el-form-item label="驱动"><el-select v-model="query.driver" style="width: 150px"><el-option v-for="item in driverOptions" :key="item.value" v-bind="item" /></el-select></el-form-item>
        <el-form-item label="原因"><el-input v-model="query.reason" clearable style="width: 180px" /></el-form-item>
        <el-form-item label="关键字"><el-input v-model="query.q" clearable style="width: 220px" placeholder="样本 ID、任务或主机" /></el-form-item>
        <el-form-item><el-button type="primary" :icon="Search" @click="search">检索</el-button></el-form-item>
      </el-form>
    </WorkspacePanel>
    <WorkspacePanel title="未识别响应" :icon="Warning" fill body-padding="none">
      <div class="table-actions"><span>找到 {{ total }} 条 · 已选 {{ selected.length }} 条</span><div><el-button size="small" :icon="CircleCheck" :disabled="!selected.length" @click="updateStatus('resolved')">标记已解决</el-button><el-button size="small" :icon="Delete" type="danger" plain :disabled="!selected.length" @click="removeSelected">删除</el-button></div></div>
      <el-table :data="samples" height="100%" stripe v-loading="loading" @selection-change="selectRows">
        <el-table-column type="selection" width="44" />
        <el-table-column label="样本 ID" min-width="170" show-overflow-tooltip><template #default="{ row }"><el-link type="primary" @click="openDetail(row)">{{ row.sample_id }}</el-link></template></el-table-column>
        <el-table-column label="链路 / 驱动" min-width="140" show-overflow-tooltip><template #default="{ row }">{{ scopeLabel(row.scope) }} / {{ driverLabel(row.driver) }}</template></el-table-column>
        <el-table-column prop="stage" label="阶段" min-width="170" show-overflow-tooltip />
        <el-table-column prop="reason" label="未命中原因" min-width="220" show-overflow-tooltip />
        <el-table-column label="状态" width="90"><template #default="{ row }"><el-tag size="small" :type="statusType(row.status)">{{ statusLabel(row.status) }}</el-tag></template></el-table-column>
        <el-table-column label="出现" width="70" align="center"><template #default="{ row }">{{ row.occurrence_count }}</template></el-table-column>
        <el-table-column label="响应" width="70" align="center"><template #default="{ row }">{{ row.response_count }}</template></el-table-column>
        <el-table-column label="大小" width="95"><template #default="{ row }">{{ formatBytes(row.total_bytes) }}</template></el-table-column>
        <el-table-column label="最近时间" min-width="170"><template #default="{ row }">{{ formatTime(row.last_seen_at) }}</template></el-table-column>
        <el-table-column label="操作" width="100" fixed="right"><template #default="{ row }"><el-button text size="small" :icon="View" @click="openDetail(row)">查看</el-button></template></el-table-column>
        <template #empty><el-empty description="暂无未识别邮箱响应" /></template>
      </el-table>
      <div class="pagination"><el-pagination v-model:current-page="page" :page-size="pageSize" :total="total" layout="prev, pager, next" @current-change="load" /></div>
    </WorkspacePanel>
    <el-drawer v-model="detailOpen" :title="detail ? `解析样本 · ${detail.sample_id}` : '解析样本'" size="720px" destroy-on-close>
      <template v-if="detail">
        <div class="drawer-actions"><el-button size="small" :icon="Refresh" @click="runReparse">离线重解析</el-button><el-button size="small" :icon="CopyDocument" @click="exportSample('sanitized')">复制脱敏夹具</el-button><el-button size="small" :icon="Download" @click="downloadFixture">下载脱敏 JSON</el-button><el-button size="small" :icon="CopyDocument" type="warning" plain @click="exportSample('fixture')">复制原文夹具</el-button><el-button size="small" :icon="Download" type="warning" plain @click="downloadSample('fixture')">下载原文 JSON</el-button><el-button size="small" :icon="View" @click="revealRaw">查看原文</el-button></div>
        <el-descriptions :column="2" border size="small"><el-descriptions-item label="状态"><el-tag size="small" :type="statusType(detail.status)">{{ statusLabel(detail.status) }}</el-tag></el-descriptions-item><el-descriptions-item label="链路 / 驱动">{{ scopeLabel(detail.scope) }} / {{ driverLabel(detail.driver) }}</el-descriptions-item><el-descriptions-item label="阶段">{{ detail.stage }}</el-descriptions-item><el-descriptions-item label="未命中原因">{{ detail.reason }}</el-descriptions-item><el-descriptions-item label="解析器版本">{{ detail.parser_version }}</el-descriptions-item><el-descriptions-item label="出现次数">{{ detail.occurrence_count }}</el-descriptions-item><el-descriptions-item label="任务 ID" :span="2">{{ detail.task_id || '-' }}</el-descriptions-item><el-descriptions-item label="日志 ID" :span="2">{{ detail.incident_id || '-' }}</el-descriptions-item></el-descriptions>
        <section class="detail-section"><h3>解析诊断</h3><pre class="json-block">{{ JSON.stringify(detail.diagnostics || {}, null, 2) }}</pre></section>
        <section class="detail-section"><h3>响应工件</h3><el-table :data="detail.responses || []" size="small"><el-table-column prop="request_role" label="角色" width="110" /><el-table-column prop="http_status" label="HTTP" width="70" /><el-table-column prop="content_type" label="类型" min-width="180" show-overflow-tooltip /><el-table-column label="指纹" min-width="170" show-overflow-tooltip><template #default="{ row }"><code>{{ row.response_fingerprint }}</code></template></el-table-column><el-table-column prop="body_bytes" label="大小" width="90" /></el-table></section>
        <section v-if="reparse" class="detail-section"><h3>当前解析器重跑结果</h3><div class="reparse-metrics"><span>消息 {{ reparse.message_count }}</span><span>含验证码字段 {{ reparse.code_message_count }}</span><span>详情链接 {{ reparse.detail_url_fingerprints.length }}</span><span>解析错误 {{ reparse.parse_errors.length }}</span></div><pre class="json-block">{{ JSON.stringify(reparse, null, 2) }}</pre></section>
        <section v-if="rawOpen" class="detail-section raw-section"><h3>原始样本</h3><el-alert type="warning" :closable="false" title="仅本机查看：内容可能包含邮箱访问凭据、邮件正文或验证码" /><div v-for="response in detail.responses || []" :key="response.response_fingerprint" class="raw-response"><strong>{{ response.request_role }} · {{ response.response_url }}</strong><pre>{{ response.body_text }}</pre></div></section>
        <div class="status-actions"><el-button size="small" @click="updateStatus('in_review')">标记处理中</el-button><el-button size="small" type="success" plain @click="updateStatus('resolved')">标记已解决</el-button><el-button size="small" @click="updateStatus('ignored')">忽略</el-button></div>
      </template>
    </el-drawer>
  </div>
</template>

<style scoped>
.sample-page { display: grid; grid-template-rows: 44px auto minmax(0, 1fr); gap: 7px; width: 100%; height: 100%; min-height: 0; }
.sample-page :deep(.workspace-panel.is-fill) { min-height: 0; height: 100%; }
.sample-page :deep(.workspace-panel.is-fill .workspace-panel__body) { min-height: 0; }
.table-actions, .drawer-actions, .status-actions, .reparse-metrics { display: flex; align-items: center; gap: 8px; }
.table-actions { justify-content: space-between; min-height: 38px; padding: 0 10px; color: #718096; font-size: 12px; }
.pagination { display: flex; justify-content: flex-end; padding: 5px 8px; }
.drawer-actions { flex-wrap: wrap; margin-bottom: 14px; }
.detail-section { margin-top: 18px; }.detail-section h3 { margin: 0 0 8px; font-size: 14px; }
.json-block, .raw-response pre { max-height: 260px; overflow: auto; padding: 10px; border: 1px solid var(--workspace-border); border-radius: 4px; background: #f8fafc; color: #334155; font: 11px/17px ui-monospace, SFMono-Regular, Menlo, monospace; white-space: pre-wrap; word-break: break-word; }
.reparse-metrics { flex-wrap: wrap; margin-bottom: 8px; color: #64748b; font-size: 12px; }.reparse-metrics span { padding: 5px 8px; border: 1px solid var(--workspace-border); border-radius: 4px; background: #fbfdff; }
.raw-response { margin-top: 10px; }.raw-response strong { display: block; margin-bottom: 5px; color: #8b5a12; font-size: 11px; word-break: break-all; }.raw-response pre { max-height: 420px; background: #fff9ed; }
.status-actions { justify-content: flex-end; margin-top: 18px; padding-top: 12px; border-top: 1px solid var(--workspace-border); }
</style>
