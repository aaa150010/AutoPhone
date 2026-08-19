<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { CopyDocument, Delete, Key, Lock, Plus, Refresh, RefreshRight, Tickets, Link, Download, CircleCheck, Warning, View, VideoPlay } from '@element-plus/icons-vue'
import { deleteFreeMailboxes, exportFreeResults, getFreeLiveCheckState, getFreeLogs, getFreeMailboxUrl, getFreeMailboxes, getFreeSecret, importFreeMailboxes, retryFreeTwofa, setFreeMailboxStatus, startFree, startFreeLiveCheck } from '../api/client'
import type { FreeLiveCheckState, FreeMailboxRow } from '../api/client'
import ContentEmptyState from './ContentEmptyState.vue'
import WorkspacePanel from './WorkspacePanel.vue'

const rows = ref<FreeMailboxRow[]>([])
const selected = ref<FreeMailboxRow[]>([])
const loading = ref(false)
const importOpen = ref(false)
const mailboxText = ref('')
const currentPage = ref(1)
const pageSize = ref(100)
const tableRef = ref<any>()
const search = ref('')
const statusFilter = ref('')
const driverFilter = ref('')
const liveStatusFilter = ref('')
const liveBusy = ref<'fast' | 'deep' | ''>('')
const runBusy = ref(false)
const liveState = ref<FreeLiveCheckState>({ running: false, workers: 3, queue_limit: 500, active: 0, jobs: [] })
const logDialogOpen = ref(false)
const logLoading = ref(false)
const logRow = ref<FreeMailboxRow | null>(null)
const liveLogs = ref<Array<{ time?: string; level?: string; message?: string; stage?: string; stage_label?: string; page?: string; http_status?: number | string; duration_ms?: number | string; outcome?: string }>>([])
const logScroll = ref<HTMLElement>()
let refreshTimer = 0

const filteredRows = computed(() => rows.value.filter(row => {
  const needle = search.value.trim().toLowerCase()
  return (!needle || row.email.toLowerCase().includes(needle) || String(row.registration_ip || row.exit_ip || '').includes(needle))
    && (!statusFilter.value || row.status === statusFilter.value)
    && (!driverFilter.value || row.driver === driverFilter.value)
    && (!liveStatusFilter.value || (liveStatusFilter.value === 'active' ? ['queued', 'running'].includes(String(row.live_check_status || '')) : row.live_check_status === liveStatusFilter.value))
}))
const pageRows = computed(() => filteredRows.value.slice((currentPage.value - 1) * pageSize.value, currentPage.value * pageSize.value))
const metrics = computed(() => {
  const count = (status: string) => rows.value.filter(row => row.status === status).length
  const live = (status: string) => rows.value.filter(row => row.live_check_status === status).length
  return { total: rows.value.length, available: count('available'), running: count('running'), success: count('success'), failed: count('failed'), pending: count('twofa_pending'), live: live('live'), deactivated: live('deactivated'), checking: live('queued') + live('running') }
})
function openImport() {
  mailboxText.value = ''
  importOpen.value = true
}
defineExpose({ openImport })

async function refresh() {
  loading.value = true
  try {
    rows.value = (await getFreeMailboxes()).rows || []
  } catch (error: any) {
    ElMessage.error(error?.message || 'Free 邮箱池刷新失败')
  } finally {
    loading.value = false
  }
}

async function refreshLiveState() {
  try {
    const result = await getFreeLiveCheckState()
    liveState.value = result.state || liveState.value
    rows.value = result.rows || rows.value
    if (logRow.value?.row_id) logRow.value = rows.value.find(row => row.row_id === logRow.value?.row_id) || logRow.value
    if (logDialogOpen.value && logRow.value?.live_check_task_id) {
      const top = logScroll.value?.scrollTop || 0
      liveLogs.value = (await getFreeLogs(logRow.value.live_check_task_id)).logs || liveLogs.value
      await nextTick()
      if (logScroll.value) logScroll.value.scrollTop = top
    }
  } catch (error: any) {
    if (liveState.value.running) ElMessage.error(error?.message || 'Free 测活状态刷新失败')
  }
}

function canLiveCheck(row: FreeMailboxRow) {
  return Boolean(row.has_access_token && row.proxy_masked && (row.registration_ip || row.exit_ip))
    && !['queued', 'running'].includes(String(row.live_check_status || ''))
}

async function startLiveCheck(mode: 'fast' | 'deep', selection = selected.value) {
  const eligible = selection.filter(canLiveCheck)
  if (!eligible.length) {
    ElMessage.warning('请选择已保存 Token、注册代理和注册 IP 的 Free 账号')
    return
  }
  if (mode === 'deep') {
    try {
      await ElMessageBox.confirm(
        `深度测活会固定使用注册代理重新登录 ${eligible.length} 个账号，并可能多收一封 OTP 邮件。确定继续吗？`,
        '深度测活',
        { type: 'warning', confirmButtonText: '开始测活', cancelButtonText: '取消' },
      )
    } catch {
      return
    }
  }
  liveBusy.value = mode
  try {
    const result = await startFreeLiveCheck(mode, eligible.map(row => row.row_id))
    rows.value = result.rows || rows.value
    liveState.value = result.state || liveState.value
    const skipped = Number(result.skipped_count || 0)
    ElMessage.success(`已加入${mode === 'fast' ? '快速' : '深度'}测活 ${Number(result.accepted_count || 0)} 个${skipped ? `，跳过 ${skipped} 个` : ''}`)
  } catch (error: any) {
    ElMessage.error(error?.message || `${mode === 'fast' ? '快速' : '深度'}测活启动失败`)
  } finally {
    liveBusy.value = ''
  }
}

async function quickStart() {
  if (runBusy.value) return
  try {
    await ElMessageBox.confirm(
      '将按 Free 运行配置中的链路、目标数和并发直接开始注册。确定启动吗？',
      '快捷启动 Free 注册',
      { type: 'warning', confirmButtonText: '开始注册', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  runBusy.value = true
  try {
    const result = await startFree()
    ElMessage.success(`Free 注册已启动：${result.batch_id || '新批次'}`)
    await refresh()
  } catch (error: any) {
    ElMessage.error(error?.message || 'Free 注册启动失败')
  } finally {
    runBusy.value = false
  }
}

async function openLiveLog(row: FreeMailboxRow) {
  if (!row.live_check_task_id) return
  logRow.value = row
  logDialogOpen.value = true
  logLoading.value = true
  try {
    liveLogs.value = (await getFreeLogs(row.live_check_task_id)).logs || []
  } catch (error: any) {
    ElMessage.error(error?.message || '测活日志读取失败')
  } finally {
    logLoading.value = false
  }
}

function liveStatusLabel(status = '') {
  return ({ queued: '排队', running: '测活中', live: '正常', deactivated: '已停用', token_expired: 'Token 失效', failed: '失败' } as Record<string, string>)[status] || '未测活'
}

function liveStatusType(status = '') {
  return status === 'live' ? 'success' : status === 'deactivated' || status === 'failed' ? 'danger' : status === 'token_expired' ? 'warning' : 'info'
}

function scheduleRefresh() {
  refreshTimer = window.setTimeout(async () => {
    await refreshLiveState()
    scheduleRefresh()
  }, liveState.value.running || logDialogOpen.value ? 1200 : 5000)
}

async function importPools() {
  if (!mailboxText.value.trim()) {
    ElMessage.warning('请填写 Free 邮箱池')
    return
  }
  loading.value = true
  try {
    const messages: string[] = []
    const result = await importFreeMailboxes(mailboxText.value)
    messages.push(`新增 ${Number(result.imported || 0)} 条`)
    if (Number(result.skipped || 0)) messages.push(`跳过重复 ${Number(result.skipped || 0)} 条`)
    importOpen.value = false
    selected.value = []
    tableRef.value?.clearSelection()
    await refresh()
    ElMessage.success(`Free 池导入完成：${messages.join('，')}`)
  } catch (error: any) {
    ElMessage.error(error?.message || 'Free 池导入失败')
  } finally {
    loading.value = false
  }
}

async function deleteSelected() {
  const rowIds = selected.value.map(row => row.row_id).filter(Boolean)
  if (!rowIds.length) return
  try {
    await ElMessageBox.confirm(
      `确定删除选中的 ${rowIds.length} 条 Free 邮箱吗？历史注册结果会保留。`,
      '删除 Free 邮箱',
      { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  loading.value = true
  try {
    const result = await deleteFreeMailboxes(rowIds)
    selected.value = []
    tableRef.value?.clearSelection()
    await refresh()
    ElMessage.success(`已删除 ${Number(result.deleted || 0)} 条 Free 邮箱`)
  } catch (error: any) {
    ElMessage.error(error?.message || 'Free 邮箱删除失败')
  } finally {
    loading.value = false
  }
}

async function copySecret(kind: 'token' | 'password' | 'totp' | 'proxy' | 'credential', selection = selected.value) {
  const eligible = selection.filter(row => kind === 'token' ? row.has_access_token : kind === 'password' ? row.has_password : kind === 'totp' ? row.has_totp : kind === 'credential' ? row.has_credential : Boolean(row.proxy_masked))
  if (!eligible.length) {
    ElMessage.warning('当前没有可复制的 Free 记录')
    return
  }
  try {
    const value = (await getFreeSecret(kind, { row_ids: eligible.map(row => row.row_id) })).value
    await navigator.clipboard.writeText(value || '')
    ElMessage.success(`已复制 ${eligible.length} 条${kind === 'token' ? ' Token' : kind === 'password' ? '密码' : kind === 'totp' ? '2FA 密钥' : kind === 'credential' ? '完整凭据' : '代理'}`)
  } catch (error: any) {
    ElMessage.error(error?.message || 'Free 敏感字段复制失败')
  }
}

async function copyRow(kind: 'token' | 'password' | 'totp' | 'proxy' | 'credential', row: FreeMailboxRow) {
  await copySecret(kind, [row])
}

async function retryTwofa(row: FreeMailboxRow) {
  if (row.twofa_status !== 'pending' || !row.row_id) return
  try {
    await retryFreeTwofa(row.row_id)
    ElMessage.info('已重新加入 2FA 设置任务')
    await refresh()
  } catch (error: any) {
    ElMessage.error(error?.message || '2FA 重试失败')
  }
}

async function setStatus(status: 'available' | 'unavailable' | 'draft') {
  const ids = selected.value.map(row => row.row_id).filter(Boolean)
  if (!ids.length) return
  loading.value = true
  try {
    await setFreeMailboxStatus(status, ids)
    selected.value = []
    tableRef.value?.clearSelection()
    await refresh()
    ElMessage.success(`已更新 ${ids.length} 条 Free 邮箱状态`)
  } catch (error: any) {
    ElMessage.error(error?.message || 'Free 邮箱状态更新失败')
  } finally { loading.value = false }
}

async function openUrl(row: FreeMailboxRow) {
  if (!row.row_id) return
  try {
    const value = (await getFreeMailboxUrl(row.row_id)).mailbox_url
    const target = new URL(value)
    if (!['http:', 'https:'].includes(target.protocol)) throw new Error('取件 URL 协议不安全')
    window.open(target.href, '_blank', 'noopener,noreferrer')
  } catch (error: any) { ElMessage.error(error?.message || '打开 Free 取件地址失败') }
}

async function exportResults() {
  try {
    const result = await exportFreeResults(selected.value.map(row => row.row_id))
    const blob = new Blob([result.content || ''], { type: 'text/plain;charset=utf-8' })
    const link = document.createElement('a')
    link.href = URL.createObjectURL(blob)
    link.download = result.filename || 'free-results.txt'
    link.click()
    URL.revokeObjectURL(link.href)
    ElMessage.success(`已导出 ${Number(result.count || 0)} 条 Free 结果`)
  } catch (error: any) { ElMessage.error(error?.message || 'Free 结果导出失败') }
}

onMounted(async () => {
  await refresh()
  await refreshLiveState()
  scheduleRefresh()
})
onUnmounted(() => window.clearTimeout(refreshTimer))
</script>

<template>
  <div class="free-pool">
    <WorkspacePanel title="Free 注册邮箱池" :icon="Tickets" fill body-padding="none">
      <template #actions>
        <span class="pool-summary">共 {{ rows.length }} 条</span>
        <el-button size="small" type="primary" :icon="VideoPlay" :loading="runBusy" @click="quickStart">快捷运行</el-button>
        <el-button size="small" :icon="Refresh" :loading="loading" @click="refresh">刷新</el-button>
        <el-button size="small" type="primary" :icon="Plus" @click="openImport">导入 Free 邮箱</el-button>
      </template>

      <div class="table-region">
        <div class="metrics"><span>总数 <b>{{ metrics.total }}</b></span><span class="is-good">注册成功 <b>{{ metrics.success }}</b></span><span>测活中 <b>{{ metrics.checking }}</b></span><span class="is-good">账号正常 <b>{{ metrics.live }}</b></span><span class="is-bad">已停用 <b>{{ metrics.deactivated }}</b></span><span class="is-warn">2FA 待重试 <b>{{ metrics.pending }}</b></span></div>
        <div class="filters"><el-input v-model="search" size="small" clearable placeholder="搜索邮箱或注册 IP" /><el-select v-model="statusFilter" size="small" clearable placeholder="注册状态"><el-option label="可用" value="available" /><el-option label="运行中" value="running" /><el-option label="成功" value="success" /><el-option label="失败" value="failed" /><el-option label="2FA 待重试" value="twofa_pending" /></el-select><el-select v-model="driverFilter" size="small" clearable placeholder="注册链路"><el-option label="全协议" value="protocol" /><el-option label="RoxyBrowser" value="roxybrowser" /></el-select><el-select v-model="liveStatusFilter" size="small" clearable placeholder="测活状态"><el-option label="排队 / 测活中" value="active" /><el-option label="正常" value="live" /><el-option label="已停用" value="deactivated" /><el-option label="Token 失效" value="token_expired" /><el-option label="测活失败" value="failed" /></el-select></div>
        <div class="bulk-actions"><span>已选 {{ selected.length }} 条</span><el-button size="small" type="success" plain :icon="CircleCheck" :loading="liveBusy === 'fast'" :disabled="!selected.some(canLiveCheck) || Boolean(liveBusy)" @click="startLiveCheck('fast')">快速测活</el-button><el-button size="small" type="warning" plain :icon="RefreshRight" :loading="liveBusy === 'deep'" :disabled="!selected.some(canLiveCheck) || Boolean(liveBusy)" @click="startLiveCheck('deep')">深度测活</el-button><el-button size="small" :icon="CopyDocument" :disabled="!selected.length" @click="copySecret('token')">复制 Token</el-button><el-button size="small" :icon="CopyDocument" :disabled="!selected.some(row => row.has_credential)" @click="copySecret('credential')">复制凭据</el-button><el-button size="small" :icon="CopyDocument" :disabled="!pageRows.some(row => row.has_access_token)" @click="copySecret('token', pageRows)">当前页 Token</el-button><el-button size="small" :icon="Download" :disabled="loading" @click="exportResults">导出</el-button><el-button size="small" :icon="CircleCheck" :disabled="!selected.length || loading" @click="setStatus('available')">恢复</el-button><el-button size="small" :icon="Warning" :disabled="!selected.length || loading" @click="setStatus('unavailable')">不可用</el-button><el-button size="small" type="danger" plain :icon="Delete" :disabled="!selected.length || loading" @click="deleteSelected">删除选中</el-button></div>
        <el-table
          ref="tableRef"
          :data="pageRows"
          row-key="row_id"
          stripe
          height="100%"
          @selection-change="selected = $event"
        >
          <el-table-column type="selection" width="42" reserve-selection />
          <el-table-column type="index" label="序号" width="58" align="center" fixed="left" />
          <el-table-column prop="line_no" label="原序号" width="68" align="right" />
          <el-table-column prop="email" label="邮箱" min-width="190" show-overflow-tooltip />
          <el-table-column label="链路 / 阶段" min-width="180" show-overflow-tooltip>
            <template #default="{ row }"><el-tag size="small" effect="plain">{{ row.driver === 'roxybrowser' ? 'RoxyBrowser' : '全协议' }}</el-tag><el-tag size="small" :type="row.status === 'success' ? 'success' : row.status === 'failed' ? 'danger' : 'warning'">{{ row.stage || row.status || '可用' }}</el-tag></template>
          </el-table-column>
          <el-table-column label="代理 / 注册 IP" min-width="210" show-overflow-tooltip>
            <template #default="{ row }"><span>{{ row.proxy_masked || '-' }}</span><small v-if="row.registration_ip || row.exit_ip"> / {{ row.registration_ip || row.exit_ip }}</small></template>
          </el-table-column>
          <el-table-column label="套餐 / Plus 试用" width="150">
            <template #default="{ row }"><span>{{ row.plan_type || '-' }}</span><el-tag v-if="row.plus_trial_eligible" size="small" type="success" class="trial-tag">可试用</el-tag></template>
          </el-table-column>
          <el-table-column label="账号测活" min-width="165" show-overflow-tooltip>
            <template #default="{ row }"><el-tag size="small" :type="liveStatusType(row.live_check_status)">{{ liveStatusLabel(row.live_check_status) }}</el-tag><small v-if="row.live_check_mode || row.live_check_ip">{{ row.live_check_mode === 'deep' ? '深度' : '快速' }} · {{ row.live_check_ip || '-' }}</small></template>
          </el-table-column>
          <el-table-column label="2FA" width="100" align="center">
            <template #default="{ row }"><el-button v-if="row.has_totp" link :icon="Key" @click="copyRow('totp', row)">已设置</el-button><el-button v-else-if="row.twofa_status === 'pending'" link type="warning" @click="retryTwofa(row)">重试</el-button><span v-else>-</span></template>
          </el-table-column>
          <el-table-column label="取件" width="62" align="center"><template #default="{ row }"><el-button link :icon="Link" aria-label="打开取件地址" @click="openUrl(row)" /></template></el-table-column>
          <el-table-column label="Token" width="80" align="center"><template #default="{ row }"><el-button v-if="row.has_access_token" link :icon="CopyDocument" aria-label="复制 Token" @click="copyRow('token', row)" /><span v-else>-</span></template></el-table-column>
          <el-table-column label="测活操作" width="118" align="center"><template #default="{ row }"><el-tooltip content="快速测活"><el-button link type="success" :icon="CircleCheck" :disabled="!canLiveCheck(row) || Boolean(liveBusy)" aria-label="快速测活" @click.stop="startLiveCheck('fast', [row])" /></el-tooltip><el-tooltip content="深度测活"><el-button link type="warning" :icon="RefreshRight" :disabled="!canLiveCheck(row) || Boolean(liveBusy)" aria-label="深度测活" @click.stop="startLiveCheck('deep', [row])" /></el-tooltip><el-tooltip content="查看测活日志"><el-button link :icon="View" :disabled="!row.live_check_task_id" aria-label="查看测活日志" @click.stop="openLiveLog(row)" /></el-tooltip></template></el-table-column>
          <el-table-column label="敏感字段" width="210" align="center"><template #default="{ row }"><el-button v-if="row.has_credential" link :icon="CopyDocument" @click="copyRow('credential', row)">完整凭据</el-button><el-button v-if="row.has_password" link :icon="Lock" @click="copyRow('password', row)">密码</el-button><el-button v-if="row.proxy_masked" link :icon="CopyDocument" @click="copyRow('proxy', row)">代理</el-button></template></el-table-column>
          <el-table-column label="错误" min-width="240" show-overflow-tooltip><template #default="{ row }">{{ row.live_check_failure?.public_message || row.error || row.twofa_error || '-' }}</template></el-table-column>
          <template #empty><ContentEmptyState /></template>
        </el-table>
        <el-pagination v-model:current-page="currentPage" v-model:page-size="pageSize" background layout="total, sizes, prev, pager, next" :page-sizes="[25, 50, 100]" :total="filteredRows.length" />
      </div>
    </WorkspacePanel>

    <el-dialog v-model="importOpen" title="导入 Free 邮箱池" width="680px" :close-on-click-modal="false">
      <el-form label-position="top">
        <el-form-item label="Free 邮箱池"><el-input v-model="mailboxText" type="textarea" :rows="7" placeholder="邮箱---取码 URL（也支持 ---- 或 |）" /></el-form-item>
      </el-form>
      <template #footer><el-button @click="importOpen = false">取消</el-button><el-button type="primary" :loading="loading" @click="importPools">导入</el-button></template>
    </el-dialog>
    <el-dialog v-model="logDialogOpen" :title="`${logRow?.email || 'Free 账号'} · ${logRow?.live_check_mode === 'deep' ? '深度测活' : '快速测活'}日志`" width="900px" destroy-on-close>
      <div class="log-dialog-meta"><span>任务 {{ logRow?.live_check_task_id || '-' }}</span><span>状态 {{ liveStatusLabel(logRow?.live_check_status) }}</span><span>测活 IP {{ logRow?.live_check_ip || '-' }}</span><el-button size="small" :icon="Refresh" :loading="logLoading" @click="logRow && openLiveLog(logRow)">刷新</el-button></div>
      <div ref="logScroll" v-loading="logLoading" class="log-dialog-list"><div v-for="(row, index) in liveLogs.slice(-180)" :key="`${row.time}-${index}-${row.message}`" :class="`log-${row.level || 'info'}`"><small>{{ row.time || '' }}</small><span><b v-if="row.stage_label || row.stage">{{ row.stage_label || row.stage }}</b> {{ row.message || '' }}<em v-if="row.duration_ms || row.page || row.http_status || row.outcome">{{ row.duration_ms ? ` · ${row.duration_ms}ms` : '' }}{{ row.page ? ` · ${row.page}` : '' }}{{ row.http_status ? ` · HTTP ${row.http_status}` : '' }}{{ row.outcome ? ` · ${row.outcome}` : '' }}</em></span></div><ContentEmptyState v-if="!liveLogs.length && !logLoading" /></div>
    </el-dialog>
  </div>
</template>

<style scoped>
.free-pool { width: 100%; height: 100%; min-height: 0; }
.pool-summary { color: var(--el-text-color-secondary); font-size: 12px; }
.table-region { display: grid; grid-template-rows: 28px 38px 36px minmax(0, 1fr) 46px; width: 100%; height: 100%; min-height: 0; padding: 8px 10px 0; }
.metrics { display: flex; align-items: center; gap: 14px; color: var(--el-text-color-secondary); font-size: 12px; }
.metrics b { color: var(--el-text-color-primary); font-variant-numeric: tabular-nums; }
.metrics .is-good b { color: #168363; }
.metrics .is-bad b { color: #c44754; }
.metrics .is-warn b { color: #bc761c; }
.filters { display: grid; grid-template-columns: repeat(4, minmax(180px, 1fr)); gap: 6px; }
.filters > .el-input, .filters > .el-select { width: 100%; }
.bulk-actions { display: flex; align-items: center; gap: 6px; min-width: 0; overflow-x: auto; color: var(--el-text-color-secondary); font-size: 12px; scrollbar-width: thin; }
.bulk-actions > span { margin-right: auto; white-space: nowrap; }
.bulk-actions :deep(.el-button + .el-button) { margin-left: 0; }
.trial-tag { margin-left: 5px; }
.table-region :deep(.el-pagination) { justify-content: flex-end; border-top: 1px solid var(--workspace-border); }
.table-region small { color: var(--el-text-color-secondary); }
.table-region small { display: block; overflow: hidden; margin-top: 2px; text-overflow: ellipsis; white-space: nowrap; }
.log-dialog-meta { display: flex; align-items: center; gap: 18px; margin-bottom: 8px; color: var(--el-text-color-secondary); font-size: 12px; }
.log-dialog-meta .el-button { margin-left: auto; }
.log-dialog-list { height: 520px; overflow: auto; padding: 9px 10px; border: 1px solid var(--workspace-border); border-radius: 4px; background: #101923; color: #dbe7f2; font: 12px/18px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; scrollbar-width: thin; scrollbar-color: #577b9d #101923; }
.log-dialog-list > div { display: grid; grid-template-columns: 160px minmax(0, 1fr); gap: 10px; padding: 2px 0; white-space: pre-wrap; word-break: break-word; }
.log-dialog-list small { color: #8ca0b5; }
.log-error { color: #e78690; }
.log-warn { color: #d7aa63; }
.log-success { color: #58c69b; }
.log-dialog-list em { display: block; color: #91a8bd; font-style: normal; font-size: 11px; }
</style>
