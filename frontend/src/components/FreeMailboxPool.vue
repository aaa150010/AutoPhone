<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { errorMessage } from '../utils/errorMessage'
import { ElMessage, ElMessageBox } from 'element-plus'
import { ArrowDown, CircleCheck, Collection, CopyDocument, Delete, Document, DocumentCopy, Download, Key, Link, Lock, MoreFilled, Plus, PriceTag, Refresh, RefreshLeft, RefreshRight, Tickets, Upload, VideoPlay, Warning } from '@element-plus/icons-vue'
import { deleteFreeMailboxes, exportFreeResults, formatFreeMailboxes, getFreeLiveCheckState, getFreeMailboxLatestCode, getFreeMailboxUrl, getFreeMailboxes, getFreeSecret, getFreeTotp, importFreeMailboxes, retryFreeTwofa, setFreeMailboxStatus, startFree, startFreeLiveCheck, startFreePlanCheck, transferFreeMailboxes } from '../api/client'
import type { FreeLiveCheckState, FreeMailboxRow, FreeState } from '../api/client'
import ContentEmptyState from './ContentEmptyState.vue'
import FreeTaskLogDialog from './FreeTaskLogDialog.vue'
import WorkspacePanel from './WorkspacePanel.vue'
import StateDot from './StateDot.vue'
import { ACCOUNT_BANNED_DISPLAY_MESSAGE, isRetryResolved } from '../utils/freeFailure'
import { useRowClipboard } from '../composables/useRowClipboard'
import { freeRowSecretLookup } from '../utils/freeSecretLookup'
import { safeMailboxUrl } from '../utils/safeMailboxUrl'
import {
  isHistoricalMailboxDriver,
  liveStatusLabel,
  liveStatusType,
  mailboxCreatedText,
  mailboxDriverLabel,
  mailboxFailureCause,
  mailboxFailureDetails,
  mailboxFailureNode,
  mailboxIsAccountBanned,
  mailboxPlanLabel,
  mailboxPlanTagType,
  mailboxRowClass,
  mailboxStageLabel,
  mailboxStageTooltip,
  mailboxStageType,
} from '../utils/freeLiveDisplay'
import { useColumnWidths } from '../composables/useColumnWidths'
import { usePolling } from '../composables/usePolling'
type DragColumn = { label?: string; noLabelText?: string }

const FAST_LIVE_CHECK_TIP = '用注册时保存的 Token，通过原绑定代理查询一次账号状态：正常 / Token 失效 / 已停用 / 被出口或安全策略拒绝。不重新登录、不收取邮件。'
const DEEP_LIVE_CHECK_TIP = '通过原绑定代理完整重新登录确认账号状态：可能收取一封邮箱 OTP 验证码，并按需校验密码 / 2FA。成功后刷新 Token 并同步套餐与 Plus 资格。'

const rows = ref<FreeMailboxRow[]>([])
const selected = ref<FreeMailboxRow[]>([])
const loading = ref(false)
const importOpen = ref(false)
const mailboxText = ref('')
const currentPage = ref(1)
const pageSize = ref(100)
const tableRef = ref<{ clearSelection: () => void } | null>(null)
const search = ref('')
const statusFilter = ref('')
const driverFilter = ref('')
const liveStatusFilter = ref('')
const liveBusy = ref<'fast' | 'deep' | ''>('')
const planBusy = ref('')
const { loadingIds: loadingEmail, copyForRow: copyEmailRow } = useRowClipboard()
const { copyForRow: copyLatestCodeRow } = useRowClipboard()
const loadingTotp = ref<string[]>([])
const joinCurrentBatch = ref(false)
const freeState = ref<FreeState>({ running: false, tasks: [], summary: {}, pool: {} })
const runBusy = ref(false)
const liveState = ref<FreeLiveCheckState>({ running: false, workers: 3, queue_limit: 500, active: 0, jobs: [] })
const logDialogOpen = ref(false)
const logRow = ref<FreeMailboxRow | null>(null)
const logDialog = ref<{ refresh: (options?: { forceLatest?: boolean; silent?: boolean }) => Promise<void> }>()
const { colWidth: poolColWidth, handleHeaderDragend: onPoolHeaderDragend } = useColumnWidths('gptphone.table.widths.free-mailbox-pool')

const filteredRows = computed(() => rows.value.filter(row => {
  const needle = search.value.trim().toLowerCase()
  const haystack = [
    row.email,
    row.live_check_failure?.node_label, row.live_check_failure?.node_code,
    row.failure?.node_label, row.failure?.node_code,
  ].join(' ').toLowerCase()
  return (!needle || haystack.includes(needle))
    && (!statusFilter.value || row.status === statusFilter.value)
    && (!driverFilter.value || row.driver === driverFilter.value)
    && (!liveStatusFilter.value || (liveStatusFilter.value === 'active' ? ['queued', 'running'].includes(String(row.live_check_status || '')) : row.live_check_status === liveStatusFilter.value))
}))
const pageRows = computed(() => filteredRows.value.slice((currentPage.value - 1) * pageSize.value, currentPage.value * pageSize.value))
const metrics = computed(() => {
  const count = (status: string) => rows.value.filter(row => row.status === status).length
  const live = (status: string) => rows.value.filter(row => row.live_check_status === status).length
  return { total: rows.value.length, available: count('available'), running: count('running'), success: count('success'), failed: count('failed'), pending: count('twofa_pending'), rerun: count('pending_rerun'), live: live('live'), deactivated: live('deactivated'), checking: live('queued') + live('running') }
})


function handleBulkCommand(command: string) {
  if (command === 'copy-mailbox') return void copyMailboxFormat('mailbox')
  if (command === 'copy-full') return void copyMailboxFormat('full')
  if (command === 'copy-token') return void copySecret('token')
  if (command === 'copy-credential') return void copySecret('credential')
  if (command === 'copy-page-token') return void copySecret('token', pageRows.value)
  if (command === 'mark-available') return void setStatus('available')
  if (command === 'mark-unavailable') return void setStatus('unavailable')
}
function openImport() {
  mailboxText.value = ''
  importOpen.value = true
}
defineExpose({ openImport })

async function refresh() {
  loading.value = true
  try {
    const result = await getFreeMailboxes()
    rows.value = result.rows || []
    freeState.value = result.state || freeState.value
  } catch (error) {
    ElMessage.error(errorMessage(error) || 'Free 邮箱池刷新失败')
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
      await logDialog.value?.refresh({ silent: true })
    }
  } catch (error) {
    if (liveState.value.running) ElMessage.error(errorMessage(error) || 'Free 测活状态刷新失败')
  }
}

function canLiveCheck(row: FreeMailboxRow) {
  return Boolean(row.has_access_token && row.proxy_masked)
    && !['queued', 'running'].includes(String(row.live_check_status || ''))
}

async function startLiveCheck(mode: 'fast' | 'deep', selection = selected.value) {
  const eligible = selection.filter(canLiveCheck)
  if (!eligible.length) {
    ElMessage.warning('请选择已保存 Token 和代理的 Free 账号')
    return
  }
  if (mode === 'deep') {
    try {
      await ElMessageBox.confirm(
        `深度测活会使用注册时的代理重新登录 ${eligible.length} 个账号，并可能多收一封 OTP 邮件。确定继续吗？`,
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
  } catch (error) {
    ElMessage.error(errorMessage(error) || `${mode === 'fast' ? '快速' : '深度'}测活启动失败`)
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
  } catch (error) {
    ElMessage.error(errorMessage(error) || 'Free 注册启动失败')
  } finally {
    runBusy.value = false
  }
}

async function openLiveLog(row: FreeMailboxRow) {
  if (!row.live_check_task_id) {
    unavailableMailboxAction('该邮箱暂无测活日志')
    return
  }
  logRow.value = row
  logDialogOpen.value = true
}

async function startLiveCheckAction(mode: 'fast' | 'deep', row: FreeMailboxRow) {
  if (!canLiveCheck(row)) {
    unavailableMailboxAction('该邮箱需要已保存 Token 和代理，且当前不在测活中')
    return
  }
  await startLiveCheck(mode, [row])
}

async function copyEmail(row: FreeMailboxRow) {
  const rowId = String(row.row_id || '').trim()
  await copyEmailRow({
    rowId,
    // Public mailbox rows intentionally expose only a masked address. Resolve
    // the raw address through the existing on-demand secret boundary.
    produce: async () => {
      const value = String((await getFreeSecret('email', freeRowSecretLookup(row.row_id))).value || '')
      if (!value || !navigator.clipboard?.writeText) throw new Error('当前环境不支持复制')
      return value
    },
    successMessage: '已复制邮箱',
    errorMessage: '邮箱复制失败',
  })
}

const polling = usePolling(refreshLiveState, () => (liveState.value.running || logDialogOpen.value ? 1200 : 5000))
const scheduleRefresh = polling.schedule

async function importPools() {
  if (!mailboxText.value.trim()) {
    ElMessage.warning('请填写 Free 邮箱池')
    return
  }
  loading.value = true
  try {
    const messages: string[] = []
    const result = await importFreeMailboxes(mailboxText.value, joinCurrentBatch.value)
    messages.push(`新增 ${Number(result.imported || 0)} 条`)
    if (Number(result.active_batch_joined || 0)) messages.push(`已加入当前批次 ${Number(result.active_batch_joined)} 条`)
    else if (Number(result.next_batch || 0)) messages.push(`下一批优先 ${Number(result.next_batch)} 条`)
    if (Number(result.skipped || 0)) messages.push(`跳过重复 ${Number(result.skipped || 0)} 条`)
    importOpen.value = false
    joinCurrentBatch.value = false
    selected.value = []
    tableRef.value?.clearSelection()
    await refresh()
    ElMessage.success(`Free 池导入完成：${messages.join('，')}`)
  } catch (error) {
    ElMessage.error(errorMessage(error) || 'Free 池导入失败')
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
  } catch (error) {
    ElMessage.error(errorMessage(error) || 'Free 邮箱删除失败')
  } finally {
    loading.value = false
  }
}

async function copySecret(kind: 'token' | 'password' | 'totp' | 'credential', selection = selected.value) {
  const eligible = selection.filter(row => kind === 'token' ? row.has_access_token : kind === 'password' ? row.has_password : kind === 'totp' ? row.has_totp : row.has_credential)
  if (!eligible.length) {
    ElMessage.warning('当前没有可复制的 Free 记录')
    return
  }
  try {
    const value = (await getFreeSecret(kind, { row_ids: eligible.map(row => row.row_id) })).value
    await navigator.clipboard.writeText(value || '')
    ElMessage.success(`已复制 ${eligible.length} 条${kind === 'token' ? ' Token' : kind === 'password' ? '密码' : kind === 'totp' ? '2FA 密钥' : '完整凭据'}`)
  } catch (error) {
    ElMessage.error(errorMessage(error) || 'Free 敏感字段复制失败')
  }
}

async function copyMailboxFormat(mode: 'mailbox' | 'full') {
  const rowIds = selected.value.map(row => row.row_id).filter(Boolean)
  if (!rowIds.length) {
    ElMessage.warning('请先选择 Free 邮箱')
    return
  }
  try {
    await ElMessageBox.confirm(
      mode === 'full'
        ? '完整格式可能包含 OpenAI 账号密码、取件 URL 和用于自动生成验证码的 2FA Secret，仅应复制到可信位置。'
        : '接码格式包含取件 URL 和用于自动生成验证码的 2FA Secret，仅应复制到可信位置。',
      mode === 'full' ? '复制完整格式' : '复制接码格式',
      { type: 'warning', confirmButtonText: '复制', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  try {
    const result = await formatFreeMailboxes(mode, rowIds)
    if (result.content) await navigator.clipboard.writeText(result.content)
    const skipped = Number(result.skipped || 0)
    const noPassword = mode === 'full'
      ? selected.value.filter(row => !row.has_password && row.has_access_token).length
      : 0
    const details = [
      `已复制 ${Number(result.prepared || 0)} 条`,
      skipped ? `跳过 ${skipped} 条` : '',
      noPassword ? `${noPassword} 条为 passwordless（未填假密码）` : '',
    ].filter(Boolean).join('，')
    const skippedDetails = (result.skipped_items || [])
      .slice(0, 3)
      .map(item => `${item.email || '选中行'}：${item.reason}`)
      .join('；')
    const suffix = skippedDetails ? `；${skippedDetails}${skipped > 3 ? '；其余跳过项未展开' : ''}` : ''
    if (skipped) ElMessage.warning(`${details}${suffix}`)
    else ElMessage.success(details)
  } catch (error) {
    ElMessage.error(errorMessage(error) || 'Free 格式复制失败')
  }
}

async function transferSelected() {
  const rowIds = selected.value.map(row => row.row_id).filter(Boolean)
  if (!rowIds.length) {
    ElMessage.warning('请先选择 Free 邮箱')
    return
  }
  try {
    await ElMessageBox.confirm(
      `将选中的 ${rowIds.length} 条 Free 邮箱复制到普通接码邮箱管理，Free 源记录会保留。继续吗？`,
      '传输至接码邮箱',
      { type: 'warning', confirmButtonText: '开始传输', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  loading.value = true
  try {
    const result = await transferFreeMailboxes(rowIds)
    const skipped = Number(result.skipped || 0)
    selected.value = []
    tableRef.value?.clearSelection()
    const summary = `已传输 ${Number(result.imported || 0)} 条${skipped ? `，跳过 ${skipped} 条` : ''}`
    const skippedDetails = (result.skipped_items || [])
      .slice(0, 3)
      .map(item => `${item.email || '选中行'}：${item.reason}`)
      .join('；')
    if (skipped) ElMessage.warning(`${summary}${skippedDetails ? `；${skippedDetails}${skipped > 3 ? '；其余跳过项未展开' : ''}` : ''}`)
    else ElMessage.success(summary)
  } catch (error) {
    ElMessage.error(errorMessage(error) || 'Free 邮箱传输失败')
  } finally {
    loading.value = false
  }
}

async function copyRow(kind: 'token' | 'password' | 'totp' | 'credential', row: FreeMailboxRow) {
  if (kind === 'totp') {
    if (!row.row_id || loadingTotp.value.includes(row.row_id)) return
    loadingTotp.value = [...loadingTotp.value, row.row_id]
    try {
      const result = await getFreeTotp({ row_id: row.row_id })
      await navigator.clipboard.writeText(String(result.code || ''))
      ElMessage.success(`已复制临时 2FA 验证码，约 ${Number(result.remaining || 0)} 秒后刷新`)
    } catch (error) {
      ElMessage.error(errorMessage(error) || '复制临时 2FA 验证码失败')
    } finally {
      loadingTotp.value = loadingTotp.value.filter(id => id !== row.row_id)
    }
    return
  }
  await copySecret(kind, [row])
}

function unavailableMailboxAction(message: string) {
  ElMessage.info(message)
}

async function copyMailboxToken(row: FreeMailboxRow) {
  if (!row.has_access_token) return unavailableMailboxAction('该邮箱暂无可复制的账号 Token')
  await copyRow('token', row)
}

async function copyMailboxCredential(row: FreeMailboxRow) {
  if (!row.has_credential) return unavailableMailboxAction('该邮箱暂无可复制的完整凭据')
  await copyRow('credential', row)
}

async function copyMailboxPassword(row: FreeMailboxRow) {
  if (!row.has_password) return unavailableMailboxAction('该邮箱暂无可复制的密码')
  await copyRow('password', row)
}

async function copyMailboxTotp(row: FreeMailboxRow) {
  if (!row.has_totp) return unavailableMailboxAction('该邮箱暂无可复制的 2FA 验证码')
  await copyRow('totp', row)
}

async function copyLatestCode(row: FreeMailboxRow) {
  const rowId = String(row.row_id || '')
  if (!rowId) {
    unavailableMailboxAction('该邮箱暂无可用行标识')
    return
  }
  if (!row.has_mailbox_url) {
    unavailableMailboxAction('该邮箱暂无取件 URL，无法提取验证码')
    return
  }
  await copyLatestCodeRow({
    rowId,
    produce: async () => String((await getFreeMailboxLatestCode(rowId)).code || ''),
    successMessage: '验证码已复制',
    errorMessage: '提取 Free 邮箱验证码失败',
    emptyMessage: '未找到新的 OpenAI 邮箱验证码',
  })
}

async function retryTwofa(row: FreeMailboxRow) {
  if (isHistoricalMailboxDriver(row) || row.twofa_status !== 'pending' || !row.row_id) return
  try {
    await retryFreeTwofa(row.row_id)
    ElMessage.info('已重新加入 2FA 设置任务')
    await refresh()
  } catch (error) {
    ElMessage.error(errorMessage(error) || '2FA 重试失败')
  }
}

async function retryMailboxTwofa(row: FreeMailboxRow) {
  if (isHistoricalMailboxDriver(row)) return unavailableMailboxAction('历史链路邮箱不支持 2FA 重试')
  if (row.twofa_status !== 'pending') return unavailableMailboxAction('该邮箱当前没有待重试的 2FA 节点')
  await retryTwofa(row)
}

async function retryPlan(row: FreeMailboxRow) {
  if (isHistoricalMailboxDriver(row) || !row.row_id || !row.has_access_token || String(row.plan_check_status || '').toLowerCase() !== 'failed' || planBusy.value) return
  planBusy.value = row.row_id
  try {
    await startFreePlanCheck([row.row_id])
    ElMessage.info('套餐查询已加入队列')
    await refresh()
  } catch (error) {
    ElMessage.error(errorMessage(error) || '重新查询套餐失败')
  } finally {
    planBusy.value = ''
  }
}

async function retryMailboxPlan(row: FreeMailboxRow) {
  if (isHistoricalMailboxDriver(row)) return unavailableMailboxAction('历史链路邮箱不支持套餐重查')
  if (!row.has_access_token) return unavailableMailboxAction('该邮箱暂无账号 Token，无法查询套餐')
  if (String(row.plan_check_status || '').toLowerCase() !== 'failed') return unavailableMailboxAction('该邮箱当前没有失败的套餐查询')
  await retryPlan(row)
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
  } catch (error) {
    ElMessage.error(errorMessage(error) || 'Free 邮箱状态更新失败')
  } finally { loading.value = false }
}

async function openUrl(row: FreeMailboxRow) {
  if (!row.row_id) {
    unavailableMailboxAction('该邮箱暂无可用行标识')
    return
  }
  if (!row.has_mailbox_url) {
    unavailableMailboxAction('该邮箱暂无取件 URL')
    return
  }
  try {
    const destination = safeMailboxUrl((await getFreeMailboxUrl(row.row_id)).mailbox_url)
    if (!destination) throw new Error('取件 URL 无效或协议不安全')
    const target = window.open(destination, '_blank', 'noopener,noreferrer')
    if (!target) throw new Error('浏览器阻止了新窗口，请允许弹出窗口后重试')
  } catch (error) { ElMessage.error(errorMessage(error) || '打开 Free 取件地址失败') }
}

async function handleMailboxAction(command: string, row: FreeMailboxRow) {
  if (command === 'open_url') return openUrl(row)
  if (command === 'latest_code') return copyLatestCode(row)
  if (command === 'token') return copyMailboxToken(row)
  if (command === 'fast_live') return startLiveCheckAction('fast', row)
  if (command === 'deep_live') return startLiveCheckAction('deep', row)
  if (command === 'live_log') return openLiveLog(row)
  if (command === 'credential') return copyMailboxCredential(row)
  if (command === 'password') return copyMailboxPassword(row)
  if (command === 'totp') return copyMailboxTotp(row)
  if (command === 'twofa') return retryMailboxTwofa(row)
  if (command === 'plan') return retryMailboxPlan(row)
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
  } catch (error) { ElMessage.error(errorMessage(error) || 'Free 结果导出失败') }
}

onMounted(async () => {
  await refresh()
  await refreshLiveState()
  scheduleRefresh()
})
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
        <div class="metrics"><span>总数 <b>{{ metrics.total }}</b></span><span class="is-good">注册成功 <b>{{ metrics.success }}</b></span><span>测活中 <b>{{ metrics.checking }}</b></span><span class="is-good">账号正常 <b>{{ metrics.live }}</b></span><span class="is-bad">已停用 <b>{{ metrics.deactivated }}</b></span><span class="is-warn">待重跑 <b>{{ metrics.rerun }}</b></span><span class="is-warn">2FA 待重试 <b>{{ metrics.pending }}</b></span></div>
        <div class="filters"><el-input v-model="search" size="small" clearable placeholder="搜索邮箱或错误节点" /><el-select v-model="statusFilter" size="small" clearable placeholder="注册状态"><el-option label="可用" value="available" /><el-option label="运行中" value="running" /><el-option label="成功" value="success" /><el-option label="失败" value="failed" /><el-option label="待重跑" value="pending_rerun" /><el-option label="2FA 待重试" value="twofa_pending" /></el-select><el-select v-model="driverFilter" size="small" clearable placeholder="注册链路"><el-option label="全协议" value="protocol" /><el-option label="Camoufox" value="camoufox" /></el-select><el-select v-model="liveStatusFilter" size="small" clearable placeholder="测活状态"><el-option label="排队 / 测活中" value="active" /><el-option label="正常" value="live" /><el-option label="已停用" value="deactivated" /><el-option label="Token 失效" value="token_expired" /><el-option label="出口/反爬拒绝" value="free_live_proxy_blocked" /><el-option label="Session 被拒绝" value="free_live_session_rejected" /><el-option label="触发限流" value="free_live_rate_limited" /><el-option label="上游异常" value="free_live_upstream_error" /><el-option label="网络异常" value="free_live_network_error" /><el-option label="需要真实密码" value="free_live_password_required" /><el-option label="测活失败" value="failed" /></el-select></div>
        <div class="bulk-actions">
          <span>已选 {{ selected.length }} 条</span>
          <el-tooltip placement="top" :show-after="250"><template #content><div class="live-check-tip">{{ FAST_LIVE_CHECK_TIP }}</div></template><el-button size="small" type="success" plain :icon="CircleCheck" :loading="liveBusy === 'fast'" :disabled="!selected.some(canLiveCheck) || Boolean(liveBusy)" @click="startLiveCheck('fast')">快速测活</el-button></el-tooltip>
          <el-tooltip placement="top" :show-after="250"><template #content><div class="live-check-tip">{{ DEEP_LIVE_CHECK_TIP }}</div></template><el-button size="small" type="warning" plain :icon="RefreshRight" :loading="liveBusy === 'deep'" :disabled="!selected.some(canLiveCheck) || Boolean(liveBusy)" @click="startLiveCheck('deep')">深度测活</el-button></el-tooltip>
          <el-button size="small" :icon="Upload" :disabled="!selected.length || loading" @click="transferSelected">传输至接码邮箱</el-button>
          <el-button size="small" :icon="Download" :disabled="loading" @click="exportResults">导出</el-button>
          <el-button size="small" type="danger" plain :icon="Delete" :disabled="!selected.length || loading" @click="deleteSelected">删除选中</el-button>
          <el-dropdown trigger="click" @command="(command: string) => handleBulkCommand(command)">
            <el-button size="small" :icon="CopyDocument" aria-label="更多批量操作">更多操作<el-icon class="el-icon--right"><ArrowDown /></el-icon></el-button>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="copy-mailbox"><el-icon><CopyDocument /></el-icon>复制接码格式</el-dropdown-item>
                <el-dropdown-item command="copy-full"><el-icon><CopyDocument /></el-icon>复制完整格式</el-dropdown-item>
                <el-dropdown-item command="copy-token"><el-icon><Key /></el-icon>复制 Token</el-dropdown-item>
                <el-dropdown-item command="copy-credential"><el-icon><DocumentCopy /></el-icon>复制凭据</el-dropdown-item>
                <el-dropdown-item command="copy-page-token"><el-icon><CopyDocument /></el-icon>当前页 Token</el-dropdown-item>
                <el-dropdown-item command="mark-available" divided><el-icon><CircleCheck /></el-icon>恢复为可用</el-dropdown-item>
                <el-dropdown-item command="mark-unavailable"><el-icon><Warning /></el-icon>标记不可用</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
        <el-table
          ref="tableRef"
          :data="pageRows"
          row-key="row_id"
          stripe
          height="100%"
          border
          :row-class-name="mailboxRowClass"
          @header-dragend="(newWidth: number, oldWidth: number, column: DragColumn) => onPoolHeaderDragend(newWidth, oldWidth, column)"
          @selection-change="selected = $event" size="small">
          <el-table-column type="selection" width="42" reserve-selection />
          <el-table-column label="邮箱" :min-width="poolColWidth('邮箱', 280)" show-overflow-tooltip>
            <template #default="{ row }">
              <div class="mailbox-account-cell">
                <el-tooltip :content="`点击复制邮箱${row.email ? `：${row.email}` : ''}`" placement="top" :show-after="250"><el-button link class="email-copy" :loading="loadingEmail.includes(row.row_id)" @click.stop="copyEmail(row)"><span>{{ row.email }}</span><el-icon v-if="!loadingEmail.includes(row.row_id)"><CopyDocument /></el-icon></el-button></el-tooltip>
                <span class="mailbox-subline">{{ mailboxDriverLabel(row) }}<template v-if="mailboxCreatedText(row)"> · {{ mailboxCreatedText(row) }}</template></span>
              </div>
            </template>
          </el-table-column>
          <el-table-column label="阶段" :min-width="poolColWidth('阶段', 150)" show-overflow-tooltip><template #default="{ row }"><el-tooltip :content="mailboxStageTooltip(row)" placement="top" :show-after="250"><span class="mailbox-stage-cell"><el-tag size="small" effect="light" :type="mailboxStageType(row)">{{ mailboxStageLabel(row) }}</el-tag></span></el-tooltip></template></el-table-column>
          <el-table-column label="套餐" :width="poolColWidth('套餐', 96)" align="center" show-overflow-tooltip>
            <template #default="{ row }"><div class="mailbox-plan-cell"><el-tag size="small" :type="mailboxPlanTagType(row)" effect="plain">{{ mailboxPlanLabel(row) }}</el-tag><el-tag v-if="row.plus_trial_eligible && String(row.subscription_plan || row.plan_type || '').toLowerCase() !== 'free'" size="small" type="success" effect="plain" class="trial-tag">Plus 试用</el-tag></div></template>
          </el-table-column>
          <el-table-column label="账号测活" :min-width="poolColWidth('账号测活', 150)" show-overflow-tooltip>
            <template #default="{ row }"><div class="mailbox-live-cell"><el-tag size="small" :type="liveStatusType(row.live_check_status)">{{ liveStatusLabel(row.live_check_status) }}</el-tag><small v-if="row.live_check_mode">{{ row.live_check_mode === 'deep' ? '深度' : '快速' }}</small></div></template>
          </el-table-column>
          <el-table-column label="2FA" :width="poolColWidth('2FA', 110)">
            <template #default="{ row }"><StateDot v-if="row.has_totp" tone="success" label="已启用" /><StateDot v-else-if="row.twofa_status === 'pending'" tone="warning" label="待重试" /><StateDot v-else tone="info" label="未启用" /></template>
          </el-table-column>
          <el-table-column label="错误" :min-width="poolColWidth('错误', 320)">
            <template #default="{ row }">
              <el-tooltip placement="top" :disabled="!mailboxFailureDetails(row).length" :show-after="250">
                <template #content><div class="failure-tooltip"><span v-for="item in mailboxFailureDetails(row)" :key="item">{{ item }}</span></div></template>
                <div class="failure-cell"><span class="failure-summary"><template v-if="isRetryResolved(row.retry_resolved)"><strong class="resolved-text">已由重试解决</strong></template><template v-else-if="mailboxIsAccountBanned(row)"><strong>{{ ACCOUNT_BANNED_DISPLAY_MESSAGE }}</strong></template><template v-else><strong v-if="mailboxFailureNode(row).label || mailboxFailureNode(row).code">{{ mailboxFailureNode(row).label || mailboxFailureNode(row).code }}<code v-if="mailboxFailureNode(row).showCode">{{ mailboxFailureNode(row).code }}</code></strong><span>{{ mailboxFailureCause(row) }}</span></template></span></div>
              </el-tooltip>
            </template>
          </el-table-column>
          <el-table-column label="操作" :width="poolColWidth('操作', 64)" fixed="right" align="center">
            <template #default="{ row }">
              <el-dropdown trigger="click" @command="(command: string) => handleMailboxAction(command, row)">
                <el-button link class="row-action-button" aria-label="打开邮箱操作菜单" title="打开邮箱操作菜单"><el-icon><MoreFilled /></el-icon></el-button>
                <template #dropdown>
                  <el-dropdown-menu>
                    <el-dropdown-item command="open_url"><el-icon><Link /></el-icon>打开取件地址</el-dropdown-item>
                    <el-dropdown-item command="latest_code"><el-icon><Tickets /></el-icon>提取并复制最新验证码</el-dropdown-item>
                    <el-dropdown-item command="token"><el-icon><Key /></el-icon>复制 Token</el-dropdown-item>
                    <el-dropdown-item command="fast_live" :title="FAST_LIVE_CHECK_TIP"><el-icon><CircleCheck /></el-icon>快速测活</el-dropdown-item>
                    <el-dropdown-item command="deep_live" :title="DEEP_LIVE_CHECK_TIP"><el-icon><RefreshRight /></el-icon>深度测活</el-dropdown-item>
                    <el-dropdown-item command="live_log"><el-icon><Document /></el-icon>查看测活日志</el-dropdown-item>
                    <el-dropdown-item command="credential"><el-icon><DocumentCopy /></el-icon>复制完整凭据</el-dropdown-item>
                    <el-dropdown-item command="password"><el-icon><Lock /></el-icon>复制密码</el-dropdown-item>
                    <el-dropdown-item command="totp"><el-icon><Collection /></el-icon>复制临时 2FA 验证码</el-dropdown-item>
                    <el-dropdown-item command="twofa"><el-icon><RefreshLeft /></el-icon>重试 2FA</el-dropdown-item>
                    <el-dropdown-item command="plan"><el-icon><PriceTag /></el-icon>重新查询套餐</el-dropdown-item>
                  </el-dropdown-menu>
                </template>
              </el-dropdown>
            </template>
          </el-table-column>
          <template #empty><ContentEmptyState /></template>
        </el-table>
        <el-pagination v-model:current-page="currentPage" v-model:page-size="pageSize" background layout="total, sizes, prev, pager, next" :page-sizes="[25, 50, 100]" :total="filteredRows.length" />
      </div>
    </WorkspacePanel>

    <el-dialog v-model="importOpen" title="导入 Free 邮箱池" width="680px" :close-on-click-modal="false">
      <el-form label-position="top">
        <el-form-item label="Free 邮箱池"><el-input v-model="mailboxText" type="textarea" :rows="7" placeholder="邮箱---取码 URL（也支持 ---- 或 |）" /></el-form-item>
        <el-form-item v-if="freeState.running"><el-checkbox v-model="joinCurrentBatch">加入当前运行批次（会增加队列目标）</el-checkbox></el-form-item>
      </el-form>
      <template #footer><el-button @click="importOpen = false">取消</el-button><el-button type="primary" :loading="loading" @click="importPools">导入</el-button></template>
    </el-dialog>
    <FreeTaskLogDialog ref="logDialog" v-model="logDialogOpen" :task="logRow ? { task_id: logRow.live_check_task_id, email: logRow.email, stage: liveStatusLabel(logRow.live_check_status) } : undefined" />
  </div>
</template>

<style scoped>
.free-pool { width: 100%; height: 100%; min-height: 0; }
.pool-summary { color: var(--el-text-color-secondary); font-size: 12px; }
.table-region { display: grid; grid-template-rows: auto auto auto minmax(0, 1fr) 46px; gap: var(--workspace-gap); width: 100%; height: 100%; min-height: 0; padding: 10px; }
.metrics { display: flex; align-items: center; gap: 14px; min-height: 28px; color: var(--el-text-color-secondary); font-size: 12px; }
.metrics b { color: var(--el-text-color-primary); font-variant-numeric: tabular-nums; }
.metrics .is-good b { color: var(--el-color-success); }
.metrics .is-bad b { color: var(--el-color-danger); }
.metrics .is-warn b { color: var(--el-color-warning); }
.filters { display: grid; grid-template-columns: repeat(4, minmax(160px, 1fr)); gap: var(--workspace-gap); }
.filters > .el-input, .filters > .el-select { width: 100%; }
.bulk-actions { display: flex; align-items: center; gap: var(--workspace-gap); min-width: 0; color: var(--el-text-color-secondary); font-size: 12px; flex-wrap: wrap; }
.bulk-actions > span { margin-right: auto; white-space: nowrap; }
.bulk-actions :deep(.el-button + .el-button) { margin-left: 0; }
.trial-tag { margin-left: 5px; }
.mailbox-account-cell { display: flex; flex-direction: column; gap: 1px; min-width: 0; }
.mailbox-subline { display: block; overflow: hidden; color: var(--el-text-color-secondary); font-size: 11px; line-height: 15px; text-overflow: ellipsis; white-space: nowrap; }
.email-copy { display: inline-flex; max-width: 100%; min-width: 0; gap: 5px; height: auto; padding: 0; color: var(--el-text-color-primary); justify-content: flex-start; }
.email-copy span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.email-copy .el-icon { flex: 0 0 auto; color: var(--el-color-primary); }
.mailbox-plan-cell, .mailbox-live-cell { display: flex; align-items: center; min-width: 0; gap: 5px; overflow: hidden; white-space: nowrap; }
.mailbox-plan-cell > .el-tag, .mailbox-live-cell > .el-tag { flex: 0 0 auto; }
.mailbox-stage-cell { display: inline-flex; max-width: 100%; min-width: 0; overflow: hidden; vertical-align: middle; }
.mailbox-stage-cell :deep(.el-tag) { max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.mailbox-live-cell small { display: inline; flex: 0 0 auto; margin-top: 0; color: var(--el-text-color-secondary); white-space: nowrap; }
.table-region :deep(.el-pagination) { justify-content: flex-end; border-top: 1px solid var(--workspace-border); }
.table-region small { color: var(--el-text-color-secondary); display: block; overflow: hidden; margin-top: 2px; text-overflow: ellipsis; white-space: nowrap; }
.failure-cell { min-width: 0; max-width: 100%; overflow: hidden; line-height: 16px; }
.failure-summary { display: block; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.failure-summary strong, .failure-summary span { white-space: nowrap; }
.failure-cell strong { color: var(--el-color-danger); font-size: 12px; font-weight: 650; }
.failure-cell code { margin-left: 5px; color: var(--el-text-color-secondary); font-size: 10px; }
.failure-cell span { color: var(--el-text-color-regular); font-size: 11px; }
.failure-tooltip { display: grid; max-width: 520px; gap: 4px; line-height: 18px; }
.live-check-tip { max-width: 300px; line-height: 18px; white-space: normal; }
</style>
