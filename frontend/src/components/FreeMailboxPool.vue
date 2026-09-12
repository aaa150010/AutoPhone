<script setup lang="ts">
import { freeMailboxRowsFingerprint } from '../utils/fingerprint'
import { computed, onMounted, ref } from 'vue'
import { errorMessage } from '../utils/errorMessage'
import { ElMessage, ElMessageBox } from 'element-plus'
import { ArrowDown, CircleCheck, Collection, CopyDocument, Delete, Document, DocumentCopy, Download, Key, Link, Lock, MoreFilled, Plus, PriceTag, Refresh, RefreshLeft, RefreshRight, Tickets, Upload, VideoPlay, Warning } from '@element-plus/icons-vue'
import { deleteFreeMailboxes, exportFreeResults, formatFreeMailboxes, getFreeLiveCheckState, getFreeMailboxLatestCode, getFreeMailboxUrl, getFreeMailboxes, getFreePlanCheckState, getFreeSecret, getFreeTotp, importFreeMailboxes, retryFreePassword, retryFreeTwofa, setFreeMailboxStatus, startFree, startFreeLiveCheck, startFreePlanCheck, transferFreeMailboxes } from '../api/client'
import type { FreeLiveCheckState, FreeMailboxRow, FreePlanCheckState, FreeState } from '../api/client'
import ContentEmptyState from './ContentEmptyState.vue'
import FreeTaskLogDialog from './FreeTaskLogDialog.vue'
import WorkspacePanel from './WorkspacePanel.vue'
import StateDot from './StateDot.vue'
import { ACCOUNT_BANNED_DISPLAY_MESSAGE, isRetryResolved } from '../utils/freeFailure'
import { useRowClipboard } from '../composables/useRowClipboard'
import { freeRowSecretLookup } from '../utils/freeSecretLookup'
import { safeMailboxUrl } from '../utils/safeMailboxUrl'
import { browserDownload } from '../utils/browserDownload'
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
  mailboxPasswordLabel,
  mailboxPasswordType,
  mailboxPlanLabel,
  mailboxPlanTagType,
  mailboxRowClass,
  mailboxStageLabel,
  mailboxStageTooltip,
  mailboxStageType,
  mailboxTwofaLabel,
  mailboxTwofaType,
  mailboxRegisteredLabel,
  mailboxRegisteredType,
} from '../utils/freeLiveDisplay'
import { useColumnWidths, type DragColumn } from '../composables/useColumnWidths'
import { usePolling } from '../composables/usePolling'

const FAST_LIVE_CHECK_TIP = '用注册时保存的 Token，通过代理池分配的代理查询一次账号状态：正常 / Token 失效 / 已停用 / 被出口或安全策略拒绝。不重新登录、不收取邮件。'
const DEEP_LIVE_CHECK_TIP = '通过代理池分配的代理完整重新登录确认账号状态：可能收取一封邮箱 OTP 验证码，并按需校验密码 / 2FA。成功后刷新 Token 并同步套餐与 Plus 资格；确认封禁的账号会自动移出邮箱池。'
const PLAN_RECHECK_TIP = '按账号各自链路重查 Plus 套餐：Token 有效直接查询；失效或缺失时全协议账号走协议重新登录，Camoufox 账号打开浏览器重新登录（可能收取一封邮箱验证码）。确认停用的账号会自动移出邮箱池。'

const rows = ref<FreeMailboxRow[]>([])
const selected = ref<FreeMailboxRow[]>([])
const loading = ref(false)
const importOpen = ref(false)
const mailboxText = ref('')
const currentPage = ref(1)
const pageSize = ref(50)
const tableRef = ref<{ clearSelection: () => void } | null>(null)
const search = ref('')
const statusFilter = ref('')
const driverFilter = ref('')
const liveStatusFilter = ref('')
const liveBusy = ref<'fast' | 'deep' | ''>('')
const planBusy = ref('')
const passwordBusy = ref('')
const { loadingIds: loadingEmail, copyForRow: copyEmailRow } = useRowClipboard()
const { copyForRow: copyLatestCodeRow } = useRowClipboard()
const loadingTotp = ref<string[]>([])
const joinCurrentBatch = ref(false)
const freeState = ref<FreeState>({ running: false, tasks: [], summary: {}, pool: {} })
const runBusy = ref(false)
const liveState = ref<FreeLiveCheckState>({ running: false, workers: 3, queue_limit: 500, active: 0, jobs: [] })
const planState = ref<FreePlanCheckState>({ running: false, workers: 2, queue_limit: 500, active: 0, jobs: [] })
const planBatchBusy = ref(false)
const rowsFingerprint = ref('')
const logDialogOpen = ref(false)
const logRow = ref<FreeMailboxRow | null>(null)
const logDialog = ref<{ refresh: (options?: { forceLatest?: boolean; silent?: boolean }) => Promise<void> }>()
const { colWidth: poolColWidth, handleHeaderDragend: onPoolHeaderDragend, resetWidths: resetPoolWidths } = useColumnWidths('gptphone.table.widths.free-mailbox-pool', { autoResetOnce: true })

const filteredRows = computed(() => {
  const needle = search.value.trim().toLowerCase()
  return rows.value.filter(row => {
    const haystack = [
      row.email,
      row.live_check_failure?.node_label, row.live_check_failure?.node_code,
      row.failure?.node_label, row.failure?.node_code,
    ].join(' ').toLowerCase()
    return (!needle || haystack.includes(needle))
      && (!statusFilter.value || row.status === statusFilter.value)
      && (!driverFilter.value || row.driver === driverFilter.value)
      && (!liveStatusFilter.value || (liveStatusFilter.value === 'active' ? ['queued', 'running'].includes(String(row.live_check_status || '')) : row.live_check_status === liveStatusFilter.value))
  })
})
const pageRows = computed(() => filteredRows.value.slice((currentPage.value - 1) * pageSize.value, currentPage.value * pageSize.value))
const metrics = computed(() => {
  // One pass instead of eleven filters per poll tick.
  const statuses: Record<string, number> = {}
  const liveStatuses: Record<string, number> = {}
  for (const row of rows.value) {
    statuses[row.status] = (statuses[row.status] || 0) + 1
    const liveStatus = row.live_check_status || ''
    if (liveStatus) liveStatuses[liveStatus] = (liveStatuses[liveStatus] || 0) + 1
  }
  const count = (status: string) => statuses[status] || 0
  const live = (status: string) => liveStatuses[status] || 0
  return { total: rows.value.length, available: count('available'), running: count('running'), success: count('success'), failed: count('failed'), pending: count('twofa_pending'), rerun: count('pending_rerun'), live: live('live'), deactivated: live('deactivated'), checking: live('queued') + live('running') }
})

const tokenExpiredRows = computed(() => rows.value.filter(row => row.live_check_status === 'token_expired'))
const activePoolTab = computed(() => {
  if (!statusFilter.value && !liveStatusFilter.value) return 'all'
  if (statusFilter.value && liveStatusFilter.value) return ''
  if (!liveStatusFilter.value) {
    if (statusFilter.value === 'success') return 'success'
    if (statusFilter.value === 'pending_rerun') return 'pending_rerun'
    if (statusFilter.value === 'twofa_pending') return 'twofa_pending'
    return ''
  }
  if (liveStatusFilter.value === 'active') return 'checking'
  if (liveStatusFilter.value === 'live') return 'live'
  if (liveStatusFilter.value === 'token_expired') return 'token_expired'
  if (liveStatusFilter.value === 'deactivated') return 'deactivated'
  return ''
})
const poolTabs = computed(() => [
  { value: 'all', label: '全部', count: metrics.value.total, tone: 'info' },
  { value: 'success', label: '注册成功', count: metrics.value.success, tone: 'success' },
  { value: 'checking', label: '测活中', count: metrics.value.checking, tone: 'primary' },
  { value: 'live', label: '账号正常', count: metrics.value.live, tone: 'success' },
  { value: 'token_expired', label: 'Token 失效', count: tokenExpiredRows.value.length, tone: 'warning' },
  { value: 'deactivated', label: '已停用', count: metrics.value.deactivated, tone: 'danger' },
  { value: 'pending_rerun', label: '待重跑', count: metrics.value.rerun, tone: 'warning' },
  { value: 'twofa_pending', label: '2FA 待重试', count: metrics.value.pending, tone: 'warning' },
] as { value: string; label: string; count: number; tone: string }[])

function setPoolTab(value: string) {
  switch (value) {
    case 'success': statusFilter.value = 'success'; liveStatusFilter.value = ''; break
    case 'checking': statusFilter.value = ''; liveStatusFilter.value = 'active'; break
    case 'live': statusFilter.value = ''; liveStatusFilter.value = 'live'; break
    case 'token_expired': statusFilter.value = ''; liveStatusFilter.value = 'token_expired'; break
    case 'deactivated': statusFilter.value = ''; liveStatusFilter.value = 'deactivated'; break
    case 'pending_rerun': statusFilter.value = 'pending_rerun'; liveStatusFilter.value = ''; break
    case 'twofa_pending': statusFilter.value = 'twofa_pending'; liveStatusFilter.value = ''; break
    default: statusFilter.value = ''; liveStatusFilter.value = ''
  }
  currentPage.value = 1
}

async function rerunExpiredTokens() {
  // Selection first: re-run only the checked 401 rows; fall back to the
  // whole Token 失效 tab when nothing is checked.
  const selectedExpired = selected.value.filter(row => canLiveCheck(row) && row.live_check_status === 'token_expired')
  const targets = selectedExpired.length ? selectedExpired : tokenExpiredRows.value.filter(canLiveCheck)
  if (!targets.length) {
    ElMessage.info('当前没有可重跑的 Token 失效账号')
    return
  }
  const scope = selectedExpired.length ? `选中的 ${targets.length} 个 Token 失效账号` : `Token 失效页的全部 ${targets.length} 个账号`
  try {
    await ElMessageBox.confirm(
      `深度测活会从代理池分配代理重新登录${scope}，并可能各收一封 OTP 邮件；确认封禁的账号会自动移出邮箱池。确定继续吗？`,
      '批量重跑401',
      { type: 'warning', confirmButtonText: '开始重跑', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  liveBusy.value = 'deep'
  try {
    const result = await startFreeLiveCheck('deep', targets.map(row => row.row_id))
    rows.value = result.rows || rows.value
    liveState.value = result.state || liveState.value
    const skipped = Number(result.skipped_count || 0)
    ElMessage.success(`已加入深度测活 ${Number(result.accepted_count || 0)} 个${skipped ? `，跳过 ${skipped} 个` : ''}`)
  } catch (error) {
    ElMessage.error(errorMessage(error) || '批量重跑 401 启动失败')
  } finally {
    liveBusy.value = ''
  }
}


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
    // Skip the reactive assignment when the polled rows equal the rendered
    // ones; the 1.2s poll otherwise re-renders the whole table.
    const nextFingerprint = freeMailboxRowsFingerprint(result.rows)
    if (nextFingerprint !== rowsFingerprint.value) {
      rowsFingerprint.value = nextFingerprint
      rows.value = result.rows || []
    }
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
    const nextFingerprint = freeMailboxRowsFingerprint(result.rows)
    if (nextFingerprint !== rowsFingerprint.value) {
      rowsFingerprint.value = nextFingerprint
      rows.value = result.rows || rows.value
      if (logRow.value?.row_id) logRow.value = rows.value.find(row => row.row_id === logRow.value?.row_id) || logRow.value
    }
    if (logDialogOpen.value && logRow.value?.live_check_task_id) {
      await logDialog.value?.refresh({ silent: true })
    }
  } catch (error) {
    if (liveState.value.running) ElMessage.error(errorMessage(error) || 'Free 测活状态刷新失败')
  }
}

async function refreshPlanState() {
  try {
    const result = await getFreePlanCheckState()
    planState.value = result.state || planState.value
    const nextFingerprint = freeMailboxRowsFingerprint(result.rows)
    if (nextFingerprint !== rowsFingerprint.value) {
      rowsFingerprint.value = nextFingerprint
      rows.value = result.rows || rows.value
      if (logRow.value?.row_id) logRow.value = rows.value.find(row => row.row_id === logRow.value?.row_id) || logRow.value
    }
  } catch (error) {
    if (planState.value.running) ElMessage.error(errorMessage(error) || 'Free 套餐查询状态刷新失败')
  }
}

function canLiveCheck(row: FreeMailboxRow) {
  return Boolean(row.has_access_token)
    && !['queued', 'running'].includes(String(row.live_check_status || ''))
}

async function startLiveCheck(mode: 'fast' | 'deep', selection = selected.value) {
  const eligible = selection.filter(canLiveCheck)
  if (!eligible.length) {
    ElMessage.warning('请选择已保存 Token 的 Free 账号')
    return
  }
  if (mode === 'deep') {
    try {
      await ElMessageBox.confirm(
        `深度测活会从代理池分配代理重新登录 ${eligible.length} 个账号，并可能多收一封 OTP 邮件；确认封禁的账号会自动移出邮箱池。确定继续吗？`,
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
    unavailableMailboxAction('该邮箱需要已保存 Token，且当前不在测活中')
    return
  }
  await startLiveCheck(mode, [row])
}

function canPlanRecheck(row: FreeMailboxRow) {
  if (isHistoricalMailboxDriver(row)) return false
  return !['queued', 'running'].includes(String(row.plan_check_status || ''))
}

async function startPlanRecheck(selection = selected.value) {
  const eligible = selection.filter(canPlanRecheck)
  if (!eligible.length) {
    ElMessage.warning('请选择可重查套餐的 Free 账号')
    return
  }
  try {
    await ElMessageBox.confirm(
      `将为 ${eligible.length} 个账号重查 Plus 套餐：Token 失效或缺失的账号会按各自链路重新登录（Camoufox 账号会打开浏览器，可能收取一封邮箱验证码）；确认停用的账号会自动移出邮箱池。确定继续吗？`,
      '批量重查套餐',
      { type: 'warning', confirmButtonText: '开始重查', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  planBatchBusy.value = true
  try {
    const result = await startFreePlanCheck(eligible.map(row => row.row_id), { mode: 'recheck' })
    rows.value = result.rows || rows.value
    planState.value = result.state || planState.value
    const skipped = Number(result.skipped_count || 0)
    ElMessage.success(`已加入套餐重查 ${Number(result.accepted_count || 0)} 个${skipped ? `，跳过 ${skipped} 个` : ''}`)
  } catch (error) {
    ElMessage.error(errorMessage(error) || '批量重查套餐启动失败')
  } finally {
    planBatchBusy.value = false
  }
}

async function copyEmail(row: FreeMailboxRow) {
  const rowId = String(row.row_id || '').trim()
  await copyEmailRow({
    rowId,
    // Public mailbox rows intentionally expose only a masked address. Resolve
    // the raw address through the existing on-demand secret boundary.
    produce: async () => {
      const value = String((await getFreeSecret('email', freeRowSecretLookup(row.row_id))).value || '')
      // The clipboard guard already ran in useRowClipboard before produce.
      if (!value) throw new Error('当前环境不支持复制')
      return value
    },
    successMessage: '已复制邮箱',
    errorMessage: '邮箱复制失败',
  })
}

const polling = usePolling(async () => {
  await refreshLiveState()
  await refreshPlanState()
}, () => (liveState.value.running || planState.value.running || logDialogOpen.value ? 1200 : 5000))
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

function skippedSuffix(items: Array<{ email?: string; reason?: string }> | undefined, skippedCount: number) {
  const details = (items || [])
    .slice(0, 3)
    .map(item => `${item.email || '选中行'}：${item.reason}`)
    .join('；')
  return details ? `；${details}${skippedCount > 3 ? '；其余跳过项未展开' : ''}` : ''
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
    const suffix = skippedSuffix(result.skipped_items, skipped)
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
    if (skipped) ElMessage.warning(`${summary}${skippedSuffix(result.skipped_items, skipped)}`)
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

function canRetryPassword(row: FreeMailboxRow): boolean {
  return Boolean(row.row_id) && Boolean(row.has_access_token) && !Boolean(row.has_password)
}

async function retryMailboxPassword(row: FreeMailboxRow) {
  if (isHistoricalMailboxDriver(row)) return unavailableMailboxAction('历史链路邮箱不支持密码补设')
  if (!canRetryPassword(row)) {
    return unavailableMailboxAction(row.has_password ? '该邮箱已有密码' : '该邮箱暂无账号 Token，无法补设密码')
  }
  if (passwordBusy.value) return
  passwordBusy.value = row.row_id
  try {
    await retryFreePassword(row.row_id)
    ElMessage.info('密码设置任务已重新加入队列')
    await refresh()
  } catch (error) {
    ElMessage.error(errorMessage(error) || '密码重试失败')
  } finally {
    passwordBusy.value = ''
  }
}

async function retryPlan(row: FreeMailboxRow) {
  if (isHistoricalMailboxDriver(row) || !row.row_id || String(row.plan_check_status || '').toLowerCase() !== 'failed' || planBusy.value) return
  planBusy.value = row.row_id
  try {
    await startFreePlanCheck([row.row_id], { mode: 'recheck' })
    ElMessage.info('套餐重查已加入队列')
    await refresh()
  } catch (error) {
    ElMessage.error(errorMessage(error) || '重新查询套餐失败')
  } finally {
    planBusy.value = ''
  }
}

async function retryMailboxPlan(row: FreeMailboxRow) {
  if (isHistoricalMailboxDriver(row)) return unavailableMailboxAction('历史链路邮箱不支持套餐重查')
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
  if (command === 'password_retry') return retryMailboxPassword(row)
  if (command === 'plan') return retryMailboxPlan(row)
}

async function exportResults() {
  try {
    const result = await exportFreeResults(selected.value.map(row => row.row_id))
    browserDownload(result.content || '', 'text/plain;charset=utf-8', result.filename || 'free-results.txt')
    ElMessage.success(`已导出 ${Number(result.count || 0)} 条 Free 结果`)
  } catch (error) { ElMessage.error(errorMessage(error) || 'Free 结果导出失败') }
}

onMounted(async () => {
  // The three payloads are independent; fetching them concurrently halves the
  // time to first paint of the pool table.
  await Promise.all([refresh(), refreshLiveState(), refreshPlanState()])
  scheduleRefresh()
})
</script>

<template>
  <div class="free-pool">
    <WorkspacePanel fill body-padding="none">
      <div class="table-region">
        <div class="metrics-row">
          <div class="pool-summary-strip" role="group" aria-label="邮箱池状态筛选">
            <button v-for="item in poolTabs" :key="item.value" type="button" class="summary-cell is-filter" :class="{ 'is-active': activePoolTab === item.value, [`tone-${item.tone}`]: true }" :aria-pressed="activePoolTab === item.value" @click="setPoolTab(item.value)">
              <span>{{ item.label }}</span><strong>{{ item.count }}</strong>
            </button>
          </div>
          <div class="pool-actions">
            <el-tooltip v-if="activePoolTab === 'token_expired'" :content="DEEP_LIVE_CHECK_TIP" placement="top" :show-after="250">
              <el-button size="small" type="warning" :icon="RefreshRight" :loading="liveBusy === 'deep'" :disabled="!tokenExpiredRows.length || Boolean(liveBusy)" aria-label="批量重跑401" @click="rerunExpiredTokens">批量重跑401</el-button>
            </el-tooltip>
            <el-tooltip content="撤销本表拖拽保存的列宽，恢复默认列宽" placement="top" :show-after="250">
              <el-button size="small" :icon="RefreshLeft" aria-label="重置列宽" @click="resetPoolWidths">重置列宽</el-button>
            </el-tooltip>
            <el-button size="small" type="primary" :icon="VideoPlay" :loading="runBusy" @click="quickStart">快捷运行</el-button>
            <el-button size="small" :icon="Refresh" :loading="loading" @click="refresh">刷新</el-button>
            <el-button size="small" type="primary" :icon="Plus" @click="openImport">导入 Free 邮箱</el-button>
          </div>
        </div>
        <div class="pool-filter-row">
          <el-input v-model="search" class="pool-search" size="small" clearable placeholder="搜索邮箱或错误节点" /><el-select v-model="statusFilter" class="pool-select" size="small" clearable placeholder="注册状态"><el-option label="可用" value="available" /><el-option label="运行中" value="running" /><el-option label="成功" value="success" /><el-option label="失败" value="failed" /><el-option label="待重跑" value="pending_rerun" /><el-option label="2FA 待重试" value="twofa_pending" /></el-select><el-select v-model="driverFilter" class="pool-select" size="small" clearable placeholder="注册链路"><el-option label="全协议" value="protocol" /><el-option label="Camoufox" value="camoufox" /></el-select><el-select v-model="liveStatusFilter" class="pool-select" size="small" clearable placeholder="测活状态"><el-option label="排队 / 测活中" value="active" /><el-option label="正常" value="live" /><el-option label="已停用" value="deactivated" /><el-option label="Token 失效" value="token_expired" /><el-option label="出口/反爬拒绝" value="free_live_proxy_blocked" /><el-option label="Session 被拒绝" value="free_live_session_rejected" /><el-option label="触发限流" value="free_live_rate_limited" /><el-option label="上游异常" value="free_live_upstream_error" /><el-option label="网络异常" value="free_live_network_error" /><el-option label="需要真实密码" value="free_live_password_required" /><el-option label="测活失败" value="failed" /></el-select>
          <div class="pool-bulk-actions">
            <span>已选 {{ selected.length }} 条</span>
            <el-tooltip placement="top" :show-after="250"><template #content><div class="live-check-tip">{{ FAST_LIVE_CHECK_TIP }}</div></template><el-button size="small" type="success" plain :icon="CircleCheck" :loading="liveBusy === 'fast'" :disabled="!selected.some(canLiveCheck) || Boolean(liveBusy)" @click="startLiveCheck('fast')">快速测活</el-button></el-tooltip>
            <el-tooltip placement="top" :show-after="250"><template #content><div class="live-check-tip">{{ DEEP_LIVE_CHECK_TIP }}</div></template><el-button size="small" type="warning" plain :icon="RefreshRight" :loading="liveBusy === 'deep'" :disabled="!selected.some(canLiveCheck) || Boolean(liveBusy)" @click="startLiveCheck('deep')">深度测活</el-button></el-tooltip>
            <el-tooltip placement="top" :show-after="250"><template #content><div class="live-check-tip">{{ PLAN_RECHECK_TIP }}</div></template><el-button size="small" type="primary" plain :icon="PriceTag" :loading="planBatchBusy" :disabled="!selected.some(canPlanRecheck) || Boolean(planBatchBusy)" @click="startPlanRecheck()">重查套餐</el-button></el-tooltip>
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
        </div>
        <el-table
          ref="tableRef"
          v-loading="loading"
          :data="pageRows"
          row-key="row_id"
          stripe
          height="100%"
          border
          :row-class-name="mailboxRowClass"
          @header-dragend="(newWidth: number, oldWidth: number, column: DragColumn) => onPoolHeaderDragend(newWidth, oldWidth, column)"
          @selection-change="selected = $event" size="small">
          <el-table-column type="selection" width="42" reserve-selection />
          <el-table-column type="index" label="序号" width="58" align="center" :index="(index: number) => index + 1 + (currentPage - 1) * pageSize" />
          <el-table-column label="邮箱" :width="poolColWidth('邮箱', 240)" show-overflow-tooltip>
            <template #default="{ row }">
              <div class="mailbox-account-cell">
                <el-tooltip :content="`点击复制邮箱${row.email ? `：${row.email}` : ''}`" placement="top" :show-after="250"><el-button link class="email-copy" :loading="loadingEmail.includes(row.row_id)" @click.stop="copyEmail(row)"><span>{{ row.email }}</span><el-icon v-if="!loadingEmail.includes(row.row_id)"><CopyDocument /></el-icon></el-button></el-tooltip>
                <span class="mailbox-subline">{{ mailboxDriverLabel(row) }}<template v-if="mailboxCreatedText(row)"> · {{ mailboxCreatedText(row) }}</template></span>
              </div>
            </template>
          </el-table-column>
          <el-table-column label="是否注册" :width="poolColWidth('是否注册', 90)" align="center">
            <template #default="{ row }"><el-tag size="small" :type="mailboxRegisteredType(row)" effect="plain">{{ mailboxRegisteredLabel(row) }}</el-tag></template>
          </el-table-column>
          <el-table-column label="阶段" :width="poolColWidth('阶段', 140)" align="center" show-overflow-tooltip><template #default="{ row }"><el-tooltip :content="mailboxStageTooltip(row)" placement="top" :show-after="250"><span class="mailbox-stage-cell"><el-tag size="small" effect="light" :type="mailboxStageType(row)">{{ mailboxStageLabel(row) }}</el-tag></span></el-tooltip></template></el-table-column>
          <el-table-column label="套餐" :width="poolColWidth('套餐', 96)" align="center" show-overflow-tooltip>
            <template #default="{ row }"><div class="mailbox-plan-cell"><el-tag size="small" :type="mailboxPlanTagType(row)" effect="plain">{{ mailboxPlanLabel(row) }}</el-tag><el-tag v-if="row.plus_trial_eligible && String(row.subscription_plan || row.plan_type || '').toLowerCase() !== 'free'" size="small" type="success" effect="plain" class="trial-tag">Plus 试用</el-tag></div></template>
          </el-table-column>
          <el-table-column label="账号测活" :width="poolColWidth('账号测活', 110)" align="center" show-overflow-tooltip>
            <template #default="{ row }"><div class="mailbox-live-cell"><el-tag size="small" :type="liveStatusType(row.live_check_status)">{{ liveStatusLabel(row.live_check_status) }}</el-tag><small v-if="row.live_check_mode">{{ row.live_check_mode === 'deep' ? '深度' : '快速' }}</small></div></template>
          </el-table-column>
          <el-table-column label="凭据" :width="poolColWidth('凭据', 120)">
            <template #default="{ row }"><div class="credential-cell"><StateDot :tone="mailboxTwofaType(row)" :label="`2FA ${mailboxTwofaLabel(row)}`" /><StateDot :tone="mailboxPasswordType(row)" :label="`密码 ${mailboxPasswordLabel(row)}`" /></div></template>
          </el-table-column>
          <el-table-column label="错误" :min-width="poolColWidth('错误', 260)">
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
                    <el-dropdown-item command="password_retry" :disabled="!canRetryPassword(row)" :title="canRetryPassword(row) ? '使用已保存 Token 补设账号密码' : '需要已保存 Token 且尚未设置密码'"><el-icon><Lock /></el-icon>重跑密码设置</el-dropdown-item>
                    <el-dropdown-item command="plan"><el-icon><PriceTag /></el-icon>重新查询套餐</el-dropdown-item>
                  </el-dropdown-menu>
                </template>
              </el-dropdown>
            </template>
          </el-table-column>
          <template #empty><ContentEmptyState /></template>
        </el-table>
        <el-pagination v-model:current-page="currentPage" v-model:page-size="pageSize" size="small" background layout="total, sizes, prev, pager, next" :page-sizes="[25, 50, 100]" :total="filteredRows.length" />
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
.pool-actions { margin-left: auto; display: flex; align-items: center; gap: var(--workspace-gap); flex: 0 0 auto; }
.pool-actions :deep(.el-button + .el-button) { margin-left: 0; }
.table-region { display: grid; grid-template-rows: auto auto minmax(0, 1fr) 46px; gap: var(--workspace-gap); width: 100%; height: 100%; min-height: 0; padding: 10px; }
.metrics-row { display: flex; align-items: center; gap: var(--workspace-gap); min-width: 0; }
.metrics-row .el-button { flex: 0 0 auto; }
.pool-summary-strip { display: flex; align-items: stretch; flex: 0 1 auto; height: 30px; min-width: 0; border: 1px solid var(--workspace-border); border-radius: var(--workspace-radius); overflow: hidden; background: var(--workspace-surface); }
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
.pool-filter-row { display: flex; align-items: center; gap: var(--workspace-gap); min-width: 0; flex-wrap: wrap; }
.pool-search { width: 200px; flex: 0 0 auto; }
.pool-select { width: 136px; flex: 0 0 auto; }
.pool-bulk-actions { margin-left: auto; display: flex; align-items: center; gap: var(--workspace-gap); min-width: 0; color: var(--el-text-color-secondary); font-size: 12px; }
.pool-bulk-actions > span { white-space: nowrap; }
.pool-bulk-actions :deep(.el-button + .el-button) { margin-left: 0; }
.trial-tag { margin-left: 5px; }
.mailbox-account-cell { display: flex; flex-direction: column; gap: 1px; min-width: 0; }
.mailbox-subline { display: block; overflow: hidden; color: var(--el-text-color-secondary); font-size: 11px; line-height: 15px; text-overflow: ellipsis; white-space: nowrap; }
.email-copy { display: inline-flex; max-width: 100%; min-width: 0; gap: 5px; height: auto; padding: 0; color: var(--el-text-color-primary); justify-content: flex-start; }
.email-copy span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.email-copy .el-icon { flex: 0 0 auto; color: var(--el-color-primary); }
.mailbox-plan-cell, .mailbox-live-cell { display: flex; align-items: center; justify-content: center; min-width: 0; gap: 5px; overflow: hidden; white-space: nowrap; }
.credential-cell { display: flex; flex-direction: column; align-items: center; gap: 2px; min-width: 0; }
.mailbox-plan-cell > .el-tag, .mailbox-live-cell > .el-tag { flex: 0 0 auto; }
.mailbox-stage-cell { display: inline-flex; max-width: 100%; min-width: 0; overflow: hidden; vertical-align: middle; }
.mailbox-stage-cell :deep(.el-tag) { max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.mailbox-live-cell small { display: inline; flex: 0 0 auto; margin-top: 0; color: var(--el-text-color-secondary); white-space: nowrap; }
.table-region :deep(.el-table td.el-table__cell),
.table-region :deep(.el-table th.el-table__cell) { padding-top: 3px; padding-bottom: 3px; }
.table-region :deep(.el-table .cell) { line-height: 18px; }
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
