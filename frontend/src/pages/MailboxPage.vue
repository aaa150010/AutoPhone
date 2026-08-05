<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  CircleCheckFilled,
  CircleCloseFilled,
  Collection,
  Connection,
  DataAnalysis,
  Download,
  Message,
  MessageBox,
  Search,
  VideoPlay,
  UploadFilled,
} from '@element-plus/icons-vue'
import {
  api,
  ApiError,
  exportMailboxSub2,
  getMailboxUrl,
  getMailboxTotp,
  getMailboxes,
  queryMailboxQuotas,
  retryMailboxPixel,
} from '../api/client'
import DashboardMetricCard from '../components/DashboardMetricCard.vue'
import MailboxTable from '../components/MailboxTable.vue'
import PageToolbar from '../components/PageToolbar.vue'
import WorkspacePanel from '../components/WorkspacePanel.vue'
import { useAppController } from '../composables/useAppController'
import type { MailboxPayload, MailboxRow } from '../types/api'

const controller = useAppController()
const data = ref<MailboxPayload>({ counts: {}, rows: [] })
const importContent = ref('')
const importVisible = ref(false)
const filter = ref('all')
const sub2Filter = ref('all')
const quotaFilter = ref('all')
const searchText = ref('')
const selectedRows = ref<MailboxRow[]>([])
const mailboxTable = ref<{ clearSelection: () => void } | null>(null)
const loadingPasswords = ref<string[]>([])
const loadingTotp = ref<string[]>([])
const currentPage = ref(1)
const pageSize = ref(50)
const mutating = ref(false)
const testingSub2 = ref(false)
const retryingPixel = ref(false)
const exportingSub2 = ref(false)
const queryingQuota = ref(false)
const quotaProgress = ref('')
let timer = 0
let pollingStopped = false
let dataVersion = 0
let latestRefresh = 0

const metricDefinitions = [
  { key: 'total', title: '邮箱总数', icon: Collection, tone: 'primary' },
  { key: 'available', title: '可用', icon: Message, tone: 'primary' },
  { key: 'running', title: '运行中', icon: VideoPlay, tone: 'warning' },
  { key: 'success', title: '已使用', icon: CircleCheckFilled, tone: 'success' },
  { key: 'failed', title: '失败', icon: CircleCloseFilled, tone: 'danger' },
] as const

function sub2StatusCode(status: any) {
  const code = Number(status?.status_code ?? status?.code)
  return Number.isFinite(code) && code > 0 ? code : null
}

function isSub2TestFailure(status: any) {
  if (!status || status.linked === false) return false
  const code = sub2StatusCode(status)
  if (code === 200 || code === 401 || code === 429) return false
  if (status.is_test_failure != null) return Boolean(status.is_test_failure)
  if (code === 404) return true
  const kind = String(status.kind || status.status || '').toLowerCase()
  if (['untested', 'unlinked', 'not_linked', 'not_ready', 'rate_limited', 'healthy', 'unauthorized'].includes(kind)) return false
  return Boolean(status.is_error || code)
}

function needsSub2Rerun(status: any) {
  const code = sub2StatusCode(status)
  if (code === 429) return false
  return Boolean(status?.needs_rerun) || code === 401 || code === 404
}

const rows = computed(() => data.value.rows.filter((row) => {
  const matchesFilter = filter.value === 'all'
    || (filter.value === 'not_consumed' ? row.status !== 'consumed' : row.status === filter.value)
  const sub2Status = row.sub2_status || (row as any).sub2
  const matchesSub2 = sub2Filter.value === 'all'
    || (sub2Filter.value === 'test_failure' && isSub2TestFailure(sub2Status))
    || (sub2Filter.value === 'needs_rerun' && needsSub2Rerun(sub2Status))
  const hasRemainingQuota = [row.quota_5h, row.quota_7d].some((window) => (
    window?.remaining_percent != null && Number(window.remaining_percent) > 0
  ))
  const hasQuotaResult = row.quota_status === 'ok' || row.quota_status === 'error'
  const matchesQuota = quotaFilter.value === 'all'
    || (quotaFilter.value === 'remaining' && hasRemainingQuota)
    || (quotaFilter.value === 'queried' && hasQuotaResult)
  const query = searchText.value.trim().toLowerCase()
  const haystack = [
    row.email,
    row.status,
    row.status_label,
    row.task_status,
    row.progress?.label,
    row.error,
    row.reason,
    sub2Status?.label,
    sub2Status?.summary,
    row.batch_id,
  ].join(' ').toLowerCase()
  return matchesFilter && matchesSub2 && matchesQuota && (!query || haystack.includes(query))
}))

const pageRows = computed(() => rows.value.slice(
  (currentPage.value - 1) * pageSize.value,
  currentPage.value * pageSize.value,
))

watch([filter, sub2Filter, quotaFilter, searchText, pageSize], () => { currentPage.value = 1 })
watch(() => rows.value.length, (total) => {
  currentPage.value = Math.min(currentPage.value, Math.max(1, Math.ceil(total / pageSize.value)))
})

function applyMailboxPayload(payload: any) {
  const next = payload?.mailboxes || payload
  if (next && Array.isArray(next.rows)) {
    const previous = new Map(data.value.rows.map(row => [row.row_id, row]))
    data.value = {
      ok: next.ok,
      counts: next.counts || {},
      rows: next.rows.map((row: MailboxRow) => {
        const old = previous.get(row.row_id)
        return old
          ? { ...row, quota_status: old.quota_status, quota_error: old.quota_error, quota_queried_at: old.quota_queried_at, quota_5h: old.quota_5h, quota_7d: old.quota_7d }
          : row
      }),
    }
  }
  if (payload?.state) controller.syncState(payload.state)
}

function applyQuotaResults(results: any[]) {
  const byRow = new Map(results.map(item => [String(item.row_id), item]))
  data.value = {
    ...data.value,
    rows: data.value.rows.map(row => {
      const result = byRow.get(row.row_id)
      if (!result) return row
      return {
        ...row,
        quota_status: result.status,
        quota_error: result.error || '',
        quota_queried_at: result.queried_at || Math.floor(Date.now() / 1000),
        quota_5h: result.quota_5h ?? null,
        quota_7d: result.quota_7d ?? null,
      }
    }),
  }
}

async function queryQuotas() {
  const candidates = data.value.rows.filter(row => row.status === 'consumed' && row.task_id)
  if (!candidates.length) {
    ElMessage.warning('当前没有可查询 OpenAI 额度的成功账号')
    return
  }
  queryingQuota.value = true
  mutating.value = true
  dataVersion += 1
  latestRefresh += 1
  let completed = 0
  let failed = 0
  try {
    for (let index = 0; index < candidates.length; index += 5) {
      const chunk = candidates.slice(index, index + 5)
      quotaProgress.value = `${Math.min(index + chunk.length, candidates.length)}/${candidates.length}`
      const result = await queryMailboxQuotas(chunk.map(row => ({ row_id: row.row_id, line_no: row.line_no })))
      applyQuotaResults(result.results || [])
      completed += Number(result.queried || 0)
      failed += Number(result.failed || 0)
    }
    const details = failed ? `，失败 ${failed} 条` : ''
    ElMessage.success(`已查询 OpenAI 额度 ${completed} 条${details}`)
  } catch (error: any) {
    ElMessage.error(error?.message || '批量查询 OpenAI 额度失败')
  } finally {
    queryingQuota.value = false
    quotaProgress.value = ''
    mutating.value = false
  }
}

async function refresh() {
  if (mutating.value) return
  const request = ++latestRefresh
  const version = dataVersion
  try {
    const result = await getMailboxes()
    if (!mutating.value && request === latestRefresh && version === dataVersion) applyMailboxPayload(result)
  } catch (error: any) {
    if (request === latestRefresh) ElMessage.error(error?.message || '邮箱列表刷新失败')
  }
}

async function append() {
  if (!importContent.value.trim()) {
    ElMessage.warning('请先粘贴要导入的邮箱')
    return
  }
  mutating.value = true
  dataVersion += 1
  latestRefresh += 1
  try {
    const result: any = await api('/api/mailboxes/import', { pool_content: importContent.value })
    applyMailboxPayload(result)
    importContent.value = ''
    importVisible.value = false
    ElMessage.success(`已追加 ${result.imported || 0} 条，跳过 ${result.skipped || 0} 条`)
  } catch (error: any) {
    ElMessage.error(error?.message || '导入失败')
  } finally {
    mutating.value = false
  }
}

async function mutate(path: string, message: string) {
  if (!selectedRows.value.length) {
    ElMessage.warning('请先选择邮箱')
    return
  }
  try {
    await ElMessageBox.confirm(message, '确认操作', { type: 'warning' })
  } catch {
    return
  }

  mutating.value = true
  dataVersion += 1
  latestRefresh += 1
  const selected = selectedRows.value.map(row => ({ row_id: row.row_id, line_no: row.line_no }))
  const lineNumbers = selected.map(row => row.line_no)
  try {
    mailboxTable.value?.clearSelection()
    selectedRows.value = []
    const result: any = await api(path, { line_nos: lineNumbers, rows: selected })
    applyMailboxPayload(result)
    await nextTick()
    mailboxTable.value?.clearSelection()
    ElMessage.success('操作完成')
  } catch (error: any) {
    ElMessage.error(error?.message || '操作失败')
  } finally {
    mutating.value = false
  }
}

async function testSub2() {
  if (!selectedRows.value.length) {
    ElMessage.warning('请先选择邮箱')
    return
  }
  testingSub2.value = true
  mutating.value = true
  dataVersion += 1
  latestRefresh += 1
  const selected = selectedRows.value.map(row => ({ row_id: row.row_id, line_no: row.line_no }))
  try {
    mailboxTable.value?.clearSelection()
    selectedRows.value = []
    const result: any = await api('/api/mailboxes/openai-test', { rows: selected })
    applyMailboxPayload(result)
    if (Array.isArray(result?.results)) {
      const statuses = new Map<string, MailboxRow['sub2_status']>(
        result.results.map((item: any) => [String(item.row_id), item.sub2_status]),
      )
      data.value = {
        ...data.value,
        rows: data.value.rows.map(row => statuses.has(row.row_id)
          ? { ...row, sub2_status: statuses.get(row.row_id) }
          : row),
      }
    }
    if (!result?.rows && !result?.mailboxes?.rows) applyMailboxPayload(await getMailboxes())
    await nextTick()
    mailboxTable.value?.clearSelection()
    const tested = Number(result?.tested ?? result?.completed ?? selected.length)
    const unlinked = Number(result?.unlinked ?? 0)
    const notReady = Number(result?.not_ready ?? 0)
    const batchCount = Number(result?.batch_count ?? 1)
    const queuedBatches = Number(result?.queued_batches ?? Math.max(0, batchCount - 1))
    const resultStatuses = (result?.results || []).map((item: any) => item?.sub2_status).filter(Boolean)
    const failed = Number(resultStatuses.length
      ? resultStatuses.filter(isSub2TestFailure).length
      : result?.test_failures ?? result?.test_failed ?? result?.failed ?? 0)
    const rateLimited = Number(resultStatuses.length
      ? resultStatuses.filter((status: any) => sub2StatusCode(status) === 429).length
      : result?.rate_limited ?? 0)
    const details = [
      batchCount > 1 ? `已分 ${batchCount} 批排队测试` : '',
      failed ? `测试失败 ${failed} 条` : '',
      rateLimited ? `额度受限 ${rateLimited} 条` : '',
      notReady ? `未上传 ${notReady} 条` : (unlinked ? `未关联 ${unlinked} 条` : ''),
    ].filter(Boolean).join('，')
    const progressText = queuedBatches > 0 && Number(result?.completed_batches) < batchCount
      ? `，已完成 ${Number(result?.completed_batches ?? 0)}/${batchCount} 批`
      : ''
    const message = `已测试 ${tested} 条${progressText}${details ? `，${details}` : ''}`
    if (failed || rateLimited || notReady) ElMessage.warning(message)
    else ElMessage.success(message)
  } catch (error: any) {
    if (error instanceof ApiError && error.status === 409) {
      try {
        applyMailboxPayload(await getMailboxes())
      } catch {
        // Keep the stale selection cleared; normal polling will retry the refresh.
      }
    }
    ElMessage.error(error?.message || '本机 OpenAI 连接测试失败')
  } finally {
    testingSub2.value = false
    mutating.value = false
  }
}

function selectedBindings() {
  return selectedRows.value.map(row => ({ row_id: row.row_id, line_no: row.line_no }))
}

async function retryPixel() {
  if (!selectedRows.value.length) {
    ElMessage.warning('请先选择邮箱')
    return
  }
  try {
    await ElMessageBox.confirm(
      `将选中的 ${selectedRows.value.length} 个邮箱重新加入 Pixel 上传队列？`,
      '重新上传 Pixel',
      { type: 'warning', confirmButtonText: '确认重传', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  retryingPixel.value = true
  mutating.value = true
  dataVersion += 1
  latestRefresh += 1
  const selected = selectedBindings()
  try {
    mailboxTable.value?.clearSelection()
    selectedRows.value = []
    const result: any = await retryMailboxPixel(selected)
    applyMailboxPayload(result)
    await nextTick()
    mailboxTable.value?.clearSelection()
    const skipped = Number(result?.skipped || 0)
    ElMessage.success(`已加入 Pixel 队列 ${Number(result?.queued || 0)} 条${skipped ? `，跳过 ${skipped} 条` : ''}`)
  } catch (error: any) {
    if (error instanceof ApiError && error.status === 409) await refresh()
    ElMessage.error(error?.message || 'Pixel 批量重传失败')
  } finally {
    retryingPixel.value = false
    mutating.value = false
  }
}

async function exportSub2() {
  if (!selectedRows.value.length) {
    ElMessage.warning('请先选择邮箱')
    return
  }
  try {
    await ElMessageBox.confirm(
      '导出文件包含完整 OAuth Token，仅应保存在可信设备。',
      '导出 SUB2API',
      { type: 'warning', confirmButtonText: '确认导出', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  exportingSub2.value = true
  try {
    const result = await exportMailboxSub2(selectedBindings())
    const blob = new Blob([JSON.stringify(result.export, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = result.filename || 'sub2api-export.json'
    link.click()
    URL.revokeObjectURL(url)
    const skipped = Number(result.skipped || 0)
    ElMessage.success(`已导出 ${Number(result.count || 0)} 条${skipped ? `，跳过 ${skipped} 条` : ''}`)
  } catch (error: any) {
    if (error instanceof ApiError && error.status === 409) await refresh()
    ElMessage.error(error?.message || 'SUB2API 导出失败')
  } finally {
    exportingSub2.value = false
  }
}

async function copyPassword(row: MailboxRow) {
  if (loadingPasswords.value.includes(row.row_id)) return
  if (!navigator.clipboard?.writeText) {
    ElMessage.error('当前浏览器不支持安全剪贴板写入')
    return
  }
  loadingPasswords.value = [...loadingPasswords.value, row.row_id]
  try {
    const result: { password: string } = await api('/api/mailboxes/password', {
      row_id: row.row_id,
      line_no: row.line_no,
    })
    await navigator.clipboard.writeText(String(result.password || ''))
    ElMessage.success('已复制密码')
  } catch (error: any) {
    if (error instanceof ApiError && error.payload?.code === 'mailbox_row_stale') await refresh()
    ElMessage.error(error?.message || '复制密码失败')
  } finally {
    loadingPasswords.value = loadingPasswords.value.filter(id => id !== row.row_id)
  }
}

async function copyEmail(row: MailboxRow) {
  const value = String(row.email || '').trim()
  if (!value) return
  if (!navigator.clipboard?.writeText) {
    ElMessage.error('当前浏览器不支持安全剪贴板写入')
    return
  }
  try {
    await navigator.clipboard.writeText(value)
    ElMessage.success('已复制邮箱')
  } catch {
    ElMessage.error('复制邮箱失败')
  }
}

async function copyTotp(row: MailboxRow) {
  if (!row.has_totp || loadingTotp.value.includes(row.row_id)) return
  if (!navigator.clipboard?.writeText) {
    ElMessage.error('当前浏览器不支持安全剪贴板写入')
    return
  }
  loadingTotp.value = [...loadingTotp.value, row.row_id]
  try {
    const result = await getMailboxTotp({ row_id: row.row_id, line_no: row.line_no })
    await navigator.clipboard.writeText(String(result.totp_secret || ''))
    ElMessage.success('已复制 2FA 密钥')
  } catch (error: any) {
    if (error instanceof ApiError && error.payload?.code === 'mailbox_row_stale') await refresh()
    ElMessage.error(error?.message || '复制 2FA 密钥失败')
  } finally {
    loadingTotp.value = loadingTotp.value.filter(id => id !== row.row_id)
  }
}

async function openMailboxUrl(row: MailboxRow) {
  if (!row.has_mailbox_url) return
  const target = window.open('', '_blank')
  if (!target) {
    ElMessage.error('浏览器阻止了新窗口，请允许弹出窗口后重试')
    return
  }
  try {
    target.opener = null
    const result = await getMailboxUrl({ row_id: row.row_id, line_no: row.line_no })
    target.location.href = String(result.mailbox_url || '')
  } catch (error: any) {
    target.close()
    if (error instanceof ApiError && error.payload?.code === 'mailbox_row_stale') await refresh()
    ElMessage.error(error?.message || '打开取件 URL 失败')
  }
}

async function poll() {
  await refresh()
  if (pollingStopped) return
  const active = data.value.rows.some(row => row.progress && row.progress.finished_at == null)
  timer = window.setTimeout(poll, active ? 1000 : 3000)
}

onMounted(async () => {
  pollingStopped = false
  await refresh()
  if (!pollingStopped) timer = window.setTimeout(poll, 3000)
})

onUnmounted(() => {
  pollingStopped = true
  window.clearTimeout(timer)
})
</script>

<template>
  <div class="mailbox-page">
    <PageToolbar title="邮箱管理" status="邮箱池" tone="info">
      <el-button type="primary" :disabled="mutating" @click="importVisible = true"><el-icon><Upload /></el-icon>导入邮箱</el-button>
    </PageToolbar>

    <div class="metric-grid">
      <DashboardMetricCard
        v-for="metric in metricDefinitions"
        :key="metric.key"
        :title="metric.title"
        :value="data.counts[metric.key] || 0"
        :icon="metric.icon"
        :tone="metric.tone"
        framed
      />
    </div>

    <WorkspacePanel title="邮箱状态" :icon="MessageBox" fill body-padding="none">
      <template #actions>
        <span v-if="selectedRows.length" class="selected-count">已选 {{ selectedRows.length }}</span>
        <el-input v-model="searchText" class="search-input" clearable placeholder="搜索邮箱、状态、说明" :prefix-icon="Search" />
        <el-select v-model="filter" class="filter-select">
          <el-option label="全部" value="all" />
          <el-option label="未使用" value="not_consumed" />
          <el-option label="可用" value="available" />
          <el-option label="运行中" value="running" />
          <el-option label="已使用" value="consumed" />
          <el-option label="失败" value="failed" />
        </el-select>
        <el-select v-model="sub2Filter" class="sub2-filter-select">
          <el-option label="全部 OpenAI" value="all" />
          <el-option label="OpenAI 测试失败" value="test_failure" />
          <el-option label="OpenAI 401/404（需重试）" value="needs_rerun" />
        </el-select>
        <el-select v-model="quotaFilter" class="quota-filter-select">
          <el-option label="全部额度" value="all" />
          <el-option label="有剩余额度" value="remaining" />
          <el-option label="已查询额度" value="queried" />
        </el-select>
        <el-button :loading="queryingQuota" :disabled="mutating" @click="queryQuotas">
          <el-icon><DataAnalysis /></el-icon>{{ queryingQuota && quotaProgress ? `查询额度 ${quotaProgress}` : '批量查询额度' }}
        </el-button>
        <el-button :loading="testingSub2" :disabled="mutating || !selectedRows.length" @click="testSub2">
          <el-icon><Connection /></el-icon>批量测试 OpenAI
        </el-button>
        <el-button :loading="retryingPixel" :disabled="mutating || !selectedRows.length" @click="retryPixel">
          <el-icon><UploadFilled /></el-icon>重传 Pixel
        </el-button>
        <el-button :loading="exportingSub2" :disabled="mutating || !selectedRows.length" @click="exportSub2">
          <el-icon><Download /></el-icon>导出 SUB2API
        </el-button>
        <el-button :disabled="mutating || !selectedRows.length" @click="mutate('/api/mailboxes/restore', '将选中邮箱恢复为可用状态？')">
          <el-icon><RefreshLeft /></el-icon>恢复可用
        </el-button>
        <el-button type="danger" plain :disabled="mutating || !selectedRows.length" @click="mutate('/api/mailboxes/delete', '确定删除选中的邮箱？')">
          <el-icon><Delete /></el-icon>删除
        </el-button>
      </template>

      <div class="table-region">
        <MailboxTable
          ref="mailboxTable"
          :rows="pageRows"
          :loading-passwords="loadingPasswords"
          :loading-totp="loadingTotp"
          @select="selectedRows = $event"
          @email="copyEmail"
          @password="copyPassword"
          @totp="copyTotp"
          @url="openMailboxUrl"
        />
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          class="pager"
          background
          layout="total, sizes, prev, pager, next"
          :page-sizes="[25, 50, 100]"
          :total="rows.length"
        />
      </div>
    </WorkspacePanel>

    <el-dialog v-model="importVisible" title="批量追加邮箱" width="720px" destroy-on-close>
      <el-input
        v-model="importContent"
        type="textarea"
        :rows="12"
        resize="none"
        placeholder="URL 邮箱：邮箱---https://接码地址&#10;URL 邮箱：邮箱|https://接码地址&#10;TOTP：GPT账号---登录密码---Base32 2FA密钥&#10;TOTP：GPT账号|登录密码|Base32 2FA密钥&#10;OAuth：邮箱----密码----client_id----refresh_token&#10;&#10;URL 邮箱支持 --- / ---- / | / ｜"
      />
      <template #footer>
        <el-button @click="importVisible = false">取消</el-button>
        <el-button type="primary" :loading="mutating" @click="append"><el-icon><Upload /></el-icon>追加导入</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.mailbox-page { display: grid; grid-template-rows: 44px 78px minmax(0, 1fr); gap: 6px; width: 100%; height: 100%; min-width: 0; min-height: 0; }
.metric-grid { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 7px; min-width: 0; }
.selected-count { color: var(--el-color-primary); font-size: 13px; white-space: nowrap; }
.search-input { width: 210px; }
.filter-select { width: 110px; }
.sub2-filter-select { width: 168px; }
.quota-filter-select { width: 128px; }
.table-region { display: grid; grid-template-rows: minmax(0, 1fr) 46px; width: 100%; height: 100%; min-height: 0; padding: 8px 10px 0; }
.pager { justify-content: flex-end; border-top: 1px solid var(--workspace-border); }

@media (max-width: 760px) {
  .metric-grid { gap: 4px; }
  .metric-grid :deep(.metric-card.framed) { gap: 3px; overflow: hidden; padding: 4px; }
  .metric-grid :deep(.metric-card.framed .metric-icon) { flex-basis: 20px; width: 20px; height: 20px; font-size: 12px; }
  .metric-grid :deep(.metric-card.framed .metric-copy span) { font-size: 10px; line-height: 14px; }
  .metric-grid :deep(.metric-card.framed .metric-value) { font-size: 20px; line-height: 24px; }
}
</style>
