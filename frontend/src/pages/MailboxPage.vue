<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  CircleCheckFilled,
  CircleCloseFilled,
  Collection,
  Connection,
  DataAnalysis,
  Message,
  MessageBox,
  Search,
  VideoPlay,
} from '@element-plus/icons-vue'
import {
  api,
  ApiError,
  exportMailboxSub2,
  getMailboxUrl,
  getMailboxTotp,
  getMailboxes,
  importWebsiteMailboxes,
  queryMailboxQuotas,
  reloginMailboxRows,
  retryMailboxPixel,
  setMailboxRowsUnavailable,
} from '../api/client'
import DashboardMetricCard from '../components/DashboardMetricCard.vue'
import MailboxActionMenus from '../components/MailboxActionMenus.vue'
import MailboxImportDialog from '../components/MailboxImportDialog.vue'
import MailboxTable from '../components/MailboxTable.vue'
import PageToolbar from '../components/PageToolbar.vue'
import WorkspacePanel from '../components/WorkspacePanel.vue'
import { useAppController } from '../composables/useAppController'
import { useMailboxBatchOperations } from '../composables/useMailboxBatchOperations'
import type { MailboxPayload, MailboxRow } from '../types/api'
import {
  isLatestMailboxBatchFailure,
  isMailboxNetworkDisconnected,
  latestMailboxBatchId,
} from '../utils/mailboxFilters'
import {
  canSetMailboxRowsUnavailable,
  mergeMailboxOperationUpdates,
  mergeMailboxQuotaResults,
} from '../utils/mailboxRows'

const controller = useAppController()
const data = ref<MailboxPayload>({ counts: {}, rows: [] })
const mailboxImportDialog = ref<InstanceType<typeof MailboxImportDialog>>()
const filter = ref('all')
const sub2Filter = ref('all')
const quotaFilter = ref('all')
const searchText = ref('')
const selectedRows = ref<MailboxRow[]>([])
const mailboxTable = ref<{ clearSelection: () => void } | null>(null)
const loadingPasswords = ref<string[]>([])
const loadingTotp = ref<string[]>([])
const currentPage = ref(1)
const pageSize = ref(100)
const mutating = ref(false)
const reloginStarting = ref(false)
const retryingPixel = ref(false)
const exportingSub2 = ref(false)
const uploadingWebsite = ref(false)
const settingUnavailable = ref(false)
const retryingQuotaRows = ref<string[]>([])
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

const latestBatchId = computed(() => latestMailboxBatchId(data.value.rows))

const rows = computed(() => data.value.rows.filter((row) => {
  const inLatestBatch = Boolean(latestBatchId.value && row.batch_id === latestBatchId.value)
  const matchesFilter = filter.value === 'all'
    || (filter.value === 'latest_batch' && inLatestBatch)
    || (filter.value === 'latest_batch_failed' && inLatestBatch && isLatestMailboxBatchFailure(row))
    || (filter.value === 'not_consumed' ? row.status !== 'consumed' : row.status === filter.value)
  const sub2Status = row.sub2_status || (row as any).sub2
  const matchesSub2 = sub2Filter.value === 'all'
    || (sub2Filter.value === 'test_failure' && isSub2TestFailure(sub2Status))
    || (sub2Filter.value === 'needs_rerun' && needsSub2Rerun(sub2Status))
    || (sub2Filter.value === 'network_disconnected' && isMailboxNetworkDisconnected(row))
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

const pageRows = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  return rows.value
    .slice(start, currentPage.value * pageSize.value)
    .map((row, index) => ({ ...row, display_index: start + index + 1 }))
})

watch([filter, sub2Filter, quotaFilter, searchText, pageSize], () => { currentPage.value = 1 })
watch(() => rows.value.length, (total) => {
  currentPage.value = Math.min(currentPage.value, Math.max(1, Math.ceil(total / pageSize.value)))
})

function applyMailboxPayload(payload: any) {
  mailboxBatch.sync(payload)
  const next = payload?.mailboxes || payload
  if (next && Array.isArray(next.rows)) {
    data.value = {
      ok: next.ok,
      counts: next.counts || {},
      rows: mergeMailboxOperationUpdates(
        next.rows,
        mailboxBatch.operation.value?.row_updates || [],
      ),
    }
  }
  if (payload?.state) controller.syncState(payload.state)
}

function queryableRows() {
  return data.value.rows.filter(row => row.status === 'consumed' && row.task_id)
}

function scheduleMailboxPoll(delay: number) {
  if (pollingStopped) return
  window.clearTimeout(timer)
  timer = window.setTimeout(poll, delay)
}

const mailboxBatch = useMailboxBatchOperations({
  candidates: queryableRows,
  clearSelection: () => {
    mailboxTable.value?.clearSelection()
    selectedRows.value = []
  },
  onStarted: () => {
    dataVersion += 1
    latestRefresh += 1
    scheduleMailboxPoll(0)
  },
})
const {
  busy: batchBusy,
  queryingQuota,
  testingOpenAI: testingSub2,
  quotaProgress,
  openaiTestProgress,
  queryQuotas,
  testOpenAI: testSub2,
} = mailboxBatch

async function retryQuota(row: MailboxRow) {
  if (row.quota_status !== 'error' || mutating.value || batchBusy.value || retryingQuotaRows.value.includes(row.row_id)) return
  retryingQuotaRows.value = [...retryingQuotaRows.value, row.row_id]
  mutating.value = true
  dataVersion += 1
  latestRefresh += 1
  try {
    const result = await queryMailboxQuotas([{ row_id: row.row_id, line_no: row.line_no }])
    data.value = {
      ...data.value,
      rows: mergeMailboxQuotaResults(data.value.rows, result.results || []),
    }
    const status = result.results?.[0]
    if (status?.status === 'ok') ElMessage.success('OpenAI 额度已更新')
    else ElMessage.error(status?.error || '查询 OpenAI 额度失败')
  } catch (error: any) {
    if (error instanceof ApiError && error.status === 409) {
      try {
        applyMailboxPayload(await getMailboxes())
      } catch {
        // Normal polling will retry after this mutation finishes.
      }
    }
    ElMessage.error(error?.message || '查询 OpenAI 额度失败')
  } finally {
    retryingQuotaRows.value = retryingQuotaRows.value.filter(id => id !== row.row_id)
    mutating.value = false
  }
}

async function refresh() {
  const request = ++latestRefresh
  const version = dataVersion
  try {
    const result = await getMailboxes()
    if (!mutating.value && request === latestRefresh && version === dataVersion) applyMailboxPayload(result)
  } catch (error: any) {
    if (request === latestRefresh) ElMessage.error(error?.message || '邮箱列表刷新失败')
  }
}

function setImportBusy(value: boolean) {
  if (value) {
    dataVersion += 1
    latestRefresh += 1
  }
  mutating.value = value
}

function applyImportedMailboxes(result: any) {
  applyMailboxPayload(result)
  currentPage.value = 1
}

async function mutate(
  path: string,
  message: string,
  action?: (rows: Array<{ row_id: string; line_no: number }>) => Promise<any>,
  successMessage: string | ((result: any) => string) = '操作完成',
) {
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
    const result: any = action
      ? await action(selected)
      : await api(path, { line_nos: lineNumbers, rows: selected })
    applyMailboxPayload(result)
    await nextTick()
    mailboxTable.value?.clearSelection()
    ElMessage.success(typeof successMessage === 'function' ? successMessage(result) : successMessage)
  } catch (error: any) {
    ElMessage.error(error?.message || '操作失败')
  } finally {
    mutating.value = false
  }
}

async function setUnavailable() {
  settingUnavailable.value = true
  try {
    await mutate(
      '',
      '将选中的邮箱设置为不可用？源邮箱行和历史结果会保留。',
      setMailboxRowsUnavailable,
      result => `已设置为不可用 ${Number(result?.unavailable || 0)} 条`,
    )
  } finally {
    settingUnavailable.value = false
  }
}

async function uploadWebsiteMailboxes() {
  try {
    await ElMessageBox.confirm(
      '将扫描本机全部带取件 URL 的邮箱并增量上传到网站，完整取件 URL 会保存到受密码保护的在线管理页。',
      '导入网站邮箱',
      { type: 'warning', confirmButtonText: '确认上传', cancelButtonText: '取消' },
    )
  } catch {
    return
  }

  uploadingWebsite.value = true
  mutating.value = true
  try {
    const result = await importWebsiteMailboxes()
    const summary = [
      `新增 ${Number(result.created || 0)}`,
      `更新 ${Number(result.updated || 0)}`,
      `重复 ${Number(result.duplicates || 0)}`,
      `跳过 ${Number(result.skipped || 0)}`,
    ].join('，')
    ElMessage.success(`网站邮箱导入完成：${summary}`)
    if (result.manager_url) {
      try {
        await ElMessageBox.confirm(
          summary,
          '网站邮箱导入完成',
          { type: 'success', confirmButtonText: '打开在线管理', cancelButtonText: '关闭' },
        )
        const target = window.open(result.manager_url, '_blank')
        if (target) target.opener = null
      } catch {
        // The upload is complete; closing the result dialog needs no follow-up.
      }
    }
  } catch (error: any) {
    ElMessage.error(error?.message || '网站邮箱上传失败')
  } finally {
    uploadingWebsite.value = false
    mutating.value = false
  }
}

function selectedBindings() {
  return selectedRows.value.map(row => ({ row_id: row.row_id, line_no: row.line_no }))
}

async function startRelogin() {
  if (!selectedRows.value.length) {
    ElMessage.warning('请先选择需要重登的邮箱')
    return
  }
  if (selectedRows.value.some(row => !needsSub2Rerun(row.sub2_status))) {
    ElMessage.warning('只能选择当前为 401/404 的邮箱执行重登')
    return
  }
  try {
    await ElMessageBox.confirm(
      `将 ${selectedRows.value.length} 个邮箱执行无手机号重登并原位更新 SUB2？`,
      '重登并更新 SUB2',
      { type: 'warning', confirmButtonText: '开始重登', cancelButtonText: '取消' },
    )
  } catch {
    return
  }

  reloginStarting.value = true
  mutating.value = true
  dataVersion += 1
  latestRefresh += 1
  const selected = selectedBindings()
  try {
    mailboxTable.value?.clearSelection()
    selectedRows.value = []
    const result = await reloginMailboxRows(selected)
    applyMailboxPayload(result)
    await nextTick()
    mailboxTable.value?.clearSelection()
    ElMessage.success(`已启动 ${Number(result.started || selected.length)} 个重登任务`)
  } catch (error: any) {
    if (error instanceof ApiError && error.status === 409) await refresh()
    ElMessage.error(error?.message || '重登任务启动失败')
  } finally {
    reloginStarting.value = false
    mutating.value = false
  }
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
    await navigator.clipboard.writeText(String(result.code || ''))
    ElMessage.success(`已复制临时 2FA 验证码，约 ${result.remaining} 秒后刷新`)
  } catch (error: any) {
    if (error instanceof ApiError && error.payload?.code === 'mailbox_row_stale') await refresh()
    ElMessage.error(error?.message || '复制临时 2FA 验证码失败')
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
  const active = mailboxBatch.running.value
    || data.value.rows.some(row => row.progress && row.progress.finished_at == null)
  scheduleMailboxPoll(active ? 1000 : 3000)
}

onMounted(async () => {
  pollingStopped = false
  await refresh()
  const active = mailboxBatch.running.value
    || data.value.rows.some(row => row.progress && row.progress.finished_at == null)
  scheduleMailboxPoll(active ? 1000 : 3000)
})

onUnmounted(() => {
  pollingStopped = true
  window.clearTimeout(timer)
})
</script>

<template>
  <div class="mailbox-page">
    <PageToolbar title="邮箱管理" status="邮箱池" tone="info">
      <el-button type="primary" :disabled="mutating || batchBusy" @click="mailboxImportDialog?.open()"><el-icon><Upload /></el-icon>导入邮箱</el-button>
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
          <el-option label="最近运行批次" value="latest_batch" />
          <el-option label="最近运行批次失败" value="latest_batch_failed" />
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
          <el-option label="网络断开" value="network_disconnected" />
        </el-select>
        <el-select v-model="quotaFilter" class="quota-filter-select">
          <el-option label="全部额度" value="all" />
          <el-option label="有剩余额度" value="remaining" />
          <el-option label="已查询额度" value="queried" />
        </el-select>
        <el-button :loading="queryingQuota" :disabled="mutating || batchBusy" @click="queryQuotas">
          <el-icon><DataAnalysis /></el-icon>{{ queryingQuota && quotaProgress ? `查询额度 ${quotaProgress}` : '批量查询额度' }}
        </el-button>
        <el-button :loading="testingSub2" :disabled="mutating || batchBusy" @click="testSub2">
          <el-icon><Connection /></el-icon>{{ testingSub2 && openaiTestProgress ? `测试 OpenAI ${openaiTestProgress}` : '批量测试 OpenAI' }}
        </el-button>
        <MailboxActionMenus
          :relogin-disabled="mutating || batchBusy || controller.runtime.value.running || !selectedRows.length || selectedRows.some(row => !needsSub2Rerun(row.sub2_status))"
          :restore-disabled="mutating || batchBusy || !selectedRows.length"
          :unavailable-disabled="mutating || batchBusy || !canSetMailboxRowsUnavailable(selectedRows)"
          :pixel-disabled="mutating || batchBusy || !selectedRows.length"
          :export-disabled="mutating || batchBusy || exportingSub2 || !selectedRows.length"
          :website-disabled="mutating || batchBusy"
          :delete-disabled="mutating || batchBusy || !selectedRows.length"
          :relogin-loading="reloginStarting"
          :pixel-loading="retryingPixel"
          :export-loading="exportingSub2"
          :website-loading="uploadingWebsite"
          :unavailable-loading="settingUnavailable"
          @relogin="startRelogin"
          @restore="mutate('/api/mailboxes/restore', '将选中邮箱恢复为可用状态？')"
          @unavailable="setUnavailable"
          @pixel="retryPixel"
          @export="exportSub2"
          @website="uploadWebsiteMailboxes"
          @delete="mutate('/api/mailboxes/delete', '确定删除选中的邮箱？')"
        />
      </template>

      <div class="table-region">
        <MailboxTable
          ref="mailboxTable"
          :rows="pageRows"
          :loading-passwords="loadingPasswords"
          :loading-totp="loadingTotp"
          :loading-quotas="retryingQuotaRows"
          :quota-retry-disabled="mutating || batchBusy"
          @select="selectedRows = $event"
          @email="copyEmail"
          @password="copyPassword"
          @totp="copyTotp"
          @url="openMailboxUrl"
          @quota="retryQuota"
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

    <MailboxImportDialog
      ref="mailboxImportDialog"
      @busy-change="setImportBusy"
      @imported="applyImportedMailboxes"
    />
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
