<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  Connection,
  DataAnalysis,
  MessageBox,
  Search,
  Upload,
} from '@element-plus/icons-vue'
import {
  api,
  ApiError,
  getMailboxes,
  importWebsiteMailboxes,
  moveMailboxRowsToDraft,
  queryMailboxQuotas,
  reloginMailboxRows,
  restoreMailboxDraftRows,
  setMailboxRowsUnavailable,
} from '../api/client'
import MailboxActionMenus from '../components/MailboxActionMenus.vue'
import MailboxDraftDialog from '../components/MailboxDraftDialog.vue'
import MailboxImportDialog from '../components/MailboxImportDialog.vue'
import MailboxMetrics from '../components/MailboxMetrics.vue'
import MailboxTable from '../components/MailboxTable.vue'
import WorkspacePanel from '../components/WorkspacePanel.vue'
import { useAppController } from '../composables/useAppController'
import { useMailboxBatchOperations } from '../composables/useMailboxBatchOperations'
import { useMailboxExports } from '../composables/useMailboxExports'
import { useMailboxRowActions } from '../composables/useMailboxRowActions'
import type { MailboxOperationKind, MailboxPayload, MailboxRow } from '../types/api'
import {
  latestMailboxBatchId,
  mailboxBatchCandidates,
  mailboxBatchOptions,
  matchesMailboxView,
  needsSub2Rerun,
} from '../utils/mailboxFilters'
import {
  canMoveMailboxRowsToDraft,
  canSetMailboxRowsUnavailable,
  mergeMailboxOperationUpdates,
  mergeMailboxQuotaResults,
} from '../utils/mailboxRows'
import { createMailboxRefreshGuard } from '../utils/mailboxRefreshGuard'

const controller = useAppController()
const data = ref<MailboxPayload>({ counts: {}, rows: [] })
const mailboxImportDialog = ref<InstanceType<typeof MailboxImportDialog>>()
const draftDialogOpen = ref(false)
const filter = ref('all')
const batchFilter = ref('all')
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
const uploadingWebsite = ref(false)
const settingUnavailable = ref(false)
const settingDraft = ref(false)
const restoringDraft = ref(false)
const retryingQuotaRows = ref<string[]>([])
const retryingOpenAIRows = ref<string[]>([])
const rowActionLoading = ref<string[]>([])
const refreshGuard = createMailboxRefreshGuard()
let timer = 0
let pollingStopped = false

const latestBatchId = computed(() => latestMailboxBatchId(data.value.rows))
const batchOptions = computed(() => mailboxBatchOptions(data.value.rows))
const draftRows = computed(() => data.value.rows.filter(row => row.status === 'draft'))

const rows = computed(() => data.value.rows.filter(row => matchesMailboxView(row, {
  status: filter.value,
  batchId: batchFilter.value,
  sub2: sub2Filter.value,
  quota: quotaFilter.value,
  search: searchText.value,
  latestBatchId: latestBatchId.value,
})))

const pageRows = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  return rows.value
    .slice(start, currentPage.value * pageSize.value)
    .map((row, index) => ({ ...row, display_index: start + index + 1 }))
})

function clearMainSelection() {
  mailboxTable.value?.clearSelection()
  selectedRows.value = []
}

watch([filter, batchFilter, sub2Filter, quotaFilter], () => {
  currentPage.value = 1
  clearMainSelection()
})
watch(batchOptions, (options) => {
  if (batchFilter.value !== 'all' && !options.some(item => item.batchId === batchFilter.value)) {
    batchFilter.value = 'all'
  }
})
watch([searchText, pageSize], () => { currentPage.value = 1 })
watch(() => rows.value.length, (total) => {
  currentPage.value = Math.min(currentPage.value, Math.max(1, Math.ceil(total / pageSize.value)))
})

function applyMetricFilter(value: string) {
  draftDialogOpen.value = false
  filter.value = value
  sub2Filter.value = 'all'
  quotaFilter.value = 'all'
  clearMainSelection()
}

function openDraftDialog() {
  clearMainSelection()
  draftDialogOpen.value = true
}

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

function batchCandidates(kind: MailboxOperationKind) {
  return mailboxBatchCandidates(data.value.rows, kind)
}

function scheduleMailboxPoll(delay: number) {
  if (pollingStopped) return
  window.clearTimeout(timer)
  timer = window.setTimeout(poll, delay)
}

const mailboxBatch = useMailboxBatchOperations({
  candidates: batchCandidates,
  clearSelection: () => {
    mailboxTable.value?.clearSelection()
    selectedRows.value = []
  },
  onStarted: () => {
    refreshGuard.invalidate()
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
  testOpenAIRows,
} = mailboxBatch
const {
  copyEmail,
  copyPassword,
  copyTotp,
  handleRowAction,
  openMailboxUrl,
  copyLatestCode,
} = useMailboxRowActions({
  loadingPasswords,
  loadingTotp,
  rowActionLoading,
  mutating,
  batchBusy,
  refreshGuard,
  refresh,
  applyMailboxPayload,
  scheduleMailboxPoll,
})
const {
  exportingSource,
  exportingSub2,
  exportSource,
  exportSub2,
} = useMailboxExports({ selectedRows, refresh })

async function retryQuota(row: MailboxRow) {
  if (row.quota_status !== 'error' || mutating.value || batchBusy.value || retryingQuotaRows.value.includes(row.row_id)) return
  retryingQuotaRows.value = [...retryingQuotaRows.value, row.row_id]
  mutating.value = true
  refreshGuard.invalidate()
  try {
    const result = await queryMailboxQuotas([{ row_id: row.row_id, line_no: row.line_no }])
    if (Number(result.deactivated_deleted || 0) > 0) {
      applyMailboxPayload(await getMailboxes())
      ElMessage.warning('OpenAI 工作空间已停用，已删除本地邮箱')
      return
    }
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

async function retryOpenAI(row: MailboxRow) {
  if (mutating.value || batchBusy.value || retryingOpenAIRows.value.includes(row.row_id)) return
  retryingOpenAIRows.value = [...retryingOpenAIRows.value, row.row_id]
  const started = await testOpenAIRows([{ row_id: row.row_id, line_no: row.line_no }])
  if (!started) {
    retryingOpenAIRows.value = retryingOpenAIRows.value.filter(id => id !== row.row_id)
    return
  }
  ElMessage.info('已开始重新查询 OpenAI 状态')
}

watch(() => mailboxBatch.operation.value?.status, (status) => {
  if (status && status !== 'running') retryingOpenAIRows.value = []
})

async function refresh() {
  if (mutating.value) return
  const ticket = refreshGuard.begin()
  try {
    const result = await getMailboxes()
    if (!mutating.value && refreshGuard.accepts(ticket)) applyMailboxPayload(result)
  } catch (error: any) {
    if (refreshGuard.accepts(ticket)) ElMessage.error(error?.message || '邮箱列表刷新失败')
  }
}

function setImportBusy(value: boolean) {
  if (value) refreshGuard.invalidate()
  mutating.value = value
}

function applyImportedMailboxes(result: any) {
  const hasMailboxSnapshot = Array.isArray(result?.mailboxes?.rows)
  if (hasMailboxSnapshot) applyMailboxPayload(result)
  currentPage.value = 1
  void controller.refresh()
  if (!hasMailboxSnapshot || result?.mailboxes_refresh_required) {
    window.setTimeout(() => {
      if (!pollingStopped) void refresh()
    }, 0)
  }
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
  refreshGuard.invalidate()
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
    if (error instanceof ApiError && error.status === 409) window.setTimeout(() => void refresh(), 0)
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

async function moveToDraft() {
  settingDraft.value = true
  try {
    await mutate(
      '',
      '将选中的邮箱放入草稿箱？放入后不会参与运行。',
      moveMailboxRowsToDraft,
      result => `已放入草稿箱 ${Number(result?.drafted || 0)} 条`,
    )
  } finally {
    settingDraft.value = false
  }
}

async function restoreDraftRows(rows: Array<{ row_id: string; line_no: number }>) {
  if (!rows.length || mutating.value || batchBusy.value) return
  restoringDraft.value = true
  mutating.value = true
  refreshGuard.invalidate()
  try {
    const result = await restoreMailboxDraftRows(rows)
    applyMailboxPayload(result)
    await nextTick()
    ElMessage.success(`已放回可用 ${Number(result.restored || 0)} 条`)
  } catch (error: any) {
    if (error instanceof ApiError && error.status === 409) window.setTimeout(() => void refresh(), 0)
    ElMessage.error(error?.message || '草稿邮箱放回可用失败')
  } finally {
    restoringDraft.value = false
    mutating.value = false
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
  refreshGuard.invalidate()
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
    <MailboxMetrics
      :counts="data.counts"
      :active-filter="filter"
      :draft-open="draftDialogOpen"
      @filter="applyMetricFilter"
      @draft="openDraftDialog"
    />

    <WorkspacePanel title="邮箱状态" :icon="MessageBox" fill body-padding="none">
      <template #actions>
        <span v-if="selectedRows.length" class="selected-count">已选 {{ selectedRows.length }}</span>
      </template>

      <div class="mailbox-toolbar">
        <div class="toolbar-section filter-row">
          <span class="toolbar-label">筛选</span>
          <el-input v-model="searchText" size="small" class="search-input" clearable placeholder="搜索邮箱、状态、说明" :prefix-icon="Search" />
          <el-select v-model="filter" size="small" class="filter-select">
          <el-option label="全部" value="all" />
          <el-option label="最近运行批次" value="latest_batch" />
          <el-option label="最近运行批次失败" value="latest_batch_failed" />
          <el-option label="未使用" value="not_consumed" />
          <el-option label="可用" value="available" />
          <el-option label="运行中" value="running" />
          <el-option label="已使用" value="consumed" />
          <el-option label="失败" value="failed" />
          </el-select>
          <el-select v-model="batchFilter" size="small" class="batch-filter-select" filterable>
          <el-option label="全部批次" value="all" />
          <el-option v-for="batch in batchOptions" :key="batch.batchId" :label="batch.batchId" :value="batch.batchId" />
          </el-select>
          <el-select v-model="sub2Filter" size="small" class="sub2-filter-select">
          <el-option label="全部 OpenAI" value="all" />
          <el-option label="OpenAI 测试失败" value="test_failure" />
          <el-option label="OpenAI 401/404（需重试）" value="needs_rerun" />
          <el-option label="网络断开" value="network_disconnected" />
          <el-option label="HTTP 400" value="http_400" />
          </el-select>
          <el-select v-model="quotaFilter" size="small" class="quota-filter-select">
          <el-option label="全部额度" value="all" />
          <el-option label="有剩余额度" value="remaining" />
          <el-option label="已查询额度" value="queried" />
          </el-select>
        </div>
        <div class="toolbar-section action-row">
          <span class="toolbar-label">批量操作</span>
          <el-tooltip content="导入邮箱" placement="top"><el-button size="small" type="primary" :disabled="mutating || batchBusy" :icon="Upload" aria-label="导入邮箱" @click="mailboxImportDialog?.open()" /></el-tooltip>
          <el-button size="small" :loading="queryingQuota" :disabled="mutating || batchBusy" @click="queryQuotas">
            <el-icon><DataAnalysis /></el-icon>{{ queryingQuota && quotaProgress ? `查询额度 ${quotaProgress}` : '批量查询额度' }}
          </el-button>
          <el-button size="small" :loading="testingSub2" :disabled="mutating || batchBusy" @click="testSub2">
            <el-icon><Connection /></el-icon>{{ testingSub2 && openaiTestProgress ? `测试 OpenAI ${openaiTestProgress}` : '批量测试 OpenAI' }}
          </el-button>
          <MailboxActionMenus
          :relogin-disabled="mutating || batchBusy || controller.runtime.value.running || !selectedRows.length || selectedRows.some(row => !needsSub2Rerun(row.sub2_status))"
          :restore-disabled="mutating || batchBusy || !selectedRows.length"
          :draft-disabled="mutating || batchBusy || !canMoveMailboxRowsToDraft(selectedRows)"
          :unavailable-disabled="mutating || batchBusy || !canSetMailboxRowsUnavailable(selectedRows)"
          :export-disabled="mutating || batchBusy || exportingSub2 || !selectedRows.length"
          :source-export-disabled="mutating || batchBusy || exportingSource || !selectedRows.length"
          :website-disabled="mutating || batchBusy"
          :delete-disabled="mutating || batchBusy || !selectedRows.length"
          :relogin-loading="reloginStarting"
          :export-loading="exportingSub2"
          :source-export-loading="exportingSource"
          :website-loading="uploadingWebsite"
          :unavailable-loading="settingUnavailable"
          :draft-loading="settingDraft"
          @relogin="startRelogin"
          @restore="mutate('/api/mailboxes/restore', '将选中邮箱恢复为可用状态？')"
          @draft="moveToDraft"
          @unavailable="setUnavailable"
          @export="exportSub2"
          @source-export="exportSource"
          @website="uploadWebsiteMailboxes"
          @delete="mutate('/api/mailboxes/delete', '确定删除选中的邮箱？')"
          />
        </div>
      </div>

      <div class="table-region">
        <MailboxTable
          ref="mailboxTable"
          :rows="pageRows"
          :loading-passwords="loadingPasswords"
          :loading-totp="loadingTotp"
          :loading-quotas="retryingQuotaRows"
          :loadingOpenAI="retryingOpenAIRows"
          :quota-retry-disabled="mutating || batchBusy"
          :openaiRetryDisabled="mutating || batchBusy"
          :row-mutation-disabled="mutating || batchBusy"
          :row-action-loading="rowActionLoading"
          @select="selectedRows = $event"
          @email="copyEmail"
          @password="copyPassword"
          @totp="copyTotp"
          @url="openMailboxUrl"
          @latest-code="copyLatestCode"
          @quota="retryQuota"
          @openai="retryOpenAI"
          @action="handleRowAction"
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
    <MailboxDraftDialog
      v-model="draftDialogOpen"
      :rows="draftRows"
      :disabled="mutating || batchBusy"
      :restoring="restoringDraft"
      @restore="restoreDraftRows"
    />
  </div>
</template>

<style scoped>
.mailbox-page { display: grid; grid-template-rows: 52px minmax(0, 1fr); gap: 6px; width: 100%; height: 100%; min-width: 0; min-height: 0; }
.mailbox-page :deep(.workspace-panel > .el-card__body) { display: flex; flex-direction: column; min-height: 0; }
.selected-count { color: var(--el-color-primary); font-size: 13px; white-space: nowrap; }
.mailbox-toolbar { display: grid; grid-template-rows: auto auto; gap: 6px; flex: 0 0 auto; padding: 8px 10px; border-bottom: 1px solid var(--workspace-border); background: #fbfcfd; }
.toolbar-section { display: flex; align-items: center; flex-wrap: wrap; gap: 6px; min-width: 0; }
.toolbar-label { flex: 0 0 52px; color: var(--el-text-color-secondary); font-size: 12px; font-weight: 650; }
.search-input { width: 220px; }
.filter-select { width: 140px; }
.batch-filter-select { width: 170px; }
.sub2-filter-select { width: 180px; }
.quota-filter-select { width: 145px; }
.mailbox-toolbar :deep(.el-input__wrapper), .mailbox-toolbar :deep(.el-select__wrapper), .mailbox-toolbar :deep(.el-button) { min-height: 30px; height: 30px; }
.action-row :deep(.mailbox-action-menus) { gap: 6px; }
.action-row :deep(.mailbox-action-menus .el-button) { min-height: 30px; height: 30px; }
.table-region { display: grid; grid-template-rows: minmax(0, 1fr) 46px; flex: 1 1 auto; width: 100%; height: 100%; min-height: 0; padding: 8px 10px 0; }
.pager { justify-content: flex-end; border-top: 1px solid var(--workspace-border); }

</style>
