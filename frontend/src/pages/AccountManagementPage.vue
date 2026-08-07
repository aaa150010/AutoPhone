<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Refresh, UploadFilled, UserFilled } from '@element-plus/icons-vue'
import {
  getPixelBatchRecords,
  getPixelOverview,
  getPixelUploadBatches,
  retryPixelUpload,
} from '../api/client'
import DashboardMetricCard from '../components/DashboardMetricCard.vue'
import PageToolbar from '../components/PageToolbar.vue'
import PixelBatchOverview from '../components/PixelBatchOverview.vue'
import PixelUploadBatchList from '../components/PixelUploadBatchList.vue'
import PixelUploadRecords from '../components/PixelUploadRecords.vue'
import WorkspacePanel from '../components/WorkspacePanel.vue'
import type {
  PixelOverview,
  PixelUploadBatch,
  PixelUploadRecord,
  PixelUploadTargetRecord,
} from '../types/api'

const overview = ref<PixelOverview>({
  revision: 0,
  queue: {
    configured_workers: 0,
    alive_workers: 0,
    active_workers: 0,
    pending_records: 0,
    running_records: 0,
  },
  current_batch: null,
  batch_count: 0,
  targets: [],
})
const overviewLoading = ref(false)
const batches = ref<PixelUploadBatch[]>([])
const batchesLoading = ref(false)
const batchPage = ref(1)
const batchPageSize = ref(10)
const batchTotal = ref(0)
const selectedBatchId = ref('')
const records = ref<PixelUploadRecord[]>([])
const recordsLoading = ref(false)
const recordPage = ref(1)
const recordPageSize = ref(25)
const recordTotal = ref(0)
const recordStatus = ref('')
const retryingKeys = ref<string[]>([])
const OVERVIEW_REFRESH_INTERVAL_MS = 3000
let overviewTimer = 0
let destroyed = false
let lastRevision = -1
let batchRequest = 0
let recordRequest = 0

const queueActive = computed(() => (
  overview.value.current_batch?.status === 'processing'
  || Number(overview.value.queue.active_workers || 0) > 0
  || Number(overview.value.queue.pending_records || 0) > 0
))
const queueStatusLabel = computed(() => {
  const queue = overview.value.queue
  if (queueActive.value) return `上传中 ${queue.active_workers || 0}/${queue.configured_workers || 0}`
  return `worker ${queue.alive_workers || 0}/${queue.configured_workers || 0}`
})
const targetCards = computed(() => {
  const byId = new Map(overview.value.targets.map(item => [item.target_id, item.account_count]))
  return Array.from({ length: 6 }, (_, index) => {
    const targetId = `pixel-${index + 2}`
    return { targetId, count: byId.get(targetId) ?? null }
  })
})

function first(value: any, ...keys: string[]) {
  for (const key of keys) {
    if (value?.[key] !== undefined && value?.[key] !== null) return value[key]
  }
  return undefined
}

function numberOrNull(value: any) {
  if (value === '' || value == null) return null
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : null
}

function uploadStatus(raw: any) {
  return String(first(raw, 'status', 'state', 'result_status', 'resultStatus') || 'pending')
}

function normalizeUploadTarget(raw: any, fallbackTargetId = '', recordCanRetry = false): PixelUploadTargetRecord {
  const status = uploadStatus(raw)
  const active = ['pending', 'queued', 'waiting', 'uploading', 'importing', 'imported', 'sharing', 'processing', 'retrying']
    .includes(status.toLowerCase())
  const explicitRetry = first(raw, 'retryable', 'can_retry', 'canRetry')
  const generatedNames = first(raw, 'generatedNames', 'generated_names')
  const accountIds = first(raw, 'accountIds', 'account_ids')
  const failure = first(raw, 'failure')
  return {
    targetId: String(first(raw, 'targetId', 'target_id') || fallbackTargetId || '-'),
    status,
    stage: String(first(raw, 'stage', 'target_stage', 'targetStage', 'phase') || ''),
    generatedName: Array.isArray(generatedNames)
      ? generatedNames.map(value => String(value)).join(', ')
      : String(first(raw, 'generatedName', 'generated_name', 'generated_email') || ''),
    remoteAccountId: Array.isArray(accountIds)
      ? accountIds.map(value => String(value)).join(', ') || null
      : first(raw, 'remoteAccountId', 'remote_account_id', 'account_id') ?? null,
    failedIds: (first(raw, 'failedIds', 'failed_ids', 'failed_share_ids') || []).map((value: any) => value),
    concurrency: numberOrNull(first(raw, 'concurrency', 'actual_concurrency')),
    error: String(first(raw, 'error', 'safe_error', 'sanitized_error', 'message') || failure?.public_message || ''),
    attempts: Number(first(raw, 'attempts', 'attempt_count') || 0),
    updatedAt: first(raw, 'updatedAt', 'updated_at', 'last_attempt_at') ?? null,
    retryable: explicitRetry == null
      ? recordCanRetry && ['failed', 'partial', 'retry_pending', 'pending_retry', 'import_failed', 'share_failed', 'source_unavailable'].includes(status.toLowerCase())
      : Boolean(explicitRetry) && !active,
  }
}

function normalizeUploadRecord(raw: any, index: number): PixelUploadRecord {
  const recordId = String(first(raw, 'recordId', 'record_id', 'id') || `record-${index}`)
  const sourceAvailable = first(raw, 'sourceAvailable', 'source_available') !== false
  const canRetry = Boolean(first(raw, 'canRetry', 'can_retry')) && sourceAvailable
  const failure = first(raw, 'failure')
  const recordError = String(first(raw, 'error', 'safe_error', 'sanitized_error', 'message') || failure?.public_message || '')
  const rawTargets = first(raw, 'targets', 'target_records', 'targetRecords', 'destinations', 'results')
  let normalizedTargets: PixelUploadTargetRecord[] = []
  if (Array.isArray(rawTargets)) {
    normalizedTargets = rawTargets.map(target => normalizeUploadTarget(target, '', canRetry))
  } else if (rawTargets && typeof rawTargets === 'object') {
    normalizedTargets = Object.entries(rawTargets).map(([targetId, target]) => (
      normalizeUploadTarget(target, targetId, canRetry)
    ))
  } else if (first(raw, 'targetId', 'target_id')) {
    normalizedTargets = [normalizeUploadTarget(raw, '', canRetry)]
  }
  if (!sourceAvailable) {
    normalizedTargets = normalizedTargets.map(target => ['success', 'complete', 'completed'].includes(String(target.status).toLowerCase())
      ? target
      : { ...target, status: 'source_unavailable', error: target.error || recordError, retryable: false })
  }
  return {
    recordId,
    taskId: String(first(raw, 'taskId', 'task_id') || ''),
    batchId: String(first(raw, 'batchId', 'batch_id') || ''),
    batchStartedAt: first(raw, 'batchStartedAt', 'batch_started_at') ?? null,
    sourceEmail: String(first(raw, 'sourceEmail', 'source_email', 'initial_email') || ''),
    jobId: String(first(raw, 'jobId', 'job_id', 'remote_task_id') || ''),
    status: uploadStatus(raw),
    error: recordError,
    sourceAvailable,
    canRetry,
    createdAt: first(raw, 'createdAt', 'created_at') ?? null,
    updatedAt: first(raw, 'updatedAt', 'updated_at') ?? null,
    targets: normalizedTargets,
  }
}

function messageFor(error: any, fallback: string) {
  return error?.message || fallback
}

function clearOverviewTimer() {
  window.clearTimeout(overviewTimer)
  overviewTimer = 0
}

function scheduleOverviewRefresh() {
  clearOverviewTimer()
  if (destroyed || document.hidden || !queueActive.value) return
  overviewTimer = window.setTimeout(() => { void loadOverview(true) }, OVERVIEW_REFRESH_INTERVAL_MS)
}

async function loadBatches(silent = false) {
  const request = ++batchRequest
  batchesLoading.value = true
  try {
    const payload = await getPixelUploadBatches(batchPage.value, batchPageSize.value)
    if (request !== batchRequest) return
    batches.value = payload.items || []
    batchTotal.value = Number(payload.total || 0)
    batchPage.value = Number(payload.page || batchPage.value)
    const pageBatchIds = new Set(batches.value.map(item => item.batch_id))
    if (!selectedBatchId.value || !pageBatchIds.has(selectedBatchId.value)) {
      const currentBatchId = overview.value.current_batch?.batch_id || ''
      selectedBatchId.value = pageBatchIds.has(currentBatchId)
        ? currentBatchId
        : batches.value[0]?.batch_id || ''
    }
  } catch (error: any) {
    if (!silent) ElMessage.error(messageFor(error, 'Pixel 批次读取失败'))
  } finally {
    if (request === batchRequest) batchesLoading.value = false
  }
}

async function loadRecords(silent = false) {
  if (!selectedBatchId.value) {
    records.value = []
    recordTotal.value = 0
    return
  }
  const request = ++recordRequest
  recordsLoading.value = true
  try {
    const payload = await getPixelBatchRecords(
      selectedBatchId.value,
      recordPage.value,
      recordPageSize.value,
      recordStatus.value,
    )
    if (request !== recordRequest) return
    records.value = (payload.items || []).map(normalizeUploadRecord)
    recordTotal.value = Number(payload.total || 0)
    recordPage.value = Number(payload.page || recordPage.value)
  } catch (error: any) {
    if (!silent) ElMessage.error(messageFor(error, 'Pixel 批次明细读取失败'))
  } finally {
    if (request === recordRequest) recordsLoading.value = false
  }
}

async function refreshPagedData(silent = false) {
  await loadBatches(silent)
  await loadRecords(silent)
}

async function loadOverview(silent = false, force = false) {
  if (overviewLoading.value) return
  overviewLoading.value = true
  try {
    const payload = await getPixelOverview()
    const revisionChanged = lastRevision !== Number(payload.revision)
    overview.value = payload
    if (!selectedBatchId.value && payload.current_batch?.batch_id) {
      selectedBatchId.value = payload.current_batch.batch_id
    }
    if (force || revisionChanged) await refreshPagedData(silent)
    lastRevision = Number(payload.revision)
  } catch (error: any) {
    if (!silent) ElMessage.error(messageFor(error, 'Pixel 运行概览读取失败'))
  } finally {
    overviewLoading.value = false
    scheduleOverviewRefresh()
  }
}

async function selectBatch(row: PixelUploadBatch) {
  if (!row?.batch_id || row.batch_id === selectedBatchId.value) return
  selectedBatchId.value = row.batch_id
  recordPage.value = 1
  recordStatus.value = ''
  await loadRecords()
}

async function changeBatchPage(page: number) {
  batchPage.value = page
  selectedBatchId.value = ''
  recordPage.value = 1
  await loadBatches()
  await loadRecords()
}

async function changeBatchPageSize(size: number) {
  batchPageSize.value = size
  await changeBatchPage(1)
}

async function changeRecordPage(page: number) {
  recordPage.value = page
  await loadRecords()
}

async function changeRecordPageSize(size: number) {
  recordPageSize.value = size
  recordPage.value = 1
  await loadRecords()
}

async function changeRecordStatus(status: string) {
  recordStatus.value = status
  recordPage.value = 1
  await loadRecords()
}

async function retryRecord(recordId: string, targetId?: string) {
  const key = `${recordId}:${targetId || '*'}`
  if (retryingKeys.value.includes(key)) return
  retryingKeys.value = [...retryingKeys.value, key]
  try {
    await retryPixelUpload(recordId, targetId)
    ElMessage.success(targetId ? `${targetId} 已加入重传队列` : '失败目标已加入重传队列')
    await loadOverview(true, true)
  } catch (error: any) {
    ElMessage.error(messageFor(error, '加入重传队列失败'))
  } finally {
    retryingKeys.value = retryingKeys.value.filter(value => value !== key)
  }
}

function handleVisibilityChange() {
  clearOverviewTimer()
  if (!document.hidden && !destroyed) void loadOverview(true)
}

onMounted(() => {
  destroyed = false
  document.addEventListener('visibilitychange', handleVisibilityChange)
  void loadOverview(false, true)
})

onUnmounted(() => {
  destroyed = true
  clearOverviewTimer()
  document.removeEventListener('visibilitychange', handleVisibilityChange)
})
</script>

<template>
  <div class="account-page">
    <PageToolbar title="Pixel 管理" :status="queueStatusLabel" :tone="queueActive ? 'warning' : 'info'">
      <el-tooltip content="刷新 Pixel 概览与当前页" placement="bottom">
        <el-button
          circle
          :icon="Refresh"
          :loading="overviewLoading || batchesLoading || recordsLoading"
          aria-label="刷新 Pixel 概览与当前页"
          @click="loadOverview(false, true)"
        />
      </el-tooltip>
    </PageToolbar>

    <div class="target-total-grid">
      <DashboardMetricCard
        v-for="target in targetCards"
        :key="target.targetId"
        :title="target.targetId"
        :value="target.count == null ? '-' : target.count"
        :icon="UserFilled"
        tone="primary"
        compact
        framed
      />
    </div>

    <PixelBatchOverview :overview="overview" />

    <div class="pixel-workspace">
      <PixelUploadBatchList
        :batches="batches"
        :loading="batchesLoading"
        :page="batchPage"
        :page-size="batchPageSize"
        :total="batchTotal"
        :selected-batch-id="selectedBatchId"
        @select="selectBatch"
        @page="changeBatchPage"
        @page-size="changeBatchPageSize"
      />

      <WorkspacePanel class="records-panel" title="来源记录与目标投递" :icon="UploadFilled" fill body-padding="none">
        <template #actions>
          <el-tooltip v-if="selectedBatchId" :content="selectedBatchId" placement="top">
            <span class="selected-batch">{{ selectedBatchId }}</span>
          </el-tooltip>
          <el-select
            :model-value="recordStatus"
            class="status-filter"
            aria-label="来源记录状态筛选"
            @update:model-value="changeRecordStatus"
          >
            <el-option label="全部状态" value="" />
            <el-option label="失败" value="failed" />
            <el-option label="部分失败" value="partial" />
            <el-option label="待确认" value="needs_confirmation" />
            <el-option label="处理中" value="processing" />
            <el-option label="等待" value="queued" />
            <el-option label="成功" value="success" />
          </el-select>
        </template>
        <div class="record-table-region">
          <PixelUploadRecords
            :records="records"
            :loading="recordsLoading"
            :retrying-keys="retryingKeys"
            @retry="retryRecord"
            @retry-all="retryRecord"
          />
          <el-pagination
            :current-page="recordPage"
            :page-size="recordPageSize"
            class="pager"
            background
            layout="total, sizes, prev, pager, next"
            :page-sizes="[25, 50, 100]"
            :total="recordTotal"
            @update:current-page="changeRecordPage"
            @update:page-size="changeRecordPageSize"
          />
        </div>
      </WorkspacePanel>
    </div>
  </div>
</template>

<style scoped>
.account-page {
  display: grid;
  grid-template-rows: 44px 64px 130px minmax(0, 1fr);
  gap: 6px;
  width: 100%;
  height: 100%;
  min-width: 0;
  min-height: 0;
}
.target-total-grid { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 7px; min-width: 0; }
.target-total-grid :deep(.metric-card.framed) { height: 64px; min-height: 64px; }
.pixel-workspace { display: grid; grid-template-columns: minmax(460px, 38%) minmax(0, 1fr); gap: 6px; min-width: 0; min-height: 0; }
.records-panel { min-width: 0; min-height: 0; }
.record-table-region { display: grid; grid-template-rows: minmax(0, 1fr) 42px; width: 100%; height: 100%; min-height: 0; padding: 7px 8px 0; }
.pager { justify-content: flex-end; min-width: 0; border-top: 1px solid var(--workspace-border); }
.selected-batch { display: block; max-width: 190px; overflow: hidden; color: var(--el-text-color-secondary); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; text-overflow: ellipsis; white-space: nowrap; }
.status-filter { width: 116px; }
</style>
