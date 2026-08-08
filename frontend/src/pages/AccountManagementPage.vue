<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Refresh, UploadFilled, UserFilled } from '@element-plus/icons-vue'
import {
  getBatchUploadManifests,
  getNvOverview,
  getNvUploadBatches,
  getNvUploadRecords,
  getPixelBatchRecords,
  getPixelOverview,
  getPixelUploadBatches,
  retryBatchUploadManifest,
  retryNvUpload,
} from '../api/client'
import DashboardMetricCard from '../components/DashboardMetricCard.vue'
import BatchUploadManifests from '../components/BatchUploadManifests.vue'
import ContentEmptyState from '../components/ContentEmptyState.vue'
import PageToolbar from '../components/PageToolbar.vue'
import NvUploadRecords from '../components/NvUploadRecords.vue'
import PixelBatchOverview from '../components/PixelBatchOverview.vue'
import PixelUploadBatchList from '../components/PixelUploadBatchList.vue'
import PixelUploadRecords from '../components/PixelUploadRecords.vue'
import WorkspacePanel from '../components/WorkspacePanel.vue'
import { usePixelUploadRetry } from '../composables/usePixelUploadRetry'
import type {
  BatchUploadManifest,
  NvOverview,
  NvUploadBatch,
  NvUploadRecord,
  PixelOverview,
  PixelUploadBatch,
  PixelUploadRecord,
  PixelUploadTargetRecord,
} from '../types/api'

const platform = ref<'pixel' | 'nv'>('pixel')

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
const nvOverview = ref<NvOverview>({
  revision: 0,
  configured: false,
  queue: {
    active: 0,
    pending: 0,
    alive: false,
    configured_workers: 1,
    alive_workers: 0,
    active_workers: 0,
    pending_records: 0,
    running_records: 0,
  },
  current_batch: null,
  batch_count: 0,
})
const nvBatches = ref<NvUploadBatch[]>([])
const nvRecords = ref<NvUploadRecord[]>([])
const manifests = ref<BatchUploadManifest[]>([])
const nvLoading = ref(false)
const nvRetryingIds = ref<string[]>([])
const manifestRetryingKeys = ref<string[]>([])
const nvBatchPage = ref(1)
const nvBatchPageSize = ref(20)
const nvBatchTotal = ref(0)
const nvRecordPage = ref(1)
const nvRecordPageSize = ref(50)
const nvRecordTotal = ref(0)
const OVERVIEW_REFRESH_INTERVAL_MS = 3000
let overviewTimer = 0
let destroyed = false
let lastRevision = -1
let batchRequest = 0
let recordRequest = 0
let lastNvRevision = -1
let pendingOverviewRefresh = false

const pixelQueueActive = computed(() => (
  overview.value.current_batch?.status === 'processing'
  || Number(overview.value.queue.active_workers || 0) > 0
  || Number(overview.value.queue.pending_records || 0) > 0
  || manifests.value.some(item => (
    item.targets?.pixel
    && ['waiting', 'queueing'].includes(String(item.platforms?.pixel?.status || '').toLowerCase())
  ))
))
const nvQueueActive = computed(() => (
  nvOverview.value.current_batch?.status === 'processing'
  || Number(nvOverview.value.queue.active_workers ?? nvOverview.value.queue.active ?? 0) > 0
  || Number(nvOverview.value.queue.pending_records ?? nvOverview.value.queue.pending ?? 0) > 0
  || manifests.value.some(item => (
    item.targets?.nv
    && (
      ['waiting', 'collected'].includes(String(item.status || '').toLowerCase())
      || ['waiting', 'queueing'].includes(String(item.platforms?.nv?.status || '').toLowerCase())
    )
  ))
))
const queueActive = computed(() => platform.value === 'pixel' ? pixelQueueActive.value : nvQueueActive.value)
const queueStatusLabel = computed(() => {
  if (platform.value === 'nv') {
    const queue = nvOverview.value.queue
    const active = Number(queue.active_workers ?? queue.active ?? 0)
    const pending = Number(queue.pending_records ?? queue.pending ?? 0)
    const alive = Number(queue.alive_workers ?? (queue.alive ? 1 : 0))
    const configured = Number(queue.configured_workers || 1)
    return nvQueueActive.value
      ? `上传中 ${active} / 等待 ${pending}`
      : `worker ${alive}/${configured}`
  }
  const queue = overview.value.queue
  if (pixelQueueActive.value) return `上传中 ${queue.active_workers || 0}/${queue.configured_workers || 0}`
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

function nvBatchStatusLabel(status: string) {
  const labels: Record<string, string> = {
    processing: '上传中',
    success: '成功',
    partial: '部分接收/需确认',
    failed: '失败',
  }
  return labels[String(status || '').toLowerCase()] || status || '未知'
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
    taskIds: (first(raw, 'taskIds', 'task_ids') || []).map((value: any) => String(value)),
    sourceCount: Number(first(raw, 'sourceCount', 'source_count') || 1),
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
  overviewTimer = window.setTimeout(() => { void refreshActive(true) }, OVERVIEW_REFRESH_INTERVAL_MS)
}

async function loadNv(silent = false, force = false) {
  if (nvLoading.value) return
  nvLoading.value = true
  try {
    const currentOverview = await getNvOverview()
    const revisionChanged = lastNvRevision !== Number(currentOverview.revision)
    nvOverview.value = currentOverview
    const requests: Promise<any>[] = [getBatchUploadManifests()]
    if (force || revisionChanged) {
      requests.push(
        getNvUploadBatches(nvBatchPage.value, nvBatchPageSize.value),
        getNvUploadRecords(nvRecordPage.value, nvRecordPageSize.value),
      )
    }
    const [manifestPayload, batchPayload, recordPayload] = await Promise.all(requests)
    manifests.value = manifestPayload.records || []
    if (batchPayload) {
      nvBatches.value = batchPayload.items || []
      nvBatchTotal.value = Number(batchPayload.total || 0)
      nvBatchPage.value = Number(batchPayload.page || nvBatchPage.value)
    }
    if (recordPayload) {
      nvRecords.value = recordPayload.records || []
      nvRecordTotal.value = Number(recordPayload.total || 0)
      nvRecordPage.value = Number(recordPayload.page || nvRecordPage.value)
    }
    lastNvRevision = Number(currentOverview.revision)
  } catch (error: any) {
    if (!silent) ElMessage.error(messageFor(error, 'NV 上传记录读取失败'))
  } finally {
    nvLoading.value = false
    scheduleOverviewRefresh()
  }
}

async function refreshActive(silent = false, force = false) {
  if (platform.value === 'nv') return loadNv(silent, force)
  return loadOverview(silent, force)
}

async function changePlatform(value: string | number | boolean | undefined) {
  platform.value = value === 'nv' ? 'nv' : 'pixel'
  clearOverviewTimer()
  await refreshActive(false, true)
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
  if (overviewLoading.value) {
    pendingOverviewRefresh ||= force
    return
  }
  overviewLoading.value = true
  try {
    const [payload, manifestPayload] = await Promise.all([
      getPixelOverview(),
      getBatchUploadManifests(),
    ])
    manifests.value = manifestPayload.records || []
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
    if (pendingOverviewRefresh && !destroyed) {
      pendingOverviewRefresh = false
      void loadOverview(true, true)
      return
    }
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

const { retryingKeys, retryRecord, retryBatchTarget } = usePixelUploadRetry(
  () => loadOverview(true, true),
)

async function retryNvRecord(recordId: string) {
  if (nvRetryingIds.value.includes(recordId)) return
  nvRetryingIds.value = [...nvRetryingIds.value, recordId]
  try {
    await retryNvUpload(recordId)
    ElMessage.success('NV 记录已加入重传队列')
    await refreshActive(true, true)
  } catch (error: any) {
    ElMessage.error(messageFor(error, 'NV 重传失败'))
  } finally {
    nvRetryingIds.value = nvRetryingIds.value.filter(value => value !== recordId)
  }
}

async function retryManifest(batchId: string, target: 'pixel' | 'nv') {
  const key = `${batchId}:${target}`
  if (manifestRetryingKeys.value.includes(key)) return
  manifestRetryingKeys.value = [...manifestRetryingKeys.value, key]
  try {
    await retryBatchUploadManifest(batchId, target)
    ElMessage.success(`${target.toUpperCase()} 批次已重新入队`)
    await refreshActive(true, true)
  } catch (error: any) {
    ElMessage.error(messageFor(error, `${target.toUpperCase()} 批次重试失败`))
  } finally {
    manifestRetryingKeys.value = manifestRetryingKeys.value.filter(value => value !== key)
  }
}

async function changeNvBatchPage(page: number) {
  nvBatchPage.value = page
  await loadNv(false, true)
}

async function changeNvBatchPageSize(size: number) {
  nvBatchPageSize.value = size
  nvBatchPage.value = 1
  await loadNv(false, true)
}

async function changeNvRecordPage(page: number) {
  nvRecordPage.value = page
  await loadNv(false, true)
}

async function changeNvRecordPageSize(size: number) {
  nvRecordPageSize.value = size
  nvRecordPage.value = 1
  await loadNv(false, true)
}

function handleVisibilityChange() {
  clearOverviewTimer()
  if (!document.hidden && !destroyed) void refreshActive(true)
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
    <PageToolbar title="账号管理" :status="queueStatusLabel" :tone="queueActive ? 'warning' : 'info'">
      <el-radio-group :model-value="platform" @update:model-value="changePlatform">
        <el-radio-button value="pixel">Pixel</el-radio-button>
        <el-radio-button value="nv">NV</el-radio-button>
      </el-radio-group>
      <el-tooltip content="刷新当前平台上传记录" placement="bottom">
        <el-button
          circle
          :icon="Refresh"
          :loading="overviewLoading || batchesLoading || recordsLoading || nvLoading"
          aria-label="刷新当前平台上传记录"
          @click="refreshActive(false, true)"
        />
      </el-tooltip>
    </PageToolbar>

    <div v-if="platform === 'pixel'" class="target-total-grid">
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

    <PixelBatchOverview v-if="platform === 'pixel'" :overview="overview" />

    <div v-if="platform === 'pixel'" class="pixel-workspace">
      <div class="pixel-left-stack">
        <WorkspacePanel class="manifest-panel" title="批次上传清单" :icon="UploadFilled" fill body-padding="none">
          <BatchUploadManifests
            :records="manifests"
            :loading="overviewLoading"
            :retrying-keys="manifestRetryingKeys"
            @retry="retryManifest"
          />
        </WorkspacePanel>
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
      </div>

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
            @retry-batch="retryBatchTarget"
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

    <div v-else class="nv-workspace">
      <div class="nv-left-stack">
        <WorkspacePanel class="manifest-panel" title="批次上传清单" :icon="UploadFilled" fill body-padding="none">
          <BatchUploadManifests
            :records="manifests"
            :loading="nvLoading"
            :retrying-keys="manifestRetryingKeys"
            @retry="retryManifest"
          />
        </WorkspacePanel>
        <WorkspacePanel class="nv-batches-panel" title="NV 上传批次" :icon="UploadFilled" fill body-padding="none">
          <div class="nv-table-region">
            <el-table v-loading="nvLoading" :data="nvBatches" height="100%" row-key="batch_id" stripe>
              <el-table-column prop="batch_id" label="批次" min-width="190" show-overflow-tooltip />
              <el-table-column label="成功" width="96" align="right">
                <template #default="{ row }">{{ row.source.success }}/{{ row.source.total }}</template>
              </el-table-column>
              <el-table-column label="状态" width="132">
                <template #default="{ row }">{{ nvBatchStatusLabel(row.status) }}</template>
              </el-table-column>
              <template #empty><ContentEmptyState description="暂无 NV 上传批次" /></template>
            </el-table>
            <el-pagination
              :current-page="nvBatchPage"
              :page-size="nvBatchPageSize"
              class="pager"
              background
              layout="total, prev, pager, next"
              :total="nvBatchTotal"
              @update:current-page="changeNvBatchPage"
              @update:page-size="changeNvBatchPageSize"
            />
          </div>
        </WorkspacePanel>
      </div>
      <WorkspacePanel class="nv-records-panel" title="NV 上传记录" :icon="UploadFilled" fill body-padding="none">
        <div class="nv-table-region">
          <NvUploadRecords
            :records="nvRecords"
            :loading="nvLoading"
            :retrying-ids="nvRetryingIds"
            @retry="retryNvRecord"
          />
          <el-pagination
            :current-page="nvRecordPage"
            :page-size="nvRecordPageSize"
            class="pager"
            background
            layout="total, sizes, prev, pager, next"
            :page-sizes="[25, 50, 100]"
            :total="nvRecordTotal"
            @update:current-page="changeNvRecordPage"
            @update:page-size="changeNvRecordPageSize"
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
.pixel-workspace { display: grid; grid-template-columns: minmax(520px, 42%) minmax(0, 1fr); gap: 6px; min-width: 0; min-height: 0; }
.pixel-left-stack,
.nv-left-stack { display: grid; grid-template-rows: minmax(210px, 44%) minmax(0, 1fr); gap: 6px; min-width: 0; min-height: 0; }
.nv-workspace { grid-row: 2 / -1; display: grid; grid-template-columns: minmax(520px, 42%) minmax(0, 1fr); gap: 6px; min-width: 0; min-height: 0; }
.manifest-panel,
.nv-batches-panel,
.nv-records-panel { min-width: 0; min-height: 0; }
.nv-table-region { display: grid; grid-template-rows: minmax(0, 1fr) 42px; width: 100%; height: 100%; min-height: 0; padding: 7px 8px 0; }
.records-panel { min-width: 0; min-height: 0; }
.record-table-region { display: grid; grid-template-rows: minmax(0, 1fr) 42px; width: 100%; height: 100%; min-height: 0; padding: 7px 8px 0; }
.pager { justify-content: flex-end; min-width: 0; border-top: 1px solid var(--workspace-border); }
.selected-batch { display: block; max-width: 190px; overflow: hidden; color: var(--el-text-color-secondary); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; text-overflow: ellipsis; white-space: nowrap; }
.status-filter { width: 116px; }
</style>
