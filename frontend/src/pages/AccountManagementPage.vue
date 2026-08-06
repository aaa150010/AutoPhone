<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Refresh, UploadFilled } from '@element-plus/icons-vue'
import { getPixelUploadRecords, retryPixelUpload } from '../api/client'
import PageToolbar from '../components/PageToolbar.vue'
import PixelUploadRecords from '../components/PixelUploadRecords.vue'
import WorkspacePanel from '../components/WorkspacePanel.vue'
import type { PixelUploadRecord, PixelUploadTargetRecord } from '../types/api'

const records = ref<PixelUploadRecord[]>([])
const recordsLoading = ref(false)
const retryingKeys = ref<string[]>([])
const RECORDS_REFRESH_INTERVAL_MS = 3000
const RECORDS_AUTO_REFRESH_WINDOW_MS = 15 * 60 * 1000
let recordsTimer = 0
let recordsAutoRefreshDeadline = 0
let destroyed = false

const activeRecords = computed(() => records.value.some(record => record.targets.some(target => (
  ['pending', 'queued', 'waiting', 'uploading', 'importing', 'imported', 'sharing', 'processing', 'retrying']
    .includes(String(target.status).toLowerCase())
))))

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
    error: String(first(raw, 'error', 'safe_error', 'sanitized_error', 'message') || ''),
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
  const recordError = String(first(raw, 'error', 'safe_error', 'sanitized_error', 'message') || '')
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

function restartRecordsAutoRefresh() {
  recordsAutoRefreshDeadline = Date.now() + RECORDS_AUTO_REFRESH_WINDOW_MS
}

function scheduleRecordsRefresh() {
  window.clearTimeout(recordsTimer)
  recordsTimer = 0
  const remaining = recordsAutoRefreshDeadline - Date.now()
  if (destroyed || !activeRecords.value || remaining <= 0) return
  recordsTimer = window.setTimeout(
    () => { void loadRecords(true) },
    Math.min(RECORDS_REFRESH_INTERVAL_MS, remaining),
  )
}

async function loadRecords(silent = false) {
  if (recordsLoading.value) return
  if (!silent) restartRecordsAutoRefresh()
  recordsLoading.value = true
  try {
    const payload: any = await getPixelUploadRecords()
    const source = Array.isArray(payload) ? payload : payload?.records || payload?.items || payload?.data?.records || []
    records.value = source.map(normalizeUploadRecord)
  } catch (error: any) {
    if (!silent) ElMessage.error(messageFor(error, '上传记录读取失败'))
  } finally {
    recordsLoading.value = false
    scheduleRecordsRefresh()
  }
}

async function retryRecord(recordId: string, targetId?: string) {
  const key = `${recordId}:${targetId || '*'}`
  if (retryingKeys.value.includes(key)) return
  retryingKeys.value = [...retryingKeys.value, key]
  try {
    await retryPixelUpload(recordId, targetId)
    ElMessage.success(targetId ? `${targetId} 已加入重传队列` : '失败目标已加入重传队列')
    restartRecordsAutoRefresh()
    await loadRecords(true)
  } catch (error: any) {
    ElMessage.error(messageFor(error, '加入重传队列失败'))
  } finally {
    retryingKeys.value = retryingKeys.value.filter(value => value !== key)
  }
}

onMounted(() => {
  destroyed = false
  void loadRecords()
})

onUnmounted(() => {
  destroyed = true
  window.clearTimeout(recordsTimer)
})
</script>

<template>
  <div class="account-page">
    <PageToolbar title="账号管理" :status="`${records.length} 条上传记录`" tone="info">
      <el-tooltip content="刷新上传记录" placement="bottom">
        <el-button circle :icon="Refresh" :loading="recordsLoading" aria-label="刷新上传记录" @click="loadRecords()" />
      </el-tooltip>
    </PageToolbar>

    <WorkspacePanel class="records-panel" title="Pixel 上传记录" :icon="UploadFilled" fill body-padding="none">
      <PixelUploadRecords
        :records="records"
        :loading="recordsLoading"
        :retrying-keys="retryingKeys"
        @retry="retryRecord"
        @retry-all="retryRecord"
      />
    </WorkspacePanel>
  </div>
</template>

<style scoped>
.account-page { display: grid; grid-template-rows: 44px minmax(0, 1fr); gap: 6px; width: 100%; height: 100%; min-width: 0; min-height: 0; }
.records-panel { min-width: 0; min-height: 0; }
</style>
