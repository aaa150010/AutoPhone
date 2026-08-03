<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  Connection,
  Key,
  Refresh,
  Search,
  Share,
  Tickets,
  UploadFilled,
  UserFilled,
} from '@element-plus/icons-vue'
import {
  getPixelAccounts,
  getPixelTargets,
  getPixelUploadRecords,
  reloginPixelTarget,
  retryPixelUpload,
  shareAllPixelAccounts,
  sharePixelAccounts,
  testPixelAccounts,
} from '../api/client'
import PageToolbar from '../components/PageToolbar.vue'
import PixelAccountTable from '../components/PixelAccountTable.vue'
import PixelTargetList from '../components/PixelTargetList.vue'
import PixelUploadRecords from '../components/PixelUploadRecords.vue'
import WorkspacePanel from '../components/WorkspacePanel.vue'
import type {
  PixelAccount,
  PixelAccountPage,
  PixelTarget,
  PixelUploadRecord,
  PixelUploadTargetRecord,
} from '../types/api'

const targets = ref<PixelTarget[]>([])
const activeTargetId = ref('')
const targetsLoading = ref(false)
const accounts = ref<PixelAccountPage>({ items: [], total: 0, page: 1, pageSize: 50, pages: 0 })
const accountsLoading = ref(false)
const selectedAccounts = ref<PixelAccount[]>([])
const accountTable = ref<{ clearSelection: () => void } | null>(null)
const page = ref(1)
const pageSize = ref(50)
const searchInput = ref('')
const search = ref('')
const statusFilter = ref('')
const accountAction = ref('')
const records = ref<PixelUploadRecord[]>([])
const recordsLoading = ref(false)
const retryingKeys = ref<string[]>([])
const sharingAll = ref(false)
let accountsRequest = 0
let searchTimer = 0
let recordsTimer = 0
let destroyed = false

const visibleTargetIds = new Set(['pixel-2', 'pixel-3', 'pixel-4', 'pixel-5', 'pixel-6', 'pixel-7'])

const activeTarget = computed(() => targets.value.find(target => target.id === activeTargetId.value) || null)
const automaticTargetIds = computed(() => targets.value.filter(target => target.autoUpload).map(target => target.id))
const platformBusy = computed(() => Boolean(accountAction.value) || sharingAll.value || targetsLoading.value)
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

function normalizeTarget(raw: any): PixelTarget {
  const id = String(first(raw, 'id', 'target_id', 'targetId') || '').trim()
  const email = String(first(raw, 'email', 'login_email', 'loginEmail') || '').trim()
  const excluded = Boolean(first(raw, 'excluded', 'auto_upload_excluded', 'autoUploadExcluded'))
    || id.toLowerCase() === 'pixel-1'
  const configuredAutoUpload = first(raw, 'autoUpload', 'auto_upload', 'auto_upload_enabled')
  return {
    id,
    email,
    connected: Boolean(first(raw, 'connected', 'is_connected', 'isConnected')),
    accountCount: numberOrNull(first(raw, 'accountCount', 'account_count', 'total')),
    lastCheckedAt: first(raw, 'lastCheckedAt', 'last_checked_at') || null,
    error: String(first(raw, 'error', 'last_error', 'lastError') || '') || null,
    autoUpload: configuredAutoUpload == null ? !excluded : Boolean(configuredAutoUpload) && !excluded,
  }
}

function normalizeAccount(raw: any): PixelAccount | null {
  const id = Number(first(raw, 'id', 'account_id', 'accountId'))
  if (!Number.isFinite(id)) return null
  return {
    id,
    name: String(first(raw, 'name', 'email', 'account_name', 'accountName') || ''),
    platform: String(first(raw, 'platform') || ''),
    accountLevel: String(first(raw, 'accountLevel', 'account_level', 'plan_type') || ''),
    type: String(first(raw, 'type', 'account_type') || ''),
    shareMode: String(first(raw, 'shareMode', 'share_mode') || ''),
    shareStatus: String(first(raw, 'shareStatus', 'share_status') || ''),
    concurrency: Number(first(raw, 'concurrency') || 0),
    currentConcurrency: Number(first(raw, 'currentConcurrency', 'current_concurrency') || 0),
    status: String(first(raw, 'status') || ''),
    schedulable: Boolean(first(raw, 'schedulable', 'is_schedulable', 'isSchedulable')),
    credentialsStatus: String(first(raw, 'credentialsStatus', 'credentials_status') || ''),
    errorMessage: String(first(raw, 'errorMessage', 'error_message', 'error') || ''),
    expiresAt: first(raw, 'expiresAt', 'expires_at') || null,
    updatedAt: first(raw, 'updatedAt', 'updated_at') || null,
  }
}

function normalizeAccountPage(payload: any): PixelAccountPage {
  const source = payload?.data && Array.isArray(payload.data.items) ? payload.data : payload
  const items = (source?.items || source?.accounts || []).map(normalizeAccount).filter(Boolean) as PixelAccount[]
  const total = Number(source?.total ?? items.length) || 0
  const normalizedPageSize = Number(source?.pageSize ?? source?.page_size ?? pageSize.value) || pageSize.value
  return {
    items,
    total,
    page: Number(source?.page ?? page.value) || page.value,
    pageSize: normalizedPageSize,
    pages: Number(source?.pages ?? Math.ceil(total / normalizedPageSize)) || 0,
    target: source?.target ? normalizeTarget(source.target) : undefined,
  }
}

function uploadStatus(raw: any) {
  return String(first(raw, 'status', 'state', 'result_status', 'resultStatus') || 'pending')
}

function normalizeUploadTarget(raw: any, fallbackTargetId = '', recordCanRetry = false): PixelUploadTargetRecord {
  const status = uploadStatus(raw)
  const active = ['pending', 'queued', 'importing'].includes(status.toLowerCase())
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
  const status = sourceAvailable ? uploadStatus(raw) : 'source_unavailable'
  return {
    recordId,
    taskId: String(first(raw, 'taskId', 'task_id') || ''),
    jobId: String(first(raw, 'jobId', 'job_id', 'remote_task_id') || ''),
    status,
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

async function loadTargets(probe = false) {
  targetsLoading.value = true
  try {
    const payload: any = await getPixelTargets()
    const source = Array.isArray(payload) ? payload : payload?.targets || payload?.data?.targets || payload?.items || []
    let normalized = source
      .map(normalizeTarget)
      .filter((target: PixelTarget) => visibleTargetIds.has(target.id.toLowerCase()))
    if (probe && normalized.length) {
      const checks = await Promise.all(normalized.map(async (target: PixelTarget) => {
        try {
          const accountPayload = await getPixelAccounts(target.id, 1, 1)
          return { id: target.id, page: normalizeAccountPage(accountPayload), error: '' }
        } catch (error: any) {
          return { id: target.id, page: null, error: messageFor(error, '连接失败') }
        }
      }))
      const checkById = new Map(checks.map(check => [check.id, check]))
      normalized = normalized.map((target: PixelTarget) => {
        const check = checkById.get(target.id)
        return check?.page
          ? { ...target, connected: true, accountCount: check.page.total, lastCheckedAt: new Date().toISOString(), error: null }
          : { ...target, connected: false, lastCheckedAt: new Date().toISOString(), error: check?.error || target.error }
      })
      const failed = checks.filter(check => !check.page).length
      if (failed) ElMessage.warning(`Pixel 目标已刷新，${failed} 个连接失败`)
      else ElMessage.success('Pixel 目标已刷新')
    }
    targets.value = normalized
    if (!normalized.some((target: PixelTarget) => target.id === activeTargetId.value)) {
      activeTargetId.value = normalized[0]?.id || ''
    }
  } catch (error: any) {
    ElMessage.error(messageFor(error, 'Pixel 目标读取失败'))
  } finally {
    targetsLoading.value = false
  }
}

async function loadAccounts() {
  if (!activeTargetId.value) {
    accounts.value = { items: [], total: 0, page: 1, pageSize: pageSize.value, pages: 0 }
    return
  }
  const request = ++accountsRequest
  accountsLoading.value = true
  accountTable.value?.clearSelection()
  selectedAccounts.value = []
  try {
    const payload = await getPixelAccounts(activeTargetId.value, page.value, pageSize.value, search.value, statusFilter.value)
    if (request !== accountsRequest) return
    const normalized = normalizeAccountPage(payload)
    accounts.value = normalized
    targets.value = targets.value.map(target => target.id === activeTargetId.value
      ? {
          ...target,
          connected: true,
          accountCount: search.value || statusFilter.value ? target.accountCount : normalized.total,
          lastCheckedAt: new Date().toISOString(),
          error: null,
        }
      : target)
  } catch (error: any) {
    if (request !== accountsRequest) return
    accounts.value = { items: [], total: 0, page: page.value, pageSize: pageSize.value, pages: 0 }
    targets.value = targets.value.map(target => target.id === activeTargetId.value
      ? { ...target, connected: false, lastCheckedAt: new Date().toISOString(), error: messageFor(error, '连接失败') }
      : target)
    ElMessage.error(messageFor(error, 'Pixel 账号读取失败'))
  } finally {
    if (request === accountsRequest) accountsLoading.value = false
  }
}

function scheduleRecordsRefresh() {
  window.clearTimeout(recordsTimer)
  if (!destroyed && activeRecords.value) recordsTimer = window.setTimeout(() => { void loadRecords(true) }, 3000)
}

async function loadRecords(silent = false) {
  if (recordsLoading.value) return
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

function selectTarget(targetId: string) {
  if (targetId === activeTargetId.value) return
  page.value = 1
  activeTargetId.value = targetId
}

async function bulkTest() {
  if (!selectedAccounts.value.length || !activeTargetId.value) return
  accountAction.value = 'test'
  const ids = selectedAccounts.value.map(account => account.id)
  try {
    accountTable.value?.clearSelection()
    selectedAccounts.value = []
    const result = await testPixelAccounts(activeTargetId.value, ids)
    const failed = Number(result.failed || result.failedIds?.length || 0)
    if (failed) ElMessage.warning(`连接测试完成，${failed} 个账号失败`)
    else ElMessage.success(`连接测试完成，${Number(result.success || ids.length)} 个账号正常`)
    await loadAccounts()
  } catch (error: any) {
    ElMessage.error(messageFor(error, '批量连接测试失败'))
  } finally {
    accountAction.value = ''
  }
}

async function bulkShare() {
  if (!selectedAccounts.value.length || !activeTargetId.value) return
  try {
    await ElMessageBox.confirm(
      `将选中的 ${selectedAccounts.value.length} 个账号设为公开共享，并分别随机设置 3–10 并发？`,
      '批量公开共享',
      { type: 'warning', confirmButtonText: '确认共享', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  accountAction.value = 'share'
  const ids = selectedAccounts.value.map(account => account.id)
  try {
    accountTable.value?.clearSelection()
    selectedAccounts.value = []
    const result = await sharePixelAccounts(activeTargetId.value, ids)
    const failed = Number(result.failed || result.failedIds?.length || 0)
    if (failed) ElMessage.warning(`公开共享完成，${failed} 个账号失败`)
    else ElMessage.success(`已公开共享 ${Number(result.success || ids.length)} 个账号`)
    await loadAccounts()
  } catch (error: any) {
    ElMessage.error(messageFor(error, '批量公开共享失败'))
  } finally {
    accountAction.value = ''
  }
}

async function relogin() {
  if (!activeTargetId.value) return
  accountAction.value = 'relogin'
  try {
    await reloginPixelTarget(activeTargetId.value)
    ElMessage.success(`${activeTargetId.value} 已重新授权`)
    await Promise.all([loadTargets(), loadAccounts()])
  } catch (error: any) {
    ElMessage.error(messageFor(error, '重新授权失败'))
  } finally {
    accountAction.value = ''
  }
}

async function shareAll() {
  if (!automaticTargetIds.value.length) {
    ElMessage.warning('没有可执行一键共享的自动上传目标')
    return
  }
  try {
    await ElMessageBox.confirm(
      `扫描 ${automaticTargetIds.value.length} 个自动上传目标的全部账号，并分别随机设置 3–10 并发及公开共享？`,
      '一键公开共享',
      { type: 'warning', confirmButtonText: '开始共享', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  sharingAll.value = true
  try {
    const result: any = await shareAllPixelAccounts(automaticTargetIds.value)
    const failed = Number(result.failed || 0)
    const shared = Number(result.shared || result.success || 0)
    if (failed || result.status === 'partial' || result.status === 'failed') {
      ElMessage.warning(`一键共享完成：成功 ${shared}，失败 ${failed}`)
    } else {
      ElMessage.success(`一键共享完成：成功 ${shared}`)
    }
    await Promise.all([loadTargets(), loadAccounts()])
  } catch (error: any) {
    ElMessage.error(messageFor(error, '一键公开共享失败'))
  } finally {
    sharingAll.value = false
  }
}

async function retryRecord(recordId: string, targetId?: string) {
  const key = `${recordId}:${targetId || '*'}`
  if (retryingKeys.value.includes(key)) return
  retryingKeys.value = [...retryingKeys.value, key]
  try {
    await retryPixelUpload(recordId, targetId)
    ElMessage.success(targetId ? `${targetId} 已加入重传队列` : '失败目标已加入重传队列')
    await loadRecords(true)
  } catch (error: any) {
    ElMessage.error(messageFor(error, '加入重传队列失败'))
  } finally {
    retryingKeys.value = retryingKeys.value.filter(value => value !== key)
  }
}

watch(searchInput, (value) => {
  window.clearTimeout(searchTimer)
  searchTimer = window.setTimeout(() => {
    search.value = value.trim()
    page.value = 1
  }, 300)
})

watch([activeTargetId, page, pageSize, statusFilter, search], () => {
  void nextTick(loadAccounts)
})

onMounted(async () => {
  destroyed = false
  await Promise.allSettled([loadTargets(), loadRecords()])
})

onUnmounted(() => {
  destroyed = true
  accountsRequest += 1
  window.clearTimeout(searchTimer)
  window.clearTimeout(recordsTimer)
})
</script>

<template>
  <div class="account-page">
    <PageToolbar title="账号管理" :status="`${targets.length} 个 Pixel 目标`" tone="info">
      <el-tooltip content="刷新六个平台连接和账号数" placement="bottom">
        <el-button circle :icon="Refresh" :loading="targetsLoading" :disabled="platformBusy" aria-label="刷新平台状态" @click="loadTargets(true)" />
      </el-tooltip>
      <el-button :icon="Key" :loading="accountAction === 'relogin'" :disabled="!activeTargetId || platformBusy" @click="relogin">
        重新授权
      </el-button>
      <el-button type="primary" :icon="Share" :loading="sharingAll" :disabled="!automaticTargetIds.length || platformBusy" @click="shareAll">
        六平台一键共享
      </el-button>
    </PageToolbar>

    <div class="account-grid">
      <WorkspacePanel class="target-panel" title="Pixel 目标" :icon="UserFilled" fill body-padding="none">
        <PixelTargetList :targets="targets" :active-id="activeTargetId" :loading="targetsLoading" :disabled="platformBusy" @select="selectTarget" />
      </WorkspacePanel>

      <WorkspacePanel
        class="accounts-panel"
        :title="activeTarget ? `${activeTarget.id} 账号` : '平台账号'"
        :icon="Tickets"
        fill
        body-padding="none"
      >
        <template #actions>
          <span v-if="selectedAccounts.length" class="selected-count">已选 {{ selectedAccounts.length }}</span>
          <el-input v-model="searchInput" class="account-search" clearable placeholder="搜索账号名" :prefix-icon="Search" :disabled="platformBusy" />
          <el-select v-model="statusFilter" class="status-filter" :disabled="platformBusy">
            <el-option label="全部状态" value="" />
            <el-option label="正常" value="active" />
            <el-option label="额度受限" value="rate_limited" />
            <el-option label="配额保护" value="codex_quota_protected" />
            <el-option label="异常" value="error" />
          </el-select>
          <el-button :icon="Connection" :loading="accountAction === 'test'" :disabled="platformBusy || !selectedAccounts.length" @click="bulkTest">
            批量测试
          </el-button>
          <el-button type="primary" plain :icon="Share" :loading="accountAction === 'share'" :disabled="platformBusy || !selectedAccounts.length" @click="bulkShare">
            公开共享
          </el-button>
        </template>
        <div class="account-table-region">
          <PixelAccountTable
            ref="accountTable"
            :rows="accounts.items"
            :loading="accountsLoading"
            :selection-disabled="platformBusy"
            @select="selectedAccounts = $event"
          />
          <el-pagination
            v-model:current-page="page"
            v-model:page-size="pageSize"
            class="pager"
            background
            :disabled="platformBusy"
            layout="total, sizes, prev, pager, next"
            :page-sizes="[25, 50, 100]"
            :total="accounts.total"
          />
        </div>
      </WorkspacePanel>

      <WorkspacePanel class="records-panel" title="Pixel 上传记录" :icon="UploadFilled" fill body-padding="none">
        <template #actions>
          <el-tooltip content="刷新上传记录" placement="top">
            <el-button circle :icon="Refresh" :loading="recordsLoading" aria-label="刷新上传记录" @click="loadRecords()" />
          </el-tooltip>
        </template>
        <PixelUploadRecords
          :records="records"
          :loading="recordsLoading"
          :retrying-keys="retryingKeys"
          @retry="retryRecord"
          @retry-all="retryRecord"
        />
      </WorkspacePanel>
    </div>
  </div>
</template>

<style scoped>
.account-page { display: grid; grid-template-rows: 44px minmax(0, 1fr); gap: 6px; width: 100%; height: 100%; min-width: 0; min-height: 0; }
.account-grid { display: grid; grid-template-columns: 226px minmax(0, 1fr); grid-template-rows: minmax(280px, 1.15fr) minmax(210px, .85fr); gap: 6px; min-width: 0; min-height: 0; }
.target-panel { grid-row: 1 / span 2; }
.accounts-panel,
.records-panel { min-width: 0; min-height: 0; }
.selected-count { color: var(--el-color-primary); font-size: 12px; white-space: nowrap; }
.account-search { width: 175px; }
.status-filter { width: 116px; }
.account-table-region { display: grid; grid-template-rows: minmax(0, 1fr) 42px; width: 100%; height: 100%; min-height: 0; padding: 7px 9px 0; }
.pager { justify-content: flex-end; border-top: 1px solid var(--workspace-border); }

@media (max-width: 1380px) {
  .account-grid { grid-template-columns: 208px minmax(0, 1fr); }
  .account-search { width: 145px; }
}
</style>
