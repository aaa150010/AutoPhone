<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  CircleCheckFilled,
  CircleCloseFilled,
  Collection,
  Message,
  MessageBox,
  Search,
  VideoPlay,
} from '@element-plus/icons-vue'
import { api, ApiError, getMailboxes } from '../api/client'
import DashboardMetricCard from '../components/DashboardMetricCard.vue'
import MailboxTable from '../components/MailboxTable.vue'
import PageToolbar from '../components/PageToolbar.vue'
import WorkspacePanel from '../components/WorkspacePanel.vue'
import { useAppController } from '../composables/useAppController'
import type { LatestCodeValue, MailboxPayload, MailboxRow } from '../types/api'

const controller = useAppController()
const data = ref<MailboxPayload>({ counts: {}, rows: [] })
const importContent = ref('')
const importVisible = ref(false)
const filter = ref('all')
const searchText = ref('')
const selectedRows = ref<MailboxRow[]>([])
const mailboxTable = ref<{ clearSelection: () => void } | null>(null)
const latestCodes = ref<Record<string, LatestCodeValue>>({})
const loadingCodes = ref<string[]>([])
const loadingPasswords = ref<string[]>([])
const currentPage = ref(1)
const pageSize = ref(50)
const mutating = ref(false)
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

const rows = computed(() => data.value.rows.filter((row) => {
  const matchesFilter = filter.value === 'all'
    || (filter.value === 'not_consumed' ? row.status !== 'consumed' : row.status === filter.value)
  const query = searchText.value.trim().toLowerCase()
  const haystack = [
    row.email,
    row.status,
    row.status_label,
    row.task_status,
    row.progress?.label,
    row.error,
    row.reason,
  ].join(' ').toLowerCase()
  return matchesFilter && (!query || haystack.includes(query))
}))

const pageRows = computed(() => rows.value.slice(
  (currentPage.value - 1) * pageSize.value,
  currentPage.value * pageSize.value,
))

watch([filter, searchText, pageSize], () => { currentPage.value = 1 })
watch(() => rows.value.length, (total) => {
  currentPage.value = Math.min(currentPage.value, Math.max(1, Math.ceil(total / pageSize.value)))
})

function applyMailboxPayload(payload: any) {
  const next = payload?.mailboxes || payload
  if (next && Array.isArray(next.rows)) {
    data.value = { ok: next.ok, counts: next.counts || {}, rows: next.rows }
  }
  if (payload?.state) controller.syncState(payload.state)
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
  const lineNumbers = selectedRows.value.map(row => row.line_no)
  try {
    mailboxTable.value?.clearSelection()
    selectedRows.value = []
    const result: any = await api(path, { line_nos: lineNumbers })
    applyMailboxPayload(result)
    if (path.endsWith('/delete')) latestCodes.value = {}
    await nextTick()
    mailboxTable.value?.clearSelection()
    ElMessage.success('操作完成')
  } catch (error: any) {
    ElMessage.error(error?.message || '操作失败')
  } finally {
    mutating.value = false
  }
}

async function code(row: MailboxRow) {
  if (loadingCodes.value.includes(row.row_id)) return
  loadingCodes.value = [...loadingCodes.value, row.row_id]
  try {
    const result: any = await api('/api/mailboxes/latest-code', { line_no: row.line_no })
    latestCodes.value = {
      ...latestCodes.value,
      [row.row_id]: {
        code: String(result.code || ''),
        kind: result.kind,
        message: result.message,
        remaining: result.remaining == null ? undefined : Number(result.remaining),
        receivedAt: Math.floor(Date.now() / 1000),
      },
    }
    ElMessage.success(result.code ? '验证码已获取' : result.message || '未查到验证码')
  } catch (error: any) {
    latestCodes.value = {
      ...latestCodes.value,
      [row.row_id]: { code: '', message: error?.message || '暂无验证码', receivedAt: Math.floor(Date.now() / 1000) },
    }
    ElMessage.error(error?.message || '查码失败')
  } finally {
    loadingCodes.value = loadingCodes.value.filter(id => id !== row.row_id)
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
      <el-button type="primary" @click="importVisible = true"><el-icon><Upload /></el-icon>导入邮箱</el-button>
    </PageToolbar>

    <div class="metric-grid">
      <DashboardMetricCard
        v-for="metric in metricDefinitions"
        :key="metric.key"
        :title="metric.title"
        :value="data.counts[metric.key] || 0"
        :icon="metric.icon"
        :tone="metric.tone"
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
          :latest-codes="latestCodes"
          :loading-codes="loadingCodes"
          :loading-passwords="loadingPasswords"
          @select="selectedRows = $event"
          @code="code"
          @password="copyPassword"
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
        placeholder="邮箱----取码地址&#10;邮箱----密码----client_id----refresh_token&#10;GPT账号--登录密码--2FA密钥（支持连续横线、|、Tab、逗号、分号、冒号）"
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
.table-region { display: grid; grid-template-rows: minmax(0, 1fr) 46px; width: 100%; height: 100%; min-height: 0; padding: 8px 10px 0; }
.pager { justify-content: flex-end; border-top: 1px solid var(--workspace-border); }
</style>
