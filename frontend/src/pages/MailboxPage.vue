<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { CircleCheckFilled, CircleCloseFilled, Message } from '@element-plus/icons-vue'
import { api, getMailboxes } from '../api/client'
import DashboardMetricCard from '../components/DashboardMetricCard.vue'
import MailboxTable from '../components/MailboxTable.vue'
import type { MailboxPayload } from '../types/api'

const data = ref<MailboxPayload>({ counts: {}, rows: [] })
const content = ref('')
const filter = ref('all')
const searchText = ref('')
const selected = ref<number[]>([])
const mailboxTable = ref<{ clearSelection: () => void } | null>(null)
const latestCodes = ref<Record<number, string>>({})
const loadingLines = ref<number[]>([])
const currentPage = ref(1)
const pageSize = ref(50)
const mutating = ref(false)
const countLabels: Record<string, string> = {
  available: '邮箱可用总数',
  success: '成功数量',
  failed: '失败数量',
}
const metricIcons: any = {
  available: Message,
  success: CircleCheckFilled,
  failed: CircleCloseFilled,
}
let timer = 0
let dataVersion = 0
let latestRefresh = 0

const rows = computed(() => data.value.rows.filter((row) => {
  const matchesFilter = filter.value === 'all'
    || (filter.value === 'not_success' ? row.status !== 'consumed' : row.status === filter.value)
  const query = searchText.value.trim().toLowerCase()
  const haystack = [row.email, row.password, row.status, row.status_label, row.error, row.reason]
    .join(' ')
    .toLowerCase()
  return matchesFilter && (!query || haystack.includes(query))
}))

const pageRows = computed(() => rows.value.slice(
  (currentPage.value - 1) * pageSize.value,
  currentPage.value * pageSize.value,
))

watch([filter, searchText, pageSize], () => { currentPage.value = 1 })
watch(() => rows.value.length, (total) => {
  const lastPage = Math.max(1, Math.ceil(total / pageSize.value))
  currentPage.value = Math.min(currentPage.value, lastPage)
})

function applyMailboxPayload(payload: any) {
  const next = payload?.mailboxes || payload
  if (next && Array.isArray(next.rows)) {
    data.value = { counts: next.counts || {}, rows: next.rows }
  }
}

async function refresh() {
  if (mutating.value) return
  const request = ++latestRefresh
  const version = dataVersion
  try {
    const result = await getMailboxes()
    if (!mutating.value && request === latestRefresh && version === dataVersion) {
      applyMailboxPayload(result)
    }
  } catch (error: any) {
    if (request === latestRefresh) ElMessage.error(error.message)
  }
}

async function append() {
  if (!content.value.trim()) {
    ElMessage.warning('请先粘贴要导入的邮箱')
    return
  }
  mutating.value = true
  dataVersion += 1
  latestRefresh += 1
  try {
    const result: any = await api('/api/mailboxes/import', { pool_content: content.value })
    content.value = ''
    applyMailboxPayload(result)
    ElMessage.success('已追加 ' + (result.imported || 0) + ' 条，跳过 ' + (result.skipped || 0) + ' 条')
  } catch (error: any) {
    ElMessage.error(error.message)
  } finally {
    mutating.value = false
  }
}

async function mutate(path: string, message: string) {
  if (!selected.value.length) {
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
  const lineNumbers = [...selected.value]
  try {
    mailboxTable.value?.clearSelection()
    selected.value = []
    const result: any = await api(path, { line_nos: lineNumbers })
    applyMailboxPayload(result)
    if (path.endsWith('/delete')) {
      latestCodes.value = {}
      loadingLines.value = []
    }
    await nextTick()
    mailboxTable.value?.clearSelection()
    ElMessage.success('操作完成')
  } catch (error: any) {
    ElMessage.error(error.message || String(error))
  } finally {
    mutating.value = false
  }
}

async function code(line: number) {
  if (loadingLines.value.includes(line)) return
  loadingLines.value = [...loadingLines.value, line]
  try {
    const result: any = await api('/api/mailboxes/latest-code', { line_no: line })
    latestCodes.value[line] = result.code || '暂无'
    ElMessage.success(result.code ? '验证码：' + result.code : '未查到验证码')
  } catch (error: any) {
    latestCodes.value[line] = '暂无'
    ElMessage.error(error.message)
  } finally {
    loadingLines.value = loadingLines.value.filter(item => item !== line)
  }
}

onMounted(async () => {
  await refresh()
  timer = window.setInterval(refresh, 3000)
})
onUnmounted(() => window.clearInterval(timer))
</script>

<template>
  <div class="page">
    <div class="content">
      <el-card shadow="never" class="import-card">
        <template #header>
          <div class="import-header">
            <span>批量追加导入</span>
            <el-button type="primary" :loading="mutating" @click="append">
              <el-icon><Upload /></el-icon>追加导入
            </el-button>
          </div>
        </template>
        <el-input
          v-model="content"
          type="textarea"
          :rows="5"
          resize="none"
          placeholder="邮箱----取码地址&#10;邮箱----密码----client_id----refresh_token&#10;GPT账号|登录密码|2FA密钥&#10;导入会追加到现有邮箱池，完全重复的行会自动跳过。"
        />
      </el-card>

      <el-card shadow="never" class="table-card">
        <template #header>
          <div class="header-row">
            <span>邮箱状态</span>
            <div class="table-tools">
              <el-input v-model="searchText" clearable placeholder="搜索邮箱、密码、状态" />
              <el-select v-model="filter">
                <el-option label="全部" value="all" />
                <el-option label="未使用" value="not_success" />
                <el-option label="可用" value="available" />
                <el-option label="运行中" value="running" />
                <el-option label="已使用" value="consumed" />
                <el-option label="失败" value="failed" />
              </el-select>
              <el-button :disabled="mutating" @click="mutate('/api/mailboxes/restore', '将选中邮箱恢复为可用状态？')">恢复可用</el-button>
              <el-button type="danger" plain :disabled="mutating" @click="mutate('/api/mailboxes/delete', '确定删除选中的邮箱？')">删除选中</el-button>
            </div>
          </div>
        </template>

        <div class="metrics">
          <DashboardMetricCard
            v-for="key in ['available', 'success', 'failed']"
            :key="key"
            :title="countLabels[key]"
            :value="data.counts[key] || 0"
            :icon="metricIcons[key]"
            :tone="key === 'success' ? 'success' : key === 'failed' ? 'danger' : 'primary'"
          />
        </div>
        <MailboxTable
          ref="mailboxTable"
          :rows="pageRows"
          :latest-codes="latestCodes"
          :loading-lines="loadingLines"
          @select="selected = $event"
          @code="code"
        />
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          class="pager"
          small
          background
          layout="total, sizes, prev, pager, next"
          :page-sizes="[25, 50, 100]"
          :total="rows.length"
        />
      </el-card>
    </div>
  </div>
</template>

<style scoped>
.page { width: 100%; height: 100%; padding: 2px; overflow: hidden; }
.content { display: grid; grid-template-rows: minmax(116px, 24%) minmax(0, 1fr); gap: 8px; width: 100%; height: 100%; min-height: 0; }
.import-card { min-height: 0; overflow: hidden; }
.import-card > :deep(.el-card__body) { height: calc(100% - 43px); padding: 8px 10px; }
.import-card :deep(.el-textarea),
.import-card :deep(.el-textarea__inner) { height: 100%; min-height: 0 !important; }
.import-header { display: flex; align-items: center; gap: 4px; }
.import-header :deep(.el-button) { margin-left: 0; }
.table-card { min-width: 0; min-height: 0; height: 100%; display: flex; flex-direction: column; }
.table-card > :deep(.el-card__body) { min-height: 0; flex: 1; display: flex; flex-direction: column; padding: 8px; }
.header-row { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
.table-tools { display: grid; grid-template-columns: 190px 110px auto auto; align-items: center; gap: 5px; }
.table-tools :deep(.el-button) { margin-left: 0; }
.metrics { display: flex; flex: 0 0 auto; gap: 8px; margin-bottom: 8px; }
.metrics > * { flex: 1; min-width: 0; }
.table-card :deep(.mailbox-table) { min-height: 0; flex: 1; }
.pager { flex: 0 0 auto; margin-top: 7px; justify-content: flex-end; }
@media (max-width: 900px) {
  .header-row { align-items: flex-start; flex-direction: column; }
  .table-tools { width: 100%; grid-template-columns: minmax(150px, 1fr) 105px auto auto; }
}
@media (max-width: 620px) {
  .content { grid-template-rows: minmax(116px, 22%) minmax(0, 1fr); }
  .table-tools { grid-template-columns: minmax(0, 1fr) 100px; }
  .metrics { flex-wrap: wrap; }
  .metrics > * { flex: 1 1 calc(50% - 4px); }
}
</style>
