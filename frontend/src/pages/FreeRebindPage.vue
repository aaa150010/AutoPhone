<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Delete, Link, Plus, Refresh, VideoPlay } from '@element-plus/icons-vue'
import PageToolbar from '../components/PageToolbar.vue'
import WorkspacePanel from '../components/WorkspacePanel.vue'
import {
  deleteFreeRebindMailboxes,
  getFreeRebindState,
  importFreeRebindMailboxes,
  retryFreeRebind,
  setFreeRebindMailboxStatus,
  startFreeRebind,
  stopFreeRebind,
} from '../api/client'
import type { FreeRebindMailboxRow, FreeRebindSourceRow, FreeRebindState, FreeRebindTask } from '../api/client'

const state = ref<FreeRebindState>({ running: false, tasks: [], sources: [], mailboxes: [] })
const loading = ref(false)
const importing = ref(false)
const importOpen = ref(false)
const importText = ref('')
const selectedMailboxes = ref<FreeRebindMailboxRow[]>([])
const selectedSource = ref('')
const selectedTarget = ref('')
const startBusy = ref(false)
let refreshTimer = 0

const availableTargets = computed(() => state.value.mailboxes.filter(row => row.status === 'available'))
const source = computed(() => state.value.sources.find(row => row.row_id === selectedSource.value) || null)
const target = computed(() => state.value.mailboxes.find(row => row.row_id === selectedTarget.value) || null)
const canStart = computed(() => Boolean(source.value && target.value && !state.value.running && !startBusy.value))
const metrics = computed(() => {
  const summary = state.value.summary || {}
  return {
    available: availableTargets.value.length,
    eligible: state.value.sources.length,
    running: Number(summary.active || 0),
    success: Number(summary.success || 0),
    failed: Number(summary.failed || 0),
  }
})

function statusLabel(status = '') {
  return ({ available: '可用', unavailable: '停用', reserved: '已预留', running: '换绑中', success: '已完成', partial_success: '已换绑，待补查', failed: '失败', stopped: '已停止', queued: '排队' } as Record<string, string>)[status] || status || '未知'
}

function statusType(status = '') {
  if (status === 'available' || status === 'success') return 'success'
  if (status === 'partial_success') return 'warning'
  if (status === 'failed') return 'danger'
  if (status === 'running' || status === 'reserved' || status === 'queued') return 'warning'
  return 'info'
}

async function refresh() {
  loading.value = true
  try {
    const result = await getFreeRebindState()
    state.value = {
      running: Boolean(result.running),
      tasks: result.tasks || [],
      sources: result.sources || [],
      mailboxes: result.mailboxes || [],
      summary: result.summary || {},
    }
    if (!state.value.sources.some(row => row.row_id === selectedSource.value)) selectedSource.value = ''
    if (!state.value.mailboxes.some(row => row.row_id === selectedTarget.value && row.status === 'available')) selectedTarget.value = ''
  } catch (error: any) {
    ElMessage.error(error?.message || '换绑状态刷新失败')
  } finally {
    loading.value = false
  }
}

function openImport() {
  importText.value = ''
  importOpen.value = true
}

async function importPool() {
  if (!importText.value.trim()) {
    ElMessage.warning('请填写换绑邮箱池')
    return
  }
  importing.value = true
  try {
    const result = await importFreeRebindMailboxes(importText.value)
    importOpen.value = false
    ElMessage.success(`换绑邮箱池已导入：新增 ${Number(result.imported || 0)} 条${Number(result.skipped || 0) ? `，跳过重复 ${Number(result.skipped)} 条` : ''}`)
    await refresh()
  } catch (error: any) {
    ElMessage.error(error?.message || '换绑邮箱池导入失败')
  } finally {
    importing.value = false
  }
}

async function deleteSelected() {
  const ids = selectedMailboxes.value.map(row => row.row_id)
  if (!ids.length) return
  try {
    await ElMessageBox.confirm(`确定删除选中的 ${ids.length} 条换绑邮箱吗？`, '删除换绑邮箱', { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' })
  } catch {
    return
  }
  try {
    await deleteFreeRebindMailboxes(ids)
    selectedMailboxes.value = []
    await refresh()
    ElMessage.success('换绑邮箱已删除')
  } catch (error: any) {
    ElMessage.error(error?.message || '删除换绑邮箱失败')
  }
}

async function setSelectedStatus(status: 'available' | 'unavailable') {
  const ids = selectedMailboxes.value.map(row => row.row_id)
  if (!ids.length) return
  try {
    await setFreeRebindMailboxStatus(status, ids)
    selectedMailboxes.value = []
    await refresh()
    ElMessage.success(status === 'available' ? '换绑邮箱已恢复可用' : '换绑邮箱已停用')
  } catch (error: any) {
    ElMessage.error(error?.message || '更新换绑邮箱状态失败')
  }
}

function handleMailboxSelection(rows: FreeRebindMailboxRow[]) {
  selectedMailboxes.value = rows
}

async function start() {
  if (!source.value || !target.value || startBusy.value) return
  try {
    await ElMessageBox.confirm(`将 ${source.value.email} 换绑到 ${target.value.email}，并使用密码 + TOTP 完成重登。确定继续吗？`, '启动邮箱换绑', { type: 'warning', confirmButtonText: '开始换绑', cancelButtonText: '取消' })
  } catch {
    return
  }
  startBusy.value = true
  try {
    await startFreeRebind(source.value.row_id, target.value.row_id)
    selectedSource.value = ''
    selectedTarget.value = ''
    ElMessage.success('换绑任务已加入队列')
    await refresh()
  } catch (error: any) {
    ElMessage.error(error?.message || '换绑任务启动失败')
  } finally {
    startBusy.value = false
  }
}

async function retry(task: FreeRebindTask) {
  try {
    await retryFreeRebind(task.task_id)
    ElMessage.info('换绑任务已重新排队')
    await refresh()
  } catch (error: any) {
    ElMessage.error(error?.message || '换绑任务重试失败')
  }
}

async function stop() {
  try {
    await stopFreeRebind()
    ElMessage.info('已请求停止当前换绑任务')
    await refresh()
  } catch (error: any) {
    ElMessage.error(error?.message || '停止换绑任务失败')
  }
}

function scheduleRefresh() {
  refreshTimer = window.setTimeout(async () => {
    await refresh()
    scheduleRefresh()
  }, state.value.running ? 1200 : 5000)
}

onMounted(async () => {
  await refresh()
  scheduleRefresh()
})
onUnmounted(() => window.clearTimeout(refreshTimer))
</script>

<template>
  <div class="rebind-page">
    <PageToolbar title="Free 邮箱换绑" status="纯协议链路" tone="warning">
      <el-button :icon="Refresh" :loading="loading" @click="refresh">刷新</el-button>
      <el-button v-if="state.running" type="warning" @click="stop">停止当前任务</el-button>
    </PageToolbar>

    <div class="metrics-strip">
      <div><span>可用目标邮箱</span><strong>{{ metrics.available }}</strong></div>
      <div><span>可换绑账号</span><strong>{{ metrics.eligible }}</strong></div>
      <div><span>运行中</span><strong>{{ metrics.running }}</strong></div>
      <div><span>已完成</span><strong>{{ metrics.success }}</strong></div>
      <div><span>失败</span><strong>{{ metrics.failed }}</strong></div>
    </div>

    <div class="workspace-grid">
      <WorkspacePanel title="换绑邮箱池" subtitle="独立于 Free 注册邮箱池">
        <template #actions>
          <el-button size="small" :icon="Plus" @click="openImport">导入</el-button>
          <el-button size="small" :disabled="!selectedMailboxes.length" @click="setSelectedStatus('available')">恢复</el-button>
          <el-button size="small" type="warning" plain :disabled="!selectedMailboxes.length" @click="setSelectedStatus('unavailable')">停用</el-button>
          <el-button size="small" type="danger" plain :icon="Delete" :disabled="!selectedMailboxes.length" @click="deleteSelected">删除</el-button>
        </template>
        <el-table :data="state.mailboxes" height="300" size="small" @selection-change="handleMailboxSelection">
          <el-table-column type="selection" width="42" />
          <el-table-column prop="email" label="目标邮箱" min-width="220" show-overflow-tooltip />
          <el-table-column label="状态" width="92" align="center"><template #default="{ row }"><el-tag :type="statusType(row.status)" size="small">{{ statusLabel(row.status) }}</el-tag></template></el-table-column>
          <el-table-column label="错误" min-width="180" show-overflow-tooltip><template #default="{ row }"><span class="muted">{{ row.error || '-' }}</span></template></el-table-column>
        </el-table>
      </WorkspacePanel>

      <WorkspacePanel title="手动配对" subtitle="选择一个源账号和一个目标邮箱">
        <div class="pair-form">
          <label>源 Free 账号</label>
          <el-select v-model="selectedSource" filterable clearable placeholder="选择已有密码 + TOTP 的账号">
            <el-option v-for="row in state.sources" :key="row.row_id" :label="`${row.email} · ${row.driver || 'protocol'}`" :value="row.row_id" />
          </el-select>
          <div v-if="source" class="pair-meta"><span>{{ source.email }}</span><el-tag size="small" type="success">密码 + TOTP</el-tag><span v-if="source.rebind_email">上次目标：{{ source.rebind_email }}</span></div>
          <label>目标邮箱</label>
          <el-select v-model="selectedTarget" filterable clearable placeholder="选择换绑邮箱池中的目标">
            <el-option v-for="row in availableTargets" :key="row.row_id" :label="row.email" :value="row.row_id" />
          </el-select>
          <div v-if="target" class="pair-meta"><span>目标：{{ target.email }}</span><el-tag size="small" type="warning">仅用于换绑</el-tag></div>
          <el-button class="start-button" type="primary" :icon="Link" :loading="startBusy" :disabled="!canStart" @click="start">开始换绑</el-button>
        </div>
        <el-alert class="policy-alert" title="换绑不会连接 RoxyBrowser；完成后会用新邮箱重新登录并查询套餐与 Plus 资格。" type="info" :closable="false" />
      </WorkspacePanel>
    </div>

    <WorkspacePanel title="换绑任务" subtitle="保留原 Free 行 ID，新邮箱单独记录">
      <el-table :data="state.tasks" height="260" size="small">
        <el-table-column label="源账号" min-width="190" show-overflow-tooltip><template #default="{ row }"><div>{{ row.source_email }}</div><span class="muted">{{ row.source_row_id?.slice(0, 12) }}</span></template></el-table-column>
        <el-table-column label="目标邮箱" min-width="190" show-overflow-tooltip prop="target_email" />
        <el-table-column label="阶段" min-width="150" show-overflow-tooltip><template #default="{ row }">{{ row.stage_label || row.stage || '-' }}</template></el-table-column>
        <el-table-column label="状态" width="92" align="center"><template #default="{ row }"><el-tag :type="statusType(row.status)" size="small">{{ statusLabel(row.status) }}</el-tag></template></el-table-column>
        <el-table-column label="套餐 / Plus" width="160"><template #default="{ row }"><span>{{ row.plan_type || '-' }}</span><el-tag v-if="row.plus_trial_eligible" size="small" type="success" class="plus-tag">可试用</el-tag></template></el-table-column>
        <el-table-column label="结果" min-width="220" show-overflow-tooltip><template #default="{ row }"><span v-if="row.status === 'success'" class="success-text">已绑定：{{ row.new_bound_email || row.target_email }}</span><span v-else class="muted">{{ row.error || '-' }}</span></template></el-table-column>
        <el-table-column label="操作" width="82" align="center"><template #default="{ row }"><el-button v-if="['failed', 'stopped'].includes(row.status)" link type="warning" :icon="VideoPlay" aria-label="重试换绑" @click="retry(row)" /></template></el-table-column>
      </el-table>
    </WorkspacePanel>

    <el-dialog v-model="importOpen" title="导入换绑邮箱池" width="620px">
      <el-input v-model="importText" type="textarea" :rows="10" placeholder="每行：邮箱----取码 URL" />
      <template #footer><el-button @click="importOpen = false">取消</el-button><el-button type="primary" :loading="importing" @click="importPool">导入</el-button></template>
    </el-dialog>
  </div>
</template>

<style scoped>
.rebind-page { display: grid; grid-template-rows: 44px 58px minmax(0, 1fr); gap: 8px; width: 100%; height: 100%; min-width: 0; min-height: 0; overflow: hidden; }
.metrics-strip { display: grid; grid-template-columns: repeat(5, minmax(100px, 1fr)); gap: 8px; }
.metrics-strip > div { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 0 14px; border: 1px solid #dbe4ee; background: #f8fafc; border-radius: 6px; color: #64748b; font-size: 12px; }
.metrics-strip strong { color: #0f172a; font-size: 19px; font-weight: 700; }
.workspace-grid { display: grid; grid-template-columns: minmax(0, 1.12fr) minmax(360px, .88fr); grid-template-rows: minmax(0, 1fr) 260px; gap: 8px; min-height: 0; overflow: hidden; }
.workspace-grid > :last-child { grid-column: 1 / -1; }
.pair-form { display: grid; gap: 8px; }
.pair-form label { color: #64748b; font-size: 12px; }
.pair-meta { display: flex; align-items: center; gap: 8px; min-height: 24px; color: #334155; font-size: 12px; }
.pair-meta span:last-child { color: #64748b; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.start-button { width: 100%; margin-top: 6px; }
.policy-alert { margin-top: 14px; }
.muted { color: #94a3b8; }
.success-text { color: #15803d; }
.plus-tag { margin-left: 6px; }
@media (max-width: 1380px) { .workspace-grid { grid-template-columns: minmax(0, 1fr) minmax(340px, .9fr); } }
</style>
