<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { CopyDocument, Delete, Key, Lock, Plus, Refresh, Tickets } from '@element-plus/icons-vue'
import { deleteFreeMailboxes, getFreeMailboxes, getFreeSecret, importFreeMailboxes, retryFreeTwofa } from '../api/client'
import type { FreeMailboxRow } from '../api/client'
import ContentEmptyState from './ContentEmptyState.vue'
import WorkspacePanel from './WorkspacePanel.vue'

const rows = ref<FreeMailboxRow[]>([])
const selected = ref<FreeMailboxRow[]>([])
const loading = ref(false)
const importOpen = ref(false)
const mailboxText = ref('')
const currentPage = ref(1)
const pageSize = ref(100)
const tableRef = ref<any>()

const pageRows = computed(() => rows.value.slice((currentPage.value - 1) * pageSize.value, currentPage.value * pageSize.value))
function openImport() {
  mailboxText.value = ''
  importOpen.value = true
}
defineExpose({ openImport })

async function refresh() {
  loading.value = true
  try {
    rows.value = (await getFreeMailboxes()).rows || []
  } catch (error: any) {
    ElMessage.error(error?.message || 'Free 邮箱池刷新失败')
  } finally {
    loading.value = false
  }
}

async function importPools() {
  if (!mailboxText.value.trim()) {
    ElMessage.warning('请填写 Free 邮箱池')
    return
  }
  loading.value = true
  try {
    const messages: string[] = []
    const result = await importFreeMailboxes(mailboxText.value)
    messages.push(`新增 ${Number(result.imported || 0)} 条`)
    if (Number(result.skipped || 0)) messages.push(`跳过重复 ${Number(result.skipped || 0)} 条`)
    importOpen.value = false
    selected.value = []
    tableRef.value?.clearSelection()
    await refresh()
    ElMessage.success(`Free 池导入完成：${messages.join('，')}`)
  } catch (error: any) {
    ElMessage.error(error?.message || 'Free 池导入失败')
  } finally {
    loading.value = false
  }
}

async function deleteSelected() {
  const rowIds = selected.value.map(row => row.row_id).filter(Boolean)
  if (!rowIds.length) return
  try {
    await ElMessageBox.confirm(
      `确定删除选中的 ${rowIds.length} 条 Free 邮箱吗？历史注册结果会保留。`,
      '删除 Free 邮箱',
      { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  loading.value = true
  try {
    const result = await deleteFreeMailboxes(rowIds)
    selected.value = []
    tableRef.value?.clearSelection()
    await refresh()
    ElMessage.success(`已删除 ${Number(result.deleted || 0)} 条 Free 邮箱`)
  } catch (error: any) {
    ElMessage.error(error?.message || 'Free 邮箱删除失败')
  } finally {
    loading.value = false
  }
}

async function copySecret(kind: 'token' | 'password' | 'totp' | 'proxy' | 'credential', selection = selected.value) {
  const eligible = selection.filter(row => kind === 'token' ? row.has_access_token : kind === 'password' ? row.has_password : kind === 'totp' ? row.has_totp : kind === 'credential' ? row.has_credential : Boolean(row.proxy_masked))
  if (!eligible.length) {
    ElMessage.warning('当前没有可复制的 Free 记录')
    return
  }
  try {
    const value = (await getFreeSecret(kind, { row_ids: eligible.map(row => row.row_id) })).value
    await navigator.clipboard.writeText(value || '')
    ElMessage.success(`已复制 ${eligible.length} 条${kind === 'token' ? ' Token' : kind === 'password' ? '密码' : kind === 'totp' ? '2FA 密钥' : kind === 'credential' ? '完整凭据' : '代理'}`)
  } catch (error: any) {
    ElMessage.error(error?.message || 'Free 敏感字段复制失败')
  }
}

async function copyRow(kind: 'token' | 'password' | 'totp' | 'proxy' | 'credential', row: FreeMailboxRow) {
  await copySecret(kind, [row])
}

async function retryTwofa(row: FreeMailboxRow) {
  if (row.twofa_status !== 'pending' || !row.row_id) return
  try {
    await retryFreeTwofa(row.row_id)
    ElMessage.info('已重新加入 2FA 设置任务')
    await refresh()
  } catch (error: any) {
    ElMessage.error(error?.message || '2FA 重试失败')
  }
}

onMounted(refresh)
</script>

<template>
  <div class="free-pool">
    <WorkspacePanel title="Free 注册邮箱池" :icon="Tickets" fill body-padding="none">
      <template #actions>
        <span class="pool-summary">共 {{ rows.length }} 条</span>
        <el-button size="small" :icon="Refresh" :loading="loading" @click="refresh">刷新</el-button>
        <el-button size="small" type="primary" :icon="Plus" @click="openImport">导入 Free 邮箱</el-button>
        <el-button size="small" type="danger" plain :icon="Delete" :disabled="!selected.length || loading" @click="deleteSelected">删除选中</el-button>
        <el-button size="small" :icon="CopyDocument" :disabled="!selected.length" @click="copySecret('token')">复制选中 Token</el-button>
        <el-button size="small" :icon="CopyDocument" :disabled="!pageRows.some(row => row.has_access_token)" @click="copySecret('token', pageRows)">复制当前页 Token</el-button>
        <el-button size="small" :icon="CopyDocument" :disabled="!selected.some(row => row.has_credential)" @click="copySecret('credential')">复制选中凭据</el-button>
      </template>

      <div class="table-region">
        <el-table
          ref="tableRef"
          :data="pageRows"
          row-key="row_id"
          stripe
          height="100%"
          @selection-change="selected = $event"
        >
          <el-table-column type="selection" width="42" reserve-selection />
          <el-table-column prop="line_no" label="#" width="52" align="right" />
          <el-table-column prop="email" label="邮箱" min-width="190" show-overflow-tooltip />
          <el-table-column label="阶段" min-width="150" show-overflow-tooltip>
            <template #default="{ row }"><el-tag size="small" :type="row.status === 'success' ? 'success' : row.status === 'failed' ? 'danger' : 'warning'">{{ row.stage || row.status || '可用' }}</el-tag></template>
          </el-table-column>
          <el-table-column label="代理 / 出口 IP" min-width="190" show-overflow-tooltip>
            <template #default="{ row }"><span>{{ row.proxy_masked || '-' }}</span><small v-if="row.exit_ip"> / {{ row.exit_ip }}</small></template>
          </el-table-column>
          <el-table-column label="套餐 / Plus 试用" width="150">
            <template #default="{ row }"><span>{{ row.plan_type || '-' }}</span><el-tag v-if="row.plus_trial_eligible" size="small" type="success" class="trial-tag">可试用</el-tag></template>
          </el-table-column>
          <el-table-column label="2FA" width="100" align="center">
            <template #default="{ row }"><el-button v-if="row.has_totp" link :icon="Key" @click="copyRow('totp', row)">已设置</el-button><el-button v-else-if="row.twofa_status === 'pending'" link type="warning" @click="retryTwofa(row)">重试</el-button><span v-else>-</span></template>
          </el-table-column>
          <el-table-column label="Token" width="80" align="center"><template #default="{ row }"><el-button v-if="row.has_access_token" link :icon="CopyDocument" aria-label="复制 Token" @click="copyRow('token', row)" /><span v-else>-</span></template></el-table-column>
          <el-table-column label="敏感字段" width="210" align="center"><template #default="{ row }"><el-button v-if="row.has_credential" link :icon="CopyDocument" @click="copyRow('credential', row)">完整凭据</el-button><el-button v-if="row.has_password" link :icon="Lock" @click="copyRow('password', row)">密码</el-button><el-button v-if="row.proxy_masked" link :icon="CopyDocument" @click="copyRow('proxy', row)">代理</el-button></template></el-table-column>
          <el-table-column label="错误" min-width="220" show-overflow-tooltip><template #default="{ row }">{{ row.error || row.twofa_error || '-' }}</template></el-table-column>
          <template #empty><ContentEmptyState /></template>
        </el-table>
        <el-pagination v-model:current-page="currentPage" v-model:page-size="pageSize" background layout="total, sizes, prev, pager, next" :page-sizes="[25, 50, 100]" :total="rows.length" />
      </div>
    </WorkspacePanel>

    <el-dialog v-model="importOpen" title="导入 Free 邮箱池" width="680px" :close-on-click-modal="false">
      <el-form label-position="top">
        <el-form-item label="Free 邮箱池"><el-input v-model="mailboxText" type="textarea" :rows="7" placeholder="邮箱---取码 URL（也支持 ---- 或 |）" /></el-form-item>
      </el-form>
      <template #footer><el-button @click="importOpen = false">取消</el-button><el-button type="primary" :loading="loading" @click="importPools">导入</el-button></template>
    </el-dialog>
  </div>
</template>

<style scoped>
.free-pool { width: 100%; height: 100%; min-height: 0; }
.pool-summary { color: var(--el-text-color-secondary); font-size: 12px; }
.table-region { display: grid; grid-template-rows: minmax(0, 1fr) 46px; width: 100%; height: 100%; min-height: 0; padding: 8px 10px 0; }
.trial-tag { margin-left: 5px; }
.table-region :deep(.el-pagination) { justify-content: flex-end; border-top: 1px solid var(--workspace-border); }
.table-region small { color: var(--el-text-color-secondary); }
</style>
