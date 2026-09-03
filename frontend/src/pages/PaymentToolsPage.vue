<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { CopyDocument, MoreFilled, QuestionFilled, Refresh, View } from '@element-plus/icons-vue'
import {
  confirmPaymentTask,
  createPaymentTasks,
  getFreeMailboxes,
  getPaymentConfig,
  getPaymentSecret,
  getPaymentTaskLogs,
  getPaymentTasks,
  retryPaymentTask,
  savePaymentConfig,
  type PaymentTask,
} from '../api/client'
import type { FreeMailboxRow } from '../api/client'
import ContentEmptyState from '../components/ContentEmptyState.vue'
import FieldHelpLabel from '../components/FieldHelpLabel.vue'

const loading = ref(false)
const saving = ref(false)
const config = ref<any>({ mode: 'local', workers: 2, timeout_seconds: 180, country: 'US', currency: 'USD', plan: 'plus', channel: 'paypal', pay153_headless: true })
const tasks = ref<PaymentTask[]>([])
const freeRows = ref<FreeMailboxRow[]>([])
const selectedRows = ref<string[]>([])
const manualTokens = ref('')
const manualLink = ref('')
const filter = ref('')
const logVisible = ref(false)
const logTask = ref<PaymentTask | null>(null)
const logs = ref<Array<{ time?: number; stage?: string; level?: string; message?: string }>>([])
const logLoading = ref(false)

const filteredTasks = computed(() => tasks.value.filter((task) => {
  const value = filter.value.trim().toLowerCase()
  return !value || [task.email, task.status, task.stage, task.mode, task.channel, task.failure?.node_code].some((item) => String(item || '').toLowerCase().includes(value))
}))
const selectableRows = computed(() => freeRows.value.filter((row) => row.has_access_token && ['success', 'partial_success'].includes(row.status)))

function statusType(status: string) {
  if (status === 'succeeded') return 'success'
  if (status === 'failed') return 'danger'
  if (status === 'cancelled') return 'info'
  if (status === 'awaiting_confirmation') return 'warning'
  return ''
}
function statusLabel(status: string) {
  return ({ succeeded: '成功', failed: '失败', cancelled: '已取消', awaiting_confirmation: '待确认', queued: '排队中', running: '运行中' } as Record<string, string>)[status] || status
}
function formatTime(value?: number | string) {
  if (!value) return '-'
  const date = typeof value === 'number' ? new Date(value * 1000) : new Date(value)
  return Number.isNaN(date.getTime()) ? '-' : date.toLocaleString()
}
async function refresh() {
  loading.value = true
  try {
    const [payment, mailbox] = await Promise.all([getPaymentTasks(), getFreeMailboxes()])
    tasks.value = payment.tasks || []
    freeRows.value = mailbox.rows || []
  } catch (error: any) {
    ElMessage.error(error?.message || '支付工作台加载失败')
  } finally {
    loading.value = false
  }
}
async function loadConfig() {
  try {
    config.value = (await getPaymentConfig()).config
  } catch (error: any) {
    ElMessage.error(error?.message || '支付配置加载失败')
  }
}
async function save() {
  saving.value = true
  try {
    config.value = (await savePaymentConfig(config.value)).config
    ElMessage.success('支付工具配置已保存')
  } catch (error: any) {
    ElMessage.error(error?.message || '支付工具配置保存失败')
  } finally {
    saving.value = false
  }
}
async function create() {
  if (config.value.mode === 'manual' && !manualLink.value.trim()) {
    ElMessage.warning('手动模式请先粘贴支付链接')
    return
  }
  if (config.value.mode !== 'manual' && !selectedRows.value.length && !manualTokens.value.trim()) {
    ElMessage.warning('请选择 Free 成功账号或输入 Token')
    return
  }
  try {
    const response = await createPaymentTasks({ ...config.value, row_ids: selectedRows.value, manual_tokens: manualTokens.value, manual_link: manualLink.value })
    if (response.requires_confirmation) {
      const domains = [...new Set((response.tasks || []).map((task) => task.target_domain).filter(Boolean))]
      await ElMessageBox.confirm(`本批任务将把 Token 发送到：${domains.join('、')}。请确认目标域名、通道和账号数量无误。`, '第三方提链确认', { type: 'warning', confirmButtonText: '确认并开始', cancelButtonText: '取消' })
      for (const task of response.tasks || []) {
        if (task.target_domain) await confirmPaymentTask(task.task_id, task.target_domain)
      }
    }
    manualTokens.value = ''
    ElMessage.success(`已创建 ${response.tasks?.length || 0} 个支付提链任务`)
    await refresh()
  } catch (error: any) {
    if (!['cancel', 'close', '取消'].includes(String(error))) ElMessage.error(error?.message || '创建支付提链任务失败')
    await refresh()
  }
}
async function openLogs(task: PaymentTask) {
  logTask.value = task
  logVisible.value = true
  logLoading.value = true
  try {
    logs.value = (await getPaymentTaskLogs(task.task_id)).logs || []
  } catch (error: any) {
    ElMessage.error(error?.message || '日志加载失败')
  } finally {
    logLoading.value = false
  }
}
async function copyResult(task: PaymentTask) {
  try {
    const value = (await getPaymentSecret(task.task_id)).value
    await navigator.clipboard.writeText(value)
    ElMessage.success('支付链接已复制')
  } catch (error: any) {
    ElMessage.error(error?.message || '复制失败')
  }
}
async function retry(task: PaymentTask) {
  try {
    await retryPaymentTask(task.task_id)
    await refresh()
  } catch (error: any) {
    ElMessage.error(error?.message || '重试失败')
  }
}

function handleTaskAction(command: string, task: PaymentTask) {
  if (command === 'logs') return openLogs(task)
  if (command === 'copy') return copyResult(task)
  if (command === 'retry') return retry(task)
}
function toggleRow(row: FreeMailboxRow) {
  if (!row.row_id) return
  selectedRows.value = selectedRows.value.includes(row.row_id)
    ? selectedRows.value.filter((id) => id !== row.row_id)
    : [...selectedRows.value, row.row_id]
}
onMounted(async () => { await Promise.all([loadConfig(), refresh()]) })
</script>

<template>
  <div class="tool-page">
    <div class="page-heading"><div><h1>支付链接工作台</h1><p>独立提炼支付链接，不执行扣款。默认使用本地协议，第三方模式会逐批确认目标域名。</p></div><el-button :icon="Refresh" :loading="loading" @click="refresh">刷新</el-button></div>

    <section class="tool-section config-section">
      <div class="section-title"><span>提链配置</span><el-tooltip content="支付工具使用独立 payment_tools 数据目录，不会修改 Free 注册任务。Token 只有在任务执行时按需读取。"><el-icon><QuestionFilled /></el-icon></el-tooltip></div>
      <el-form label-position="top" class="config-grid">
        <el-form-item><template #label><FieldHelpLabel label="提链模式" help="本地模式优先；CDK、HTTP 和 pay.153.ink 属于第三方模式，创建后必须确认目标域名。" /></template><el-select v-model="config.mode"><el-option label="本地协议" value="local" /><el-option label="手动粘贴" value="manual" /><el-option label="CDK / SSE" value="cdk" /><el-option label="HTTP API" value="http" /><el-option label="pay.153.ink 浏览器" value="pay153" /></el-select></el-form-item>
        <el-form-item><template #label><FieldHelpLabel label="支付通道" help="支持 Hosted、PH 短链、PayPal、PIX、UPI、iDEAL、GCash、GoPay 等通道；本地协议当前优先支持 PayPal、GoPay、GCash。" /></template><el-select v-model="config.channel"><el-option label="Hosted" value="hosted" /><el-option label="PH 短链" value="ph_short" /><el-option label="PayPal" value="paypal" /><el-option label="PIX" value="pix" /><el-option label="UPI" value="upi" /><el-option label="iDEAL" value="ideal" /><el-option label="GCash" value="gcash" /><el-option label="GoPay" value="gopay" /><el-option label="Kakao Pay" value="kakao_pay" /></el-select></el-form-item>
        <el-form-item label="套餐"><el-input v-model="config.plan" /></el-form-item><el-form-item label="国家"><el-input v-model="config.country" maxlength="2" /></el-form-item><el-form-item label="币种"><el-input v-model="config.currency" maxlength="4" /></el-form-item><el-form-item label="并发"><el-input-number v-model="config.workers" :min="1" :max="5" /></el-form-item>
        <el-form-item label="超时（秒）"><el-input-number v-model="config.timeout_seconds" :min="15" :max="900" /></el-form-item>
        <el-form-item v-if="config.mode === 'http'" label="HTTP 提链地址"><el-input v-model="config.http_endpoint" placeholder="https://example.com/extract" /></el-form-item>
        <el-form-item v-if="config.mode === 'cdk'" label="CDK 服务地址"><el-input v-model="config.cdk_base_url" placeholder="https://example.com" /></el-form-item><el-form-item v-if="config.mode === 'cdk'" label="CDK"><el-input v-model="config.cdk" show-password /></el-form-item>
        <el-form-item v-if="config.mode === 'pay153'" label="pay.153.ink 地址"><el-input v-model="config.pay153_url" /></el-form-item>
        <el-form-item v-if="config.mode === 'http'" label="HTTP API Token"><el-input v-model="config.http_api_token" show-password /></el-form-item>
        <el-form-item v-if="config.mode === 'pay153'" label="浏览器"><el-switch v-model="config.pay153_headless" active-text="无头运行" /></el-form-item>
      </el-form>
      <div class="section-actions"><el-button type="primary" :loading="saving" @click="save">保存支付配置</el-button></div>
    </section>

    <section class="tool-section source-section">
      <div class="section-title"><span>任务来源</span><el-tooltip content="Free 账号必须已经有 Token；普通接码邮箱不会出现在这里。敏感 Token 不会显示在列表或浏览器本地存储中。"><el-icon><QuestionFilled /></el-icon></el-tooltip></div>
      <div v-if="config.mode !== 'manual'" class="source-grid"><div><div class="sub-title">Free 成功账号</div><el-scrollbar max-height="150"><el-checkbox v-for="row in selectableRows" :key="row.row_id" :model-value="selectedRows.includes(row.row_id)" @change="toggleRow(row)">{{ row.email }}</el-checkbox><ContentEmptyState v-if="!selectableRows.length" description="暂无可用 Free Token" /></el-scrollbar></div><el-input v-model="manualTokens" type="textarea" :rows="5" placeholder="也可以逐行粘贴 Token（仅在创建任务时读取）" /></div><el-input v-else v-model="manualLink" placeholder="粘贴已有支付链接或付款码" />
      <div class="section-actions"><el-button type="primary" @click="create">创建提链任务</el-button></div>
    </section>

    <section class="tool-section task-section">
      <div class="section-title"><span>提链任务</span><el-input v-model="filter" class="filter-input" clearable placeholder="搜索邮箱、状态、节点或模式" /></div>
      <el-table v-loading="loading" :data="filteredTasks" row-key="task_id" height="360" border>
        <el-table-column prop="email" label="账号" min-width="210" show-overflow-tooltip /><el-table-column prop="mode" label="模式" width="120" show-overflow-tooltip /><el-table-column prop="channel" label="通道" width="105" show-overflow-tooltip /><el-table-column prop="stage" label="阶段" min-width="150" show-overflow-tooltip /><el-table-column label="状态" width="100"><template #default="scope"><el-tag :type="statusType(scope.row.status)">{{ statusLabel(scope.row.status) }}</el-tag></template></el-table-column><el-table-column label="结果" min-width="150" show-overflow-tooltip><template #default="scope"><span v-if="scope.row.result_summary?.result_host">{{ scope.row.result_summary.result_host }}</span><span v-else>-</span></template></el-table-column><el-table-column label="时间" width="160"><template #default="scope">{{ formatTime(scope.row.updated_at) }}</template></el-table-column><el-table-column label="操作" width="82" fixed="right" align="center"><template #default="scope"><el-dropdown trigger="click" @command="(command: string) => handleTaskAction(command, scope.row)"><el-button link aria-label="打开支付任务操作菜单" title="打开支付任务操作菜单"><el-icon><MoreFilled /></el-icon></el-button><template #dropdown><el-dropdown-menu><el-dropdown-item command="logs"><el-icon><View /></el-icon>查看日志</el-dropdown-item><el-dropdown-item v-if="scope.row.status === 'succeeded'" command="copy"><el-icon><CopyDocument /></el-icon>复制支付链接</el-dropdown-item><el-dropdown-item v-if="['failed', 'cancelled'].includes(scope.row.status)" command="retry"><el-icon><Refresh /></el-icon>重试任务</el-dropdown-item></el-dropdown-menu></template></el-dropdown></template></el-table-column>
      </el-table><ContentEmptyState v-if="!filteredTasks.length && !loading" description="还没有支付提链任务" />
    </section>

    <el-drawer v-model="logVisible" :title="`任务日志：${logTask?.email || logTask?.task_id || ''}`" size="520px"><div class="drawer-toolbar"><el-tag v-if="logTask" :type="statusType(logTask.status)">{{ statusLabel(logTask.status) }}</el-tag><el-button link :icon="Refresh" :loading="logLoading" @click="logTask && openLogs(logTask)">刷新</el-button></div><el-scrollbar v-loading="logLoading" max-height="calc(100vh - 150px)"><div v-for="(item, index) in logs" :key="`${item.time}-${index}`" class="log-line"><span class="log-time">{{ formatTime(item.time) }}</span><el-tag size="small" :type="item.level === 'error' ? 'danger' : item.level === 'success' ? 'success' : ''">{{ item.stage }}</el-tag><span>{{ item.message }}</span></div><ContentEmptyState v-if="!logs.length && !logLoading" description="暂无日志" /></el-scrollbar></el-drawer>
  </div>
</template>

<style scoped>
.tool-page { display: flex; flex-direction: column; gap: 8px; height: 100%; min-width: 0; overflow: hidden; color: #24344d; }
.page-heading { display: flex; align-items: center; justify-content: space-between; padding: 8px 12px; background: #fff; border: 1px solid #dce5ef; border-radius: 5px; }
h1 { margin: 0; font-size: 20px; } p { margin: 3px 0 0; color: #7d8ba0; font-size: 12px; }
.tool-section { padding: 10px 12px; background: #fff; border: 1px solid #dce5ef; border-radius: 5px; }
.section-title { display: flex; align-items: center; gap: 5px; margin-bottom: 9px; font-size: 14px; font-weight: 700; } .section-title .el-icon { color: #74859a; cursor: help; }
.config-grid { display: grid; grid-template-columns: repeat(6, minmax(120px, 1fr)); gap: 0 10px; } .config-grid :deep(.el-form-item) { margin-bottom: 8px; } .config-grid :deep(.el-select), .config-grid :deep(.el-input), .config-grid :deep(.el-input-number) { width: 100%; }
.section-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 3px; }
.source-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; } .sub-title { margin-bottom: 6px; color: #53647b; font-size: 12px; font-weight: 650; } .source-grid :deep(.el-checkbox) { display: block; margin: 4px 0; }
.filter-input { width: 260px; margin-left: auto; } .task-section { min-height: 0; flex: 1; overflow: hidden; } .task-section :deep(.el-table) { width: 100%; }
.drawer-toolbar { display: flex; justify-content: space-between; margin-bottom: 10px; } .log-line { display: grid; grid-template-columns: 138px 118px 1fr; gap: 7px; align-items: start; padding: 7px 0; border-bottom: 1px solid #edf1f5; font-size: 12px; line-height: 18px; } .log-time { color: #8a97a8; }
</style>
