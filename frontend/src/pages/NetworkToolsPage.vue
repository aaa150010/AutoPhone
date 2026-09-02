<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Delete, Edit, QuestionFilled, Refresh, View } from '@element-plus/icons-vue'
import {
  deleteNetworkGroup,
  getNetworkTools,
  importNetworkProxies,
  importNetworkSubscription,
  saveNetworkToolsConfig,
  testNetworkProxy,
  testNetworkSubscription,
  updateNetworkGroup,
  type NetworkProxyRow,
} from '../api/client'
import ContentEmptyState from '../components/ContentEmptyState.vue'
import FieldHelpLabel from '../components/FieldHelpLabel.vue'

const loading = ref(false)
const saving = ref(false)
const rows = ref<NetworkProxyRow[]>([])
const groups = ref<any[]>([])
const config = ref<any>({ workers: 3, default_target_url: 'https://www.google.com/generate_204', connect_timeout_seconds: 10, request_timeout_seconds: 30 })
const filter = ref('')
const importForm = ref({ proxy_content: '', country: 'US', group: '默认组', scheme: 'http' })
const subscription = ref({ subscription_url: '', content: '', country: 'US', group: '订阅' })
const subscriptionId = ref('')
const subscriptionResult = ref<any>(null)
const selected = ref<NetworkProxyRow | null>(null)
const result = ref<any>(null)

const filteredRows = computed(() => rows.value.filter((row) => {
  const value = filter.value.trim().toLowerCase()
  return !value || [row.masked, row.scheme, row.country, row.group, row.status].some((item) => String(item || '').toLowerCase().includes(value))
}))
function statusType(value: string) { return value === 'available' ? 'success' : value === 'quarantined' ? 'danger' : value === 'unknown' ? 'warning' : 'info' }
function statusLabel(value: string) { return ({ available: '可用', quarantined: '隔离', unknown: '未检测', disabled: '已停用' } as Record<string, string>)[value] || value }
function formatTime(value?: number | string | null) { if (!value) return '-'; const date = typeof value === 'number' ? new Date(value * 1000) : new Date(value); return Number.isNaN(date.getTime()) ? '-' : date.toLocaleString() }
async function refresh() {
  loading.value = true
  try { const data = await getNetworkTools(); rows.value = data.rows || []; groups.value = data.groups || []; config.value = data.config || config.value } catch (error: any) { ElMessage.error(error?.message || '网络工具加载失败') } finally { loading.value = false }
}
async function save() {
  saving.value = true
  try { config.value = (await saveNetworkToolsConfig(config.value)).config; ElMessage.success('网络工具配置已保存') } catch (error: any) { ElMessage.error(error?.message || '网络工具配置保存失败') } finally { saving.value = false }
}
async function importManual() {
  if (!importForm.value.proxy_content.trim()) return ElMessage.warning('请粘贴代理列表')
  try { const data = await importNetworkProxies(importForm.value); rows.value = data.rows || rows.value; groups.value = data.groups || groups.value; ElMessage.success(`已导入 ${data.imported} 条，跳过 ${data.skipped} 条`) } catch (error: any) { ElMessage.error(error?.message || '代理导入失败') }
}
async function importSub() {
  if (!subscription.value.subscription_url.trim() || !subscription.value.content.trim()) return ElMessage.warning('请填写订阅地址和订阅内容')
  try { const data = await importNetworkSubscription(subscription.value); rows.value = data.rows || rows.value; groups.value = data.groups || groups.value; subscriptionId.value = data.subscription_id || ''; ElMessage.success(`订阅解析 ${data.node_count} 条，导入 ${data.imported} 条`) } catch (error: any) { ElMessage.error(error?.message || '订阅解析失败') }
}
async function testSub() {
  if (!subscriptionId.value) return ElMessage.warning('请先解析订阅')
  try { subscriptionResult.value = await testNetworkSubscription({ subscription_id: subscriptionId.value, target_url: config.value.default_target_url }); if (!subscriptionResult.value.tested) ElMessage.warning(subscriptionResult.value.message || '当前只能展示解析结果'); else ElMessage.success('订阅节点连通性检测完成') } catch (error: any) { ElMessage.error(error?.message || '订阅节点测试失败') }
}
async function test(row: NetworkProxyRow, mode: 'quick' | 'deep') {
  selected.value = row
  try { result.value = await testNetworkProxy({ proxy_id: row.proxy_id, mode, target_url: config.value.default_target_url }); ElMessage.success(`${mode === 'quick' ? '快速' : '深度'}连通性检测完成`); await refresh() } catch (error: any) { result.value = null; ElMessage.error(error?.message || '代理连通性检测失败'); await refresh() }
}
async function editGroup(group: any) {
  try {
    const newGroup = await ElMessageBox.prompt('输入新的分组名称', '重命名代理分组', { inputValue: group.group, confirmButtonText: '保存', cancelButtonText: '取消' })
    await updateNetworkGroup({ country: group.country, group: group.group, action: 'rename', new_group: newGroup.value })
    await refresh()
  } catch (error: any) { if (!['cancel', 'close', '取消'].includes(String(error))) ElMessage.error(error?.message || '分组修改失败') }
}
async function removeGroup(group: any) {
  try { await ElMessageBox.confirm(`确定删除 ${group.country} / ${group.group} 下的代理吗？租用中的代理不会被删除。`, '删除分组', { type: 'warning' }); await deleteNetworkGroup(group.country, group.group); await refresh() } catch (error: any) { if (!['cancel', 'close', '取消'].includes(String(error))) ElMessage.error(error?.message || '分组删除失败') }
}
onMounted(refresh)
</script>

<template>
  <div class="tool-page">
    <div class="page-heading"><div><h1>代理与网络工具</h1><p>独立维护手动代理和订阅节点。测活始终固定使用所选代理，不回退本机代理或自动换节点。</p></div><el-button :icon="Refresh" :loading="loading" @click="refresh">刷新</el-button></div>
    <section class="tool-section config-section"><div class="section-title"><span>网络检测配置</span><el-tooltip content="快速检测只测试本机到代理入口；深度检测会通过同一代理访问目标站。Clash/V2Ray 订阅只做安全解析，真实节点测试需要独立 Mihomo。"><el-icon><QuestionFilled /></el-icon></el-tooltip></div><el-form label-position="top" class="config-grid"><el-form-item><template #label><FieldHelpLabel label="本机并发" help="仅用于工具任务，不影响 Free 或接码并发。" /></template><el-input-number v-model="config.workers" :min="1" :max="5" /></el-form-item><el-form-item label="连接超时（秒）"><el-input-number v-model="config.connect_timeout_seconds" :min="1" :max="120" /></el-form-item><el-form-item label="请求超时（秒）"><el-input-number v-model="config.request_timeout_seconds" :min="3" :max="300" /></el-form-item><el-form-item label="目标站"><el-input v-model="config.default_target_url" /></el-form-item></el-form><div class="section-actions"><el-button type="primary" :loading="saving" @click="save">保存网络配置</el-button></div></section>
    <section class="tool-section import-section"><div class="section-title"><span>导入代理</span><el-tooltip content="支持 HTTP、HTTPS、SOCKS4、SOCKS5、SOCKS5H，以及 host:port:user:password 格式；裸格式按当前默认协议解析。重复身份会更新协议、国家和分组，不会产生重复记录。"><el-icon><QuestionFilled /></el-icon></el-tooltip></div><div class="import-grid"><el-form label-position="top"><el-form-item label="国家"><el-input v-model="importForm.country" maxlength="2" /></el-form-item><el-form-item label="分组"><el-input v-model="importForm.group" /></el-form-item><el-form-item label="默认协议"><el-select v-model="importForm.scheme"><el-option v-for="item in ['http', 'https', 'socks4', 'socks5', 'socks5h']" :key="item" :label="item.toUpperCase()" :value="item" /></el-select></el-form-item></el-form><el-input v-model="importForm.proxy_content" type="textarea" :rows="5" placeholder="每行一个代理" /><div class="import-actions"><el-button type="primary" @click="importManual">导入并去重</el-button></div></div><el-divider /><div class="subscription-grid"><el-input v-model="subscription.subscription_url" placeholder="订阅地址（仅本地保存，不公开展示）" /><el-input v-model="subscription.content" type="textarea" :rows="3" placeholder="粘贴 Clash/V2Ray 订阅内容" /><el-button @click="importSub">解析订阅</el-button><el-button :disabled="!subscriptionId" @click="testSub">隔离 Mihomo 检测</el-button></div><el-alert v-if="subscriptionResult" :closable="false" :type="subscriptionResult.tested ? 'success' : 'warning'" :title="subscriptionResult.tested ? '订阅检测完成' : '订阅仅完成解析'"><template #default>{{ subscriptionResult.message || `代理到目标：${subscriptionResult.proxy_to_target_ms ?? '-'} ms` }}</template></el-alert></section>
    <section class="tool-section group-section"><div class="section-title"><span>代理分组汇总</span><el-tooltip content="分组只是资源选择和统计维度；测活不会随机挑选其他分组。"><el-icon><QuestionFilled /></el-icon></el-tooltip></div><el-table :data="groups" height="150" border><el-table-column label="#" type="index" width="58" fixed="left" /><el-table-column prop="country" label="国家" width="80" /><el-table-column prop="group" label="分组" min-width="150" /><el-table-column prop="total" label="总数" width="70" /><el-table-column prop="available" label="可用" width="70" /><el-table-column prop="leased" label="租用" width="70" /><el-table-column prop="quarantined" label="隔离" width="70" /><el-table-column label="操作" width="120" fixed="right"><template #default="scope"><el-button link :icon="Edit" title="重命名分组" @click="editGroup(scope.row)" /><el-button link :icon="Delete" title="删除分组" @click="removeGroup(scope.row)" /></template></el-table-column></el-table><ContentEmptyState v-if="!groups.length" description="暂无分组" /></section>
    <section class="tool-section proxy-section"><div class="section-title"><span>代理明细</span><el-input v-model="filter" class="filter-input" clearable placeholder="搜索地址、国家、分组或状态" /></div><el-table v-loading="loading" :data="filteredRows" row-key="proxy_id" height="330" border><el-table-column label="#" type="index" width="58" fixed="left" /><el-table-column prop="masked" label="代理" min-width="190" fixed="left" show-overflow-tooltip /><el-table-column prop="scheme" label="协议" width="90" show-overflow-tooltip /><el-table-column prop="country" label="国家" width="76" show-overflow-tooltip /><el-table-column prop="group" label="分组" width="130" show-overflow-tooltip /><el-table-column label="状态" width="90"><template #default="scope"><el-tag :type="statusType(scope.row.status)">{{ statusLabel(scope.row.status) }}</el-tag></template></el-table-column><el-table-column prop="latency_ms" label="延迟 ms" width="90" /><el-table-column prop="last_checked_at" label="最近检测" width="160"><template #default="scope">{{ formatTime(scope.row.last_checked_at) }}</template></el-table-column><el-table-column prop="created_at" label="创建时间" width="160"><template #default="scope">{{ formatTime(scope.row.created_at) }}</template></el-table-column><el-table-column label="操作" width="160" fixed="right"><template #default="scope"><el-button link :icon="View" title="快速检测" @click="test(scope.row, 'quick')" /><el-button link type="primary" title="深度检测" @click="test(scope.row, 'deep')">深度</el-button></template></el-table-column></el-table><ContentEmptyState v-if="!filteredRows.length && !loading" description="暂无代理" /></section>
    <el-alert v-if="result" :title="`${selected?.masked || ''} ${result.ok ? '检测成功' : '检测失败'}`" :type="result.ok ? 'success' : 'error'" :closable="false" class="result-alert"><template #default><span>本机→代理：{{ result.local_to_proxy_ms ?? '-' }} ms；代理→目标：{{ result.proxy_to_target_ms ?? '-' }} ms；HTTP：{{ result.http_status ?? '-' }}</span></template></el-alert>
  </div>
</template>

<style scoped>
.tool-page { display: flex; flex-direction: column; gap: 8px; height: 100%; min-width: 0; overflow: hidden; color: #24344d; } .page-heading { display: flex; align-items: center; justify-content: space-between; padding: 8px 12px; background: #fff; border: 1px solid #dce5ef; border-radius: 5px; } h1 { margin: 0; font-size: 20px; } p { margin: 3px 0 0; color: #7d8ba0; font-size: 12px; }
.tool-section { padding: 10px 12px; background: #fff; border: 1px solid #dce5ef; border-radius: 5px; } .section-title { display: flex; align-items: center; gap: 5px; margin-bottom: 9px; font-size: 14px; font-weight: 700; } .section-title .el-icon { color: #74859a; cursor: help; } .config-grid { display: grid; grid-template-columns: repeat(5, minmax(140px, 1fr)); gap: 0 10px; } .config-grid :deep(.el-form-item) { margin-bottom: 8px; } .config-grid :deep(.el-input), .config-grid :deep(.el-input-number) { width: 100%; } .section-actions { display: flex; justify-content: flex-end; }
.import-grid { display: grid; grid-template-columns: 170px 1fr 120px; gap: 10px; align-items: end; } .import-grid :deep(.el-form-item) { margin-bottom: 4px; } .subscription-grid { display: grid; grid-template-columns: 270px 1fr 100px; gap: 10px; align-items: end; } .filter-input { width: 260px; margin-left: auto; } .proxy-section { min-height: 0; flex: 1; overflow: hidden; } .result-alert { flex: 0 0 auto; }
</style>
