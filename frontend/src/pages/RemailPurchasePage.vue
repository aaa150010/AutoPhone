<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { getRemailProjects, getRemailWallet, purchaseRemail } from '../api/client'
import PageToolbar from '../components/PageToolbar.vue'
import WorkspacePanel from '../components/WorkspacePanel.vue'

const loading = ref(false)
const projects = ref<any[]>([])
const wallet = ref<any>({})
const projectId = ref<number | undefined>()
const suffix = ref('')
const quantity = ref(1)
const supply = ref('private_first')
const products = computed(() => {
  const project = projects.value.find(item => Number(item.id) === Number(projectId.value))
  return (project?.products || []).flatMap((product: any) => (product.purchaseEnabled && Number(product.purchaseAvailable ?? product.totalAvailable ?? 0) > 0)
    ? (product.suffixes?.length ? product.suffixes.map((item: any) => ({ ...product, suffix: item.suffix, available: item.purchaseAvailable ?? item.totalAvailable })) : [{ ...product, suffix: product.type, available: product.purchaseAvailable ?? product.totalAvailable }]) : [])
})
async function load() {
  loading.value = true
  try {
    const result = await getRemailProjects()
    const value = result.projects
    projects.value = Array.isArray(value) ? value : (value?.items || [])
    if (!projectId.value && projects.value.length) projectId.value = Number(projects.value[0].id)
    wallet.value = (await getRemailWallet()).wallet || {}
  } catch (error: any) { ElMessage.error(error?.message || 'Remail 目录读取失败') } finally { loading.value = false }
}
async function purchase() {
  if (!projectId.value || !suffix.value) return ElMessage.warning('请选择项目和邮箱类型')
  loading.value = true
  try { await purchaseRemail({ project_id: projectId.value, email_suffix: suffix.value, quantity: quantity.value, supply: supply.value }); ElMessage.success('订单已创建，可在订单查询中确认并导入 Free 池'); await load() }
  catch (error: any) { ElMessage.error(error?.message || 'Remail 购买失败') } finally { loading.value = false }
}
onMounted(load)
</script>
<template>
  <div class="remail-page"><PageToolbar title="Remail 购买" status="ChatGPT 长效邮箱" tone="warning"><el-button size="small" :loading="loading" @click="load">刷新目录</el-button></PageToolbar>
    <WorkspacePanel title="购买参数" fill body-padding="compact"><el-form label-position="top" class="form-grid">
      <el-form-item label="ChatGPT 项目"><el-select v-model="projectId" filterable><el-option v-for="item in projects" :key="item.id" :label="item.name || item.id" :value="Number(item.id)" /></el-select></el-form-item>
      <el-form-item label="邮箱类型 / 后缀"><el-select v-model="suffix" filterable placeholder="选择有库存商品"><el-option v-for="item in products" :key="`${item.type}-${item.suffix}`" :label="`${item.type} · ${item.suffix} · 库存 ${item.available ?? '-'}`" :value="item.suffix" /></el-select></el-form-item>
      <el-form-item label="数量"><el-input-number v-model="quantity" :min="1" :max="100" /></el-form-item>
      <el-form-item label="库存策略"><el-radio-group v-model="supply"><el-radio value="private_first">私有优先</el-radio><el-radio value="public_only">仅公共库存</el-radio></el-radio-group></el-form-item>
    </el-form><div class="actions"><span>钱包余额：{{ wallet.balance ?? wallet.amount ?? '-' }}</span><el-button type="primary" :loading="loading" @click="purchase">创建购买订单</el-button></div></WorkspacePanel>
  </div>
</template>
<style scoped>.remail-page{display:grid;grid-template-rows:44px minmax(0,1fr);gap:6px;height:100%;min-width:0}.form-grid{display:grid;grid-template-columns:repeat(2,minmax(220px,1fr));gap:0 14px}.form-grid :deep(.el-select),.form-grid :deep(.el-input-number){width:100%}.actions{display:flex;justify-content:space-between;align-items:center;border-top:1px solid var(--workspace-border);padding-top:12px;color:var(--el-text-color-secondary)}</style>
