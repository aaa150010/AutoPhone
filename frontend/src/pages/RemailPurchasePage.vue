<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { getRemailProjects, getRemailWallet, purchaseRemail } from '../api/client'
import WorkspacePanel from '../components/WorkspacePanel.vue'

const loading = ref(false)
const projects = ref<any[]>([])
const wallet = ref<any>({})
const walletBalance = computed(() => wallet.value.consumerBalance ?? wallet.value.balance ?? wallet.value.amount ?? '-')
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
  <div class="remail-page">
    <WorkspacePanel title="购买参数" fill body-padding="compact"><template #actions><el-button size="small" :loading="loading" @click="load">刷新目录</el-button></template><el-form label-position="top" class="form-grid">
      <el-form-item label="ChatGPT 项目"><el-select v-model="projectId" size="small" filterable><el-option v-for="item in projects" :key="item.id" :label="item.name || item.id" :value="Number(item.id)" /></el-select></el-form-item>
      <el-form-item label="邮箱类型 / 后缀"><el-select v-model="suffix" size="small" filterable placeholder="选择有库存商品"><el-option v-for="item in products" :key="`${item.type}-${item.suffix}`" :label="`${item.type} · ${item.suffix} · 库存 ${item.available ?? '-'}`" :value="item.suffix" /></el-select></el-form-item>
      <el-form-item label="数量"><el-input-number v-model="quantity" size="small" :min="1" :max="100" /></el-form-item>
      <el-form-item label="库存策略"><el-radio-group v-model="supply" size="small"><el-radio value="private_first">私有优先</el-radio><el-radio value="public_only">仅公共库存</el-radio></el-radio-group></el-form-item>
    </el-form><div class="actions"><span>钱包余额：{{ walletBalance }} 积分</span><el-button size="small" type="primary" :loading="loading" @click="purchase">创建购买订单</el-button></div></WorkspacePanel>
  </div>
</template>
<style scoped>.remail-page{height:100%;min-width:0}.form-grid{display:grid;grid-template-columns:repeat(2,minmax(160px,200px));gap:0 12px;align-items:start}.form-grid :deep(.el-select),.form-grid :deep(.el-input-number){width:100%;max-width:200px}.form-grid :deep(.el-radio-group){min-height:28px;align-items:center}.form-grid :deep(.el-input__wrapper),.form-grid :deep(.el-select__wrapper),.form-grid :deep(.el-input-number){min-height:28px;height:28px}.actions{display:flex;justify-content:space-between;align-items:center;border-top:1px solid var(--workspace-border);padding-top:10px;color:var(--el-text-color-secondary)}.actions :deep(.el-button){min-height:28px;height:28px}</style>
