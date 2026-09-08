<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { errorMessage } from '../utils/errorMessage'
import { ElMessage } from 'element-plus'
import { getRemailProjects, getRemailWallet, purchaseRemail, type RemailProject, type RemailProjectProduct, type RemailWallet } from '../api/client'
import WorkspacePanel from '../components/WorkspacePanel.vue'

const loading = ref(false)
const projects = ref<RemailProject[]>([])
const wallet = ref<RemailWallet>({})
const walletBalance = computed(() => wallet.value.consumerBalance ?? wallet.value.balance ?? wallet.value.amount ?? '-')
const projectId = ref<number | undefined>()
const suffix = ref('')
const quantity = ref(1)
const supply = ref('private_first')
const products = computed(() => {
  const project = projects.value.find(item => Number(item.id) === Number(projectId.value))
  // Remail's optional emailSuffix is a mailbox domain (icloud.com/gmail.com) or a
  // special value (gmail_variant/domain); products without a suffixes list must not
  // use the type name as a suffix, or the server treats it as a private domain and
  // rejects the order with insufficient_inventory.
  const typeSuffixes: Record<string, string> = { icloud: 'icloud.com', gmail: 'gmail.com' }
  return (project?.products || []).flatMap((product: RemailProjectProduct) => (product.purchaseEnabled && Number(product.purchaseAvailable ?? product.totalAvailable ?? 0) > 0)
    ? (product.suffixes?.length ? product.suffixes.map((item: { suffix?: string; purchaseAvailable?: number | string; totalAvailable?: number | string }) => ({ ...product, suffix: item.suffix, available: item.purchaseAvailable ?? item.totalAvailable })) : [{ ...product, suffix: typeSuffixes[product.type || ''] || product.type, available: product.purchaseAvailable ?? product.totalAvailable }]) : [])
})
// Unit price = purchasePrice × priceMultiplier (the server deducts credits by the
// multiplier; a missing multiplier counts as 1).
function productPrice(item: RemailProjectProduct | Record<string, unknown> | undefined): string {
  if (!item || typeof item !== 'object') return ''
  const base = Number(item.purchasePrice)
  if (!Number.isFinite(base) || base <= 0) return ''
  const multiplier = Number(item.priceMultiplier)
  const value = Number.isFinite(multiplier) && multiplier > 0 ? base * multiplier : base
  return value % 1 === 0 ? String(value) : value.toFixed(2)
}
const totalPrice = computed(() => {
  const selected = products.value.find((item: RemailProjectProduct) => item.suffix === suffix.value)
  const unit = productPrice(selected)
  if (!unit) return ''
  const value = Number(unit) * Math.max(1, Number(quantity.value) || 1)
  return value % 1 === 0 ? String(value) : value.toFixed(2)
})
async function load() {
  loading.value = true
  try {
    const result = await getRemailProjects()
    const value = result.projects
    projects.value = Array.isArray(value) ? value : (value?.items || [])
    if (!projectId.value && projects.value.length) projectId.value = Number(projects.value[0].id)
    wallet.value = (await getRemailWallet()).wallet || {}
  } catch (error) { ElMessage.error(errorMessage(error) || 'Remail 目录读取失败') } finally { loading.value = false }
}
async function purchase() {
  if (!projectId.value || !suffix.value) return ElMessage.warning('请选择项目和邮箱类型')
  loading.value = true
  try { await purchaseRemail({ project_id: projectId.value, email_suffix: suffix.value, quantity: quantity.value, supply: supply.value }); ElMessage.success('订单已创建，可在订单查询中确认并导入 Free 池'); await load() }
  catch (error) { ElMessage.error(errorMessage(error) || 'Remail 购买失败') } finally { loading.value = false }
}
onMounted(load)
</script>
<template>
  <div class="remail-page">
    <WorkspacePanel title="购买参数" fill body-padding="compact"><template #actions><el-button size="small" :loading="loading" @click="load">刷新目录</el-button></template><el-form label-position="right" label-width="110px" class="form-grid">
      <el-form-item label="ChatGPT 项目"><el-select v-model="projectId" size="small" filterable autocomplete="nope"><el-option v-for="item in projects" :key="item.id" :label="item.name || item.id" :value="Number(item.id)" /></el-select></el-form-item>
      <el-form-item label="邮箱类型 / 后缀"><el-select v-model="suffix" size="small" filterable autocomplete="nope" placeholder="选择有库存商品"><el-option v-for="item in products" :key="`${item.type}-${item.suffix}`" :label="`${item.type} · ${item.suffix} · 库存 ${item.available ?? '-'}${productPrice(item) ? ` · ${productPrice(item)} 积分/个` : ''}`" :value="item.suffix" /></el-select></el-form-item>
      <el-form-item label="数量"><el-input-number v-model="quantity" size="small" :min="1" :max="100" /></el-form-item>
      <el-form-item label="库存策略"><el-radio-group v-model="supply" size="small"><el-radio value="private_first">私有优先</el-radio><el-radio value="public_only">仅公共库存</el-radio></el-radio-group></el-form-item>
    </el-form><div class="actions"><span>钱包余额：{{ walletBalance }} 积分<template v-if="totalPrice">　·　预计消耗：{{ totalPrice }} 积分</template></span><el-button size="small" type="primary" :loading="loading" @click="purchase">创建购买订单</el-button></div></WorkspacePanel>
  </div>
</template>
<style scoped>
.remail-page { height: 100%; min-width: 0; }
.form-grid { display: grid; grid-template-columns: repeat(2, minmax(300px, 420px)); gap: 0 24px; align-items: start; }
.form-grid :deep(.el-form-item__label) { color: var(--el-text-color-secondary); font-weight: 600; }
.form-grid :deep(.el-select), .form-grid :deep(.el-input-number) { width: 100%; }
.form-grid :deep(.el-radio-group) { min-height: 32px; align-items: center; }
.actions { display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--workspace-border); padding-top: 10px; color: var(--el-text-color-secondary); }
</style>
