<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { getRemailOrders, importRemailOrders, type RemailOrder } from '../api/client'
import WorkspacePanel from '../components/WorkspacePanel.vue'
const loading = ref(false); const rows = ref<RemailOrder[]>([]); const selected = ref<RemailOrder[]>([]); const filter = ref(''); const importedFilter = ref<boolean | 'all'>(false); const currentPage = ref(1); const pageSize = ref(50); const total = ref(0)
const formatTime = (value?: string) => value ? new Date(value).toLocaleString() : '-'
async function load(showMessage = true) { loading.value = true; try { const result = await getRemailOrders({ page: currentPage.value, page_size: pageSize.value, imported: importedFilter.value, search: filter.value }); rows.value = result.orders || []; total.value = Number(result.total || 0); if (showMessage) ElMessage.success('订单已同步') } catch (error: any) { ElMessage.error(error?.message || 'Remail 订单同步失败') } finally { loading.value = false } }
async function importSelected() { if (!selected.value.length) return ElMessage.warning('请选择未导入订单'); loading.value = true; try { const result = await importRemailOrders(selected.value.map(row => row.order_no)); selected.value = []; ElMessage.success(`已导入 ${result.imported.length} 个订单`); await load(false) } catch (error: any) { ElMessage.error(error?.message || '订单导入失败') } finally { loading.value = false } }
watch([filter, importedFilter, pageSize], () => { currentPage.value = 1; void load(false) })
watch(currentPage, () => void load(false))
onMounted(load)
</script>
<template>
  <div class="remail-page">
    <WorkspacePanel title="长效购买订单" fill body-padding="none">
      <div class="orders-content">
        <div class="toolbar">
          <el-input v-model="filter" size="small" clearable placeholder="搜索订单号、邮箱或状态" />
          <el-select v-model="importedFilter" size="small" class="import-filter">
            <el-option label="未导入 Free 池" :value="false" />
            <el-option label="全部订单" value="all" />
            <el-option label="已导入" :value="true" />
          </el-select>
          <el-button size="small" type="primary" :disabled="!selected.length" :loading="loading" @click="importSelected">导入 Free 邮箱池</el-button>
          <el-button size="small" :loading="loading" @click="load">同步订单</el-button>
        </div>
        <el-table v-loading="loading" :data="rows" row-key="order_no" @selection-change="selected = $event">
          <el-table-column type="selection" width="48" />
          <el-table-column prop="order_no" label="订单号" min-width="180" show-overflow-tooltip />
          <el-table-column prop="delivery_email_masked" label="邮箱" min-width="190" show-overflow-tooltip />
          <el-table-column prop="status" label="状态" width="120" show-overflow-tooltip />
          <el-table-column label="入池" width="100">
            <template #default="scope"><el-tag :type="scope.row.imported ? 'success' : 'info'">{{ scope.row.imported ? '已导入' : '未导入' }}</el-tag></template>
          </el-table-column>
          <el-table-column label="商品" min-width="150" show-overflow-tooltip>
            <template #default="scope">{{ scope.row.payload?.productType || scope.row.payload?.product_type || '-' }} / {{ scope.row.payload?.emailSuffix || scope.row.payload?.email_suffix || '-' }}</template>
          </el-table-column>
          <el-table-column label="创建时间" width="156">
            <template #default="scope">{{ formatTime(scope.row.created_at) }}</template>
          </el-table-column>
        </el-table>
        <div class="pager">
          <span>共 {{ total }} 条</span>
          <el-pagination v-model:current-page="currentPage" v-model:page-size="pageSize" background layout="sizes, prev, pager, next" :page-sizes="[25,50,100]" :total="total" />
        </div>
      </div>
    </WorkspacePanel>
  </div>
</template>
<style scoped>.remail-page{height:100%;min-width:0}.remail-page :deep(.workspace-panel){height:100%}.orders-content{display:grid;grid-template-rows:auto minmax(0,1fr) auto;height:100%;min-height:0}.toolbar{display:flex;align-items:center;gap:6px;padding:6px;border-bottom:1px solid var(--workspace-border)}.toolbar .el-input{width:180px;max-width:180px}.import-filter{width:150px}.toolbar :deep(.el-input__wrapper),.toolbar :deep(.el-select__wrapper),.toolbar :deep(.el-button){box-sizing:border-box;min-height:28px;height:28px}.toolbar :deep(.el-select){width:150px;height:28px}.orders-content :deep(.el-table){min-height:0}.pager{display:flex;align-items:center;justify-content:space-between;padding:6px;border-top:1px solid var(--workspace-border);color:var(--el-text-color-secondary);font-size:12px}.pager :deep(.el-pagination){height:28px}</style>
