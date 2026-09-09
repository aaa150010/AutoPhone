<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { errorMessage } from '../utils/errorMessage'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Delete } from '@element-plus/icons-vue'
import { getRemailOrders, hideRemailOrders, importRemailOrders, type RemailOrder } from '../api/client'
import WorkspacePanel from '../components/WorkspacePanel.vue'
import { useColumnWidths } from '../composables/useColumnWidths'
import { formatDateTimeOrDash } from '../utils/datetime'
type DragColumn = { label?: string; noLabelText?: string }
const loading = ref(false); const rows = ref<RemailOrder[]>([]); const selected = ref<RemailOrder[]>([]); const filter = ref(''); const importedFilter = ref<boolean | 'all'>(false); const includeFailed = ref(false); const currentPage = ref(1); const pageSize = ref(50); const total = ref(0)
const { colWidth: orderColWidth, handleHeaderDragend: onOrderHeaderDragend } = useColumnWidths('gptphone.table.widths.remail-orders')
const formatTime = (value?: string) => formatDateTimeOrDash(value)
const deletable = (row: RemailOrder) => !row.imported && row.status === 'failed'
async function load(showMessage = true) { loading.value = true; try { const result = await getRemailOrders({ page: currentPage.value, page_size: pageSize.value, imported: importedFilter.value, search: filter.value, include_failed: includeFailed.value }); rows.value = result.orders || []; total.value = Number(result.total || 0); if (showMessage) ElMessage.success('订单已同步') } catch (error) { ElMessage.error(errorMessage(error) || 'Remail 订单同步失败') } finally { loading.value = false } }
async function importSelected() { if (!selected.value.length) return ElMessage.warning('请选择未导入订单'); loading.value = true; try { const result = await importRemailOrders(selected.value.map(row => row.order_no)); selected.value = []; const skipped = result.skipped?.length || 0; ElMessage[skipped ? 'warning' : 'success'](`已导入 ${result.imported.length} 个订单${skipped ? `，跳过 ${skipped} 个` : ''}`); await load(false) } catch (error) { ElMessage.error(errorMessage(error) || '订单导入失败') } finally { loading.value = false } }
async function deleteFailed(row: RemailOrder) {
  if (!deletable(row)) return
  try {
    await ElMessageBox.confirm(`将删除失败订单 ${row.order_no} 的本地记录，之后订单同步不再显示它。Remail 后台的原始订单不受影响。`, '删除失败订单记录', { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' })
  } catch { return }
  loading.value = true
  try {
    await hideRemailOrders([row.order_no])
    ElMessage.success('已删除失败订单记录')
    await load(false)
  } catch (error) { ElMessage.error(errorMessage(error) || '失败订单删除失败') } finally { loading.value = false }
}
watch([filter, importedFilter, includeFailed, pageSize], () => { currentPage.value = 1; void load(false) })
watch(currentPage, () => void load(false))
onMounted(() => void load(false))
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
          <el-checkbox v-model="includeFailed" size="small">显示失败订单</el-checkbox>
          <el-button size="small" type="primary" :disabled="!selected.length" :loading="loading" @click="importSelected">导入 Free 邮箱池</el-button>
          <el-button size="small" :loading="loading" @click="load">同步订单</el-button>
        </div>
        <el-table v-loading="loading" :data="rows" row-key="order_no" border @header-dragend="(newWidth: number, oldWidth: number, column: DragColumn) => onOrderHeaderDragend(newWidth, oldWidth, column)" @selection-change="selected = $event" size="small">
          <el-table-column type="selection" width="48" />
          <el-table-column prop="order_no" label="订单号" :min-width="orderColWidth('订单号', 200)" show-overflow-tooltip />
          <el-table-column prop="delivery_email_masked" label="邮箱" :min-width="orderColWidth('邮箱', 210)" show-overflow-tooltip />
          <el-table-column prop="status" label="状态" :width="orderColWidth('状态', 110)" show-overflow-tooltip />
          <el-table-column label="入池" :width="orderColWidth('入池', 92)">
            <template #default="scope"><el-tag size="small" :type="scope.row.imported ? 'success' : 'info'">{{ scope.row.imported ? '已导入' : '未导入' }}</el-tag></template>
          </el-table-column>
          <el-table-column label="商品" :min-width="orderColWidth('商品', 160)" show-overflow-tooltip>
            <template #default="scope">{{ scope.row.payload?.productType || scope.row.payload?.product_type || '-' }} / {{ scope.row.payload?.emailSuffix || scope.row.payload?.email_suffix || '-' }}</template>
          </el-table-column>
          <el-table-column label="创建时间" :width="orderColWidth('创建时间', 165)">
            <template #default="scope">{{ formatTime(scope.row.created_at) }}</template>
          </el-table-column>
          <el-table-column label="操作" :width="orderColWidth('操作', 84)" fixed="right" align="center">
            <template #default="scope">
              <el-tooltip v-if="deletable(scope.row)" content="删除本地失败订单记录，同步不再显示" placement="top" :show-after="250">
                <el-button text size="small" type="danger" :icon="Delete" aria-label="删除失败订单记录" @click="deleteFailed(scope.row)" />
              </el-tooltip>
              <span v-else class="muted">-</span>
            </template>
          </el-table-column>
        </el-table>
        <div class="pager">
          <el-pagination v-model:current-page="currentPage" v-model:page-size="pageSize" size="small" background layout="total, sizes, prev, pager, next" :page-sizes="[25,50,100]" :total="total" />
        </div>
      </div>
    </WorkspacePanel>
  </div>
</template>
<style scoped>
.remail-page { height: 100%; min-width: 0; }
.remail-page :deep(.workspace-panel) { height: 100%; }
.orders-content { display: grid; grid-template-rows: auto minmax(0, 1fr) 46px; height: 100%; min-height: 0; padding: 10px; gap: var(--workspace-gap); }
.toolbar { display: flex; align-items: center; gap: var(--workspace-gap); }
.toolbar .el-input { width: 220px; max-width: 220px; }
.import-filter { width: 150px; }
.muted { color: var(--el-text-color-secondary); }
.orders-content :deep(.el-table) { min-height: 0; }
.pager { display: flex; align-items: center; justify-content: flex-end; border-top: 1px solid var(--workspace-border); }
</style>
