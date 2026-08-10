<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { RefreshLeft } from '@element-plus/icons-vue'
import type { MailboxRow } from '../types/api'
import ContentEmptyState from './ContentEmptyState.vue'

const props = defineProps<{
  modelValue: boolean
  rows: MailboxRow[]
  disabled?: boolean
  restoring?: boolean
}>()

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  restore: [rows: Array<{ row_id: string; line_no: number }>]
}>()

const tableRef = ref<any>()
const selectedRows = ref<MailboxRow[]>([])
const visible = computed({
  get: () => props.modelValue,
  set: value => emit('update:modelValue', value),
})

function clearSelection() {
  tableRef.value?.clearSelection()
  selectedRows.value = []
}

function credentialFormat(row: MailboxRow) {
  const values: string[] = []
  if (row.password) values.push('密码')
  if (row.has_totp) values.push('2FA')
  if (row.has_mailbox_url) values.push('取件 URL')
  return values.join(' / ') || '邮箱'
}

function draftRowKey(row: MailboxRow) {
  return `${row.row_id}:${row.line_no}`
}

function draftedAt(row: MailboxRow) {
  const timestamp = Number(row.updated_at || 0)
  if (!timestamp) return '-'
  const date = new Date(timestamp < 10_000_000_000 ? timestamp * 1000 : timestamp)
  return Number.isNaN(date.getTime()) ? '-' : date.toLocaleString('zh-CN', { hour12: false })
}

async function restoreSelected() {
  if (!selectedRows.value.length) {
    ElMessage.warning('请先选择草稿邮箱')
    return
  }
  try {
    await ElMessageBox.confirm(
      `将选中的 ${selectedRows.value.length} 个草稿邮箱放回可用状态？`,
      '草稿放回可用',
      { type: 'warning', confirmButtonText: '放回可用', cancelButtonText: '取消' },
    )
  } catch {
    return
  }

  const bindings = selectedRows.value.map(row => ({ row_id: row.row_id, line_no: row.line_no }))
  clearSelection()
  emit('restore', bindings)
}

watch(() => props.modelValue, async (open) => {
  if (!open) return clearSelection()
  await nextTick()
  clearSelection()
})
</script>

<template>
  <el-dialog v-model="visible" title="草稿箱" width="820px" append-to-body destroy-on-close>
    <el-table
      ref="tableRef"
      :data="rows"
      :row-key="draftRowKey"
      height="440px"
      stripe
      @selection-change="selectedRows = $event"
    >
      <el-table-column type="selection" width="46" reserve-selection :selectable="() => !disabled && !restoring" />
      <el-table-column prop="line_no" label="原序号" width="82" />
      <el-table-column prop="email" label="邮箱" min-width="270" show-overflow-tooltip />
      <el-table-column label="凭据类型" min-width="190">
        <template #default="{ row }">{{ credentialFormat(row) }}</template>
      </el-table-column>
      <el-table-column label="放入时间" width="176">
        <template #default="{ row }">{{ draftedAt(row) }}</template>
      </el-table-column>
      <template #empty><ContentEmptyState description="草稿箱为空" /></template>
    </el-table>
    <template #footer>
      <div class="draft-footer">
        <span>已选 {{ selectedRows.length }} 条</span>
        <div>
          <el-button @click="visible = false">关闭</el-button>
          <el-button
            type="primary"
            :icon="RefreshLeft"
            :loading="restoring"
            :disabled="disabled || restoring || !selectedRows.length"
            @click="restoreSelected"
          >放回可用</el-button>
        </div>
      </div>
    </template>
  </el-dialog>
</template>

<style scoped>
.draft-footer { display: flex; align-items: center; justify-content: space-between; }
.draft-footer > span { color: var(--el-text-color-secondary); font-size: 13px; }
</style>
