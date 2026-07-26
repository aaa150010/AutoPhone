<script setup lang="ts">
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import type { MailboxRow } from '../types/api'

const props = defineProps<{
  rows: MailboxRow[]
  latestCodes: Record<number, string>
  loadingLines: number[]
}>()

const emit = defineEmits<{
  select: [number[]]
  code: [number]
}>()

const tableRef = ref<any>()

function rowKey(row: MailboxRow) {
  return row.source_row
}

function selection(rows: MailboxRow[]) {
  emit('select', rows.map(row => row.line_no))
}

function clearSelection() {
  tableRef.value?.clearSelection()
}

defineExpose({ clearSelection })

async function copy(value: string | undefined, label: string) {
  const text = String(value || '')
  if (!text) return

  try {
    if (navigator.clipboard) {
      await navigator.clipboard.writeText(text)
    } else {
      const input = document.createElement('textarea')
      input.value = text
      document.body.appendChild(input)
      input.select()
      document.execCommand('copy')
      input.remove()
    }
    ElMessage.success(`已复制${label}`)
  } catch {
    ElMessage.error(`复制${label}失败`)
  }
}

function costLabel(row: MailboxRow) {
  return row.sms_cost_cny == null ? '暂无' : `¥${Number(row.sms_cost_cny).toFixed(2)}`
}

function costDetail(row: MailboxRow) {
  if (row.sms_cost_cny == null) return ''
  const usd = row.sms_cost_usd == null ? '暂无' : `$${Number(row.sms_cost_usd).toFixed(4)}`
  const rate = row.sms_exchange_rate == null ? '暂无' : Number(row.sms_exchange_rate).toFixed(4)
  const date = row.sms_exchange_date || '未知日期'
  return `美元报价 ${usd} · USD/CNY ${rate} · ${date}`
}
</script>

<template>
  <el-table
    ref="tableRef"
    class="mailbox-table"
    :data="rows"
    :row-key="rowKey"
    height="100%"
    @selection-change="selection"
  >
    <el-table-column type="selection" width="46" reserve-selection />
    <el-table-column prop="line_no" label="#" width="65" />
    <el-table-column label="邮箱" min-width="165" show-overflow-tooltip>
      <template #default="{ row }">
        <el-button class="copy-value" link @click="copy(row.email, '邮箱')">
          {{ row.email || '-' }}
        </el-button>
      </template>
    </el-table-column>
    <el-table-column label="密码" min-width="120" show-overflow-tooltip>
      <template #default="{ row }">
        <el-button class="copy-value" link @click="copy(row.password, '密码')">
          {{ row.password || '-' }}
        </el-button>
      </template>
    </el-table-column>
    <el-table-column label="接码成本" width="105" align="right">
      <template #default="{ row }">
        <el-tooltip v-if="row.sms_cost_cny != null" :content="costDetail(row)" placement="top">
          <span class="sms-cost">{{ costLabel(row) }}</span>
        </el-tooltip>
        <span v-else class="muted">暂无</span>
      </template>
    </el-table-column>
    <el-table-column label="状态" width="110">
      <template #default="{ row }">
        <el-tag :type="row.status === 'consumed' ? 'success' : row.status === 'failed' ? 'danger' : 'info'">
          {{ row.status_label || row.status }}
        </el-tag>
      </template>
    </el-table-column>
    <el-table-column label="失败原因/说明" min-width="240" show-overflow-tooltip>
      <template #default="{ row }">{{ row.error || row.reason || '-' }}</template>
    </el-table-column>
    <el-table-column label="操作" width="90">
      <template #default="{ row }">
        <el-button
          link
          type="primary"
          :loading="props.loadingLines.includes(row.line_no)"
          @click="emit('code', row.line_no)"
        >查码</el-button>
      </template>
    </el-table-column>
    <el-table-column label="验证码" width="100">
      <template #default="{ row }">{{ props.latestCodes[row.line_no] || '暂无' }}</template>
    </el-table-column>
  </el-table>
</template>

<style scoped>
.copy-value {
  max-width: 100%;
  padding: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  vertical-align: middle;
}
.sms-cost { color: var(--el-color-success); font-variant-numeric: tabular-nums; cursor: help; }
.muted { color: var(--el-text-color-secondary); }
</style>
