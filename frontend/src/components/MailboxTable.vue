<script setup lang="ts">
import { ref } from 'vue'
import ContentEmptyState from './ContentEmptyState.vue'
import TaskProgressCell from './TaskProgressCell.vue'
import { useTaskProgressClock } from '../composables/useTaskProgressClock'
import type { LatestCodeValue, MailboxRow } from '../types/api'

const props = defineProps<{
  rows: MailboxRow[]
  latestCodes: Record<string, LatestCodeValue>
  loadingCodes: string[]
  loadingPasswords: string[]
}>()

const emit = defineEmits<{
  select: [MailboxRow[]]
  code: [MailboxRow]
  password: [MailboxRow]
}>()

const tableRef = ref<any>()
const hasLiveTotp = () => Object.values(props.latestCodes).some((value) => (
  value.kind === 'totp' && (remaining(value) ?? 0) > 0
))
const nowSeconds = useTaskProgressClock(() => props.rows, hasLiveTotp)

function clearSelection() {
  tableRef.value?.clearSelection()
}

function remaining(value?: LatestCodeValue) {
  if (!value || value.kind !== 'totp' || value.remaining == null) return null
  return Math.max(0, Number(value.remaining) - Math.max(0, Math.floor(Date.now() / 1000 - value.receivedAt)))
}

function codeLabel(row: MailboxRow) {
  const value = props.latestCodes[row.row_id]
  if (!value) return '暂无'
  const seconds = remaining(value)
  if (seconds === 0) return '已过期'
  return seconds == null ? value.code || value.message || '暂无' : `${value.code} · ${seconds}s`
}

function costLabel(row: MailboxRow) {
  return row.sms_cost_cny == null ? '暂无' : `¥${Number(row.sms_cost_cny).toFixed(2)}`
}

function costDetail(row: MailboxRow) {
  if (row.sms_cost_cny == null) return ''
  const usd = row.sms_cost_usd == null ? '暂无' : `$${Number(row.sms_cost_usd).toFixed(4)}`
  const rate = row.sms_exchange_rate == null ? '暂无' : Number(row.sms_exchange_rate).toFixed(4)
  return `美元报价 ${usd} · USD/CNY ${rate} · ${row.sms_exchange_date || '未知日期'}`
}

defineExpose({ clearSelection })
</script>

<template>
  <el-table
    ref="tableRef"
    class="mailbox-table"
    :data="rows"
    row-key="row_id"
    height="100%"
    stripe
    @selection-change="emit('select', $event)"
  >
    <el-table-column type="selection" width="45" reserve-selection />
    <el-table-column prop="line_no" label="#" width="58" />
    <el-table-column label="邮箱" min-width="180" show-overflow-tooltip>
      <template #default="{ row }"><span class="mailbox-address">{{ row.email || '-' }}</span></template>
    </el-table-column>
    <el-table-column label="密码" width="94" align="center">
      <template #default="{ row }">
        <el-tooltip content="复制明文密码" placement="top">
          <el-button
            link
            class="password-copy"
            :loading="loadingPasswords.includes(row.row_id)"
            @click="emit('password', row)"
          >*****</el-button>
        </el-tooltip>
      </template>
    </el-table-column>
    <el-table-column label="状态" width="96">
      <template #default="{ row }">
        <el-tag :type="row.status === 'consumed' ? 'success' : row.status === 'failed' ? 'danger' : row.status === 'running' ? 'warning' : 'info'">
          {{ row.status_label || row.status }}
        </el-tag>
      </template>
    </el-table-column>
    <el-table-column label="当前阶段" width="190">
      <template #default="{ row }"><TaskProgressCell :progress="row.progress" :now-seconds="nowSeconds" /></template>
    </el-table-column>
    <el-table-column label="接码成本" width="98" align="right">
      <template #default="{ row }">
        <el-tooltip v-if="row.sms_cost_cny != null" :content="costDetail(row)" placement="top">
          <span class="sms-cost">{{ costLabel(row) }}</span>
        </el-tooltip>
        <span v-else class="muted">暂无</span>
      </template>
    </el-table-column>
    <el-table-column label="失败原因/说明" min-width="220" show-overflow-tooltip>
      <template #default="{ row }">{{ row.error || row.reason || '-' }}</template>
    </el-table-column>
    <el-table-column label="验证码" width="126">
      <template #default="{ row }"><span class="code-value">{{ codeLabel(row) }}</span></template>
    </el-table-column>
    <el-table-column label="操作" width="72" fixed="right">
      <template #default="{ row }">
        <el-button link type="primary" :loading="loadingCodes.includes(row.row_id)" @click="emit('code', row)">查码</el-button>
      </template>
    </el-table-column>
    <template #empty><ContentEmptyState /></template>
  </el-table>
</template>

<style scoped>
.mailbox-table { width: 100%; height: 100%; min-height: 0; }
.mailbox-address { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; }
.password-copy { min-width: 48px; padding: 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: 0; }
.sms-cost { color: var(--el-color-success); font-variant-numeric: tabular-nums; cursor: help; }
.code-value { color: var(--el-color-primary); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; font-variant-numeric: tabular-nums; }
.muted { color: var(--el-text-color-secondary); }
</style>
