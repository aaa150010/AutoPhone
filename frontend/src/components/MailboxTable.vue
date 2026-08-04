<script setup lang="ts">
import { ref } from 'vue'
import ContentEmptyState from './ContentEmptyState.vue'
import TaskProgressCell from './TaskProgressCell.vue'
import { useTaskProgressClock } from '../composables/useTaskProgressClock'
import type { MailboxRow } from '../types/api'

const props = defineProps<{
  rows: MailboxRow[]
  loadingPasswords: string[]
}>()

const emit = defineEmits<{
  select: [MailboxRow[]]
  email: [MailboxRow]
  password: [MailboxRow]
}>()

const tableRef = ref<any>()
const nowSeconds = useTaskProgressClock(() => props.rows)

function clearSelection() {
  tableRef.value?.clearSelection()
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

function sub2Value(row: MailboxRow) {
  return row.sub2_status || (row as any).sub2 || null
}

function sub2Code(row: MailboxRow) {
  const value = sub2Value(row)
  const code = Number(value?.status_code ?? value?.code)
  return Number.isFinite(code) && code > 0 ? code : null
}

function sub2Label(row: MailboxRow) {
  const value = sub2Value(row)
  if (!value) return '未测试'
  if (value.label) return value.label
  if (value.linked === false || ['unlinked', 'not_linked'].includes(String(value.kind || value.status))) return '未关联'
  const code = sub2Code(row)
  if (code === 200) return '200 健康'
  if (code === 401) return '401 Token失效'
  if (code === 429) return '429 额度受限'
  if (code === 404) return '404 账号不存在'
  const kind = String(value.kind || value.status || '').toLowerCase()
  if (kind === 'timeout') return '超时'
  if (kind === 'network_error') return '网络错误'
  if (kind === 'protocol_error') return '协议错误'
  return kind && kind !== 'untested' ? kind : '未测试'
}

function sub2Tone(row: MailboxRow): 'success' | 'warning' | 'danger' | 'info' {
  const value = sub2Value(row)
  const code = sub2Code(row)
  if (code === 200) return 'success'
  if (code === 429) return 'warning'
  if (value?.is_test_failure || value?.needs_rerun || [401, 404].includes(Number(code))) return 'danger'
  if (value?.is_error || value?.is_abnormal) return 'danger'
  return 'info'
}

function explanation(row: MailboxRow) {
  const value = String(row.error || row.reason || '').trim()
  return value === 'sub2_uploaded' ? '-' : value || '-'
}

function sub2Detail(row: MailboxRow) {
  const value = sub2Value(row)
  if (!value) return '尚未测试'
  const parts = [sub2Label(row)]
  if (value.summary) parts.push(String(value.summary))
  if (value.tested_at) {
    const numeric = Number(value.tested_at)
    const date = Number.isFinite(numeric)
      ? new Date(numeric < 10_000_000_000 ? numeric * 1000 : numeric)
      : new Date(String(value.tested_at))
    if (!Number.isNaN(date.getTime())) parts.push(date.toLocaleString('zh-CN', { hour12: false }))
  }
  return parts.join(' · ')
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
    <el-table-column label="邮箱" min-width="230">
      <template #default="{ row }">
        <el-tooltip v-if="row.email" content="点击复制邮箱" placement="top">
          <button
            type="button"
            class="mailbox-address"
            aria-label="复制邮箱"
            @click="emit('email', row)"
          >{{ row.email }}</button>
        </el-tooltip>
        <span v-else>-</span>
      </template>
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
    <el-table-column label="状态" width="105">
      <template #default="{ row }">
        <el-tag :type="row.status === 'consumed' ? 'success' : row.status === 'failed' ? 'danger' : row.status === 'running' ? 'warning' : 'info'">
          {{ row.status_label || row.status }}
        </el-tag>
      </template>
    </el-table-column>
    <el-table-column label="SUB2 状态" width="168">
      <template #default="{ row }">
        <el-tooltip :content="sub2Detail(row)" placement="top">
          <el-tag :type="sub2Tone(row)" effect="light">{{ sub2Label(row) }}</el-tag>
        </el-tooltip>
      </template>
    </el-table-column>
    <el-table-column label="当前阶段" width="220">
      <template #default="{ row }"><TaskProgressCell :progress="row.progress" :now-seconds="nowSeconds" /></template>
    </el-table-column>
    <el-table-column label="接码成本" width="110" align="right">
      <template #default="{ row }">
        <el-tooltip v-if="row.sms_cost_cny != null" :content="costDetail(row)" placement="top">
          <span class="sms-cost">{{ costLabel(row) }}</span>
        </el-tooltip>
        <span v-else class="muted">暂无</span>
      </template>
    </el-table-column>
    <el-table-column label="失败原因/说明" min-width="300" show-overflow-tooltip>
      <template #default="{ row }">{{ explanation(row) }}</template>
    </el-table-column>
    <template #empty><ContentEmptyState /></template>
  </el-table>
</template>

<style scoped>
.mailbox-table { width: 100%; height: 100%; min-height: 0; }
.mailbox-address {
  display: block;
  max-width: 100%;
  overflow: hidden;
  padding: 0;
  border: 0;
  background: transparent;
  color: var(--el-color-primary);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 13px;
  text-align: left;
  text-overflow: ellipsis;
  white-space: nowrap;
  cursor: copy;
}
.mailbox-address:focus-visible { outline: 2px solid var(--el-color-primary-light-5); outline-offset: 2px; border-radius: 2px; }
.password-copy { min-width: 48px; padding: 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: 0; }
.sms-cost { color: var(--el-color-success); font-variant-numeric: tabular-nums; cursor: help; }
.muted { color: var(--el-text-color-secondary); }
</style>
