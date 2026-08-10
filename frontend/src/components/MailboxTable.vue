<script setup lang="ts">
import { ref } from 'vue'
import {
  Box,
  CircleCheck,
  CircleCloseFilled,
  CopyDocument,
  Delete,
  Key,
  Link,
  Loading,
  MoreFilled,
  RefreshLeft,
  RefreshRight,
  Refresh,
  View,
} from '@element-plus/icons-vue'
import ContentEmptyState from './ContentEmptyState.vue'
import TaskProgressCell from './TaskProgressCell.vue'
import { useTaskProgressClock } from '../composables/useTaskProgressClock'
import type { MailboxRow, MailboxRowAction } from '../types/api'
import { needsSub2Rerun } from '../utils/mailboxFilters'

const props = defineProps<{
  rows: MailboxRow[]
  loadingPasswords: string[]
  loadingTotp: string[]
  loadingQuotas: string[]
  quotaRetryDisabled: boolean
  rowActionDisabled: boolean
  rowActionLoading: string[]
}>()

const emit = defineEmits<{
  select: [MailboxRow[]]
  email: [MailboxRow]
  password: [MailboxRow]
  totp: [MailboxRow]
  url: [MailboxRow]
  quota: [MailboxRow]
  action: [MailboxRowAction, MailboxRow]
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
  if (String(value.kind || value.status) === 'not_ready') return value.label || '未上传'
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

function batchLabel(row: MailboxRow) {
  const value = Number(row.batch_started_at || 0)
  if (!value) return '-'
  const date = new Date(value < 10_000_000_000 ? value * 1000 : value)
  if (Number.isNaN(date.getTime())) return '-'
  return date.toLocaleString('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  })
}

function batchDetail(row: MailboxRow) {
  const label = batchLabel(row)
  return row.batch_id ? `${label} · ${row.batch_id}` : label
}

function quotaLabel(value: MailboxRow['quota_5h'], status?: MailboxRow['quota_status']) {
  if (value?.remaining_percent == null) return status === 'ok' ? '-' : status === 'error' ? '失败' : '未查询'
  return `${Number(value.remaining_percent).toFixed(1)}%`
}

function quotaDetail(
  value: MailboxRow['quota_5h'],
  status?: MailboxRow['quota_status'],
  error?: string,
) {
  if (status === 'error') {
    const parts = [error || 'OpenAI 额度查询失败']
    if (value?.remaining_percent != null) parts.push(`当前显示最近一次成功结果 ${quotaLabel(value, status)}`)
    return parts.join(' · ')
  }
  if (!value) {
    if (status === 'ok') return 'OpenAI 本次未返回该额度窗口'
    if (status === 'error') return 'OpenAI 额度查询失败'
    return '尚未查询 OpenAI 额度'
  }
  if (value.reset_at) {
    const date = new Date(Number(value.reset_at) * 1000)
    if (!Number.isNaN(date.getTime())) return `${quotaLabel(value, status)} · 重置 ${date.toLocaleString('zh-CN', { hour12: false })}`
  }
  return quotaLabel(value, status)
}

function quotaRetrying(row: MailboxRow) {
  return props.loadingQuotas.includes(row.row_id)
}

function rowActionLoading(row: MailboxRow) {
  return props.rowActionLoading.includes(row.row_id)
}

function emitRowAction(command: string, row: MailboxRow) {
  emit('action', command as MailboxRowAction, row)
}

function handleDropdownCommand(command: unknown, row: MailboxRow) {
  emitRowAction(String(command), row)
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
    <el-table-column prop="display_index" label="序号" width="64" />
    <el-table-column label="批次" width="132">
      <template #default="{ row }">
        <el-tooltip :content="batchDetail(row)" placement="top">
          <span class="batch-label">{{ batchLabel(row) }}</span>
        </el-tooltip>
      </template>
    </el-table-column>
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
    <el-table-column label="取件 URL" width="92" align="center">
      <template #default="{ row }">
        <el-tooltip v-if="row.has_mailbox_url" content="打开取件网页" placement="top">
          <el-button link size="small" :icon="View" @click="emit('url', row)">查看</el-button>
        </el-tooltip>
        <span v-else class="muted">-</span>
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
    <el-table-column label="2FA" width="86" align="center">
      <template #default="{ row }">
        <el-tooltip v-if="row.has_totp" content="复制临时 2FA 验证码" placement="top">
          <el-button
            link
            class="password-copy"
            :loading="loadingTotp.includes(row.row_id)"
            @click="emit('totp', row)"
          >*****</el-button>
        </el-tooltip>
        <span v-else class="muted">-</span>
      </template>
    </el-table-column>
    <el-table-column label="5h剩余" width="92" align="center">
      <template #default="{ row }">
        <el-tooltip :content="quotaDetail(row.quota_5h, row.quota_status, row.quota_error)" placement="top">
          <button
            v-if="row.quota_status === 'error'"
            type="button"
            class="quota-retry"
            :disabled="quotaRetryDisabled || quotaRetrying(row)"
            aria-label="重新查询 OpenAI 额度"
            @click="emit('quota', row)"
          >
            <el-icon :class="{ 'is-loading': quotaRetrying(row) }"><Refresh /></el-icon>
            <span>{{ quotaLabel(row.quota_5h, row.quota_status) }}</span>
          </button>
          <span v-else :class="['quota-value', row.quota_5h?.remaining_percent > 0 ? 'quota-available' : '']">{{ quotaLabel(row.quota_5h, row.quota_status) }}</span>
        </el-tooltip>
      </template>
    </el-table-column>
    <el-table-column label="7d剩余" width="92" align="center">
      <template #default="{ row }">
        <el-tooltip :content="quotaDetail(row.quota_7d, row.quota_status, row.quota_error)" placement="top">
          <button
            v-if="row.quota_status === 'error'"
            type="button"
            class="quota-retry"
            :disabled="quotaRetryDisabled || quotaRetrying(row)"
            aria-label="重新查询 OpenAI 额度"
            @click="emit('quota', row)"
          >
            <el-icon :class="{ 'is-loading': quotaRetrying(row) }"><Refresh /></el-icon>
            <span>{{ quotaLabel(row.quota_7d, row.quota_status) }}</span>
          </button>
          <span v-else :class="['quota-value', row.quota_7d?.remaining_percent > 0 ? 'quota-available' : '']">{{ quotaLabel(row.quota_7d, row.quota_status) }}</span>
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
    <el-table-column label="OpenAI 状态" width="190">
      <template #default="{ row }">
        <el-tooltip :content="sub2Detail(row)" placement="top">
          <el-tag :type="sub2Tone(row)" effect="light">{{ sub2Label(row) }}</el-tag>
        </el-tooltip>
      </template>
    </el-table-column>
    <el-table-column label="当前阶段" width="220">
      <template #default="{ row }"><TaskProgressCell :progress="row.progress" :timing="row.timing" :now-seconds="nowSeconds" :status="row.task_status || row.status" /></template>
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
    <el-table-column label="操作" width="88" fixed="right" align="center">
      <template #default="{ row }">
        <el-dropdown
          trigger="click"
          :disabled="rowActionDisabled || rowActionLoading(row)"
          @command="handleDropdownCommand($event, row)"
        >
          <el-tooltip content="打开该账号的常用操作" placement="top">
            <el-button
              link
              class="row-action-button"
              :disabled="rowActionDisabled"
              :loading="rowActionLoading(row)"
              aria-label="打开该账号的常用操作"
            >
              <el-icon v-if="rowActionLoading(row)" class="is-loading"><Loading /></el-icon>
              <el-icon v-else><MoreFilled /></el-icon>
            </el-button>
          </el-tooltip>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="copy_email">
                <el-icon><CopyDocument /></el-icon>复制邮箱
              </el-dropdown-item>
              <el-dropdown-item command="copy_password">
                <el-icon><Key /></el-icon>复制密码
              </el-dropdown-item>
              <el-dropdown-item v-if="row.has_totp" command="copy_totp">
                <el-icon><CopyDocument /></el-icon>复制 2FA
              </el-dropdown-item>
              <el-dropdown-item v-if="row.has_mailbox_url" command="open_url">
                <el-icon><Link /></el-icon>打开取件 URL
              </el-dropdown-item>
              <el-dropdown-item v-if="row.status === 'available'" command="manual_used">
                <el-icon><CircleCheck /></el-icon>标记已手动接码
              </el-dropdown-item>
              <el-dropdown-item
                v-if="row.status === 'consumed' && row.manual_sms_received"
                command="manual_unused"
              >
                <el-icon><RefreshLeft /></el-icon>标记未用并放回可用
              </el-dropdown-item>
              <el-dropdown-item v-if="row.status === 'available'" command="draft">
                <el-icon><Box /></el-icon>放入草稿箱
              </el-dropdown-item>
              <el-dropdown-item v-if="row.status === 'failed'" command="restore">
                <el-icon><RefreshLeft /></el-icon>恢复可用
              </el-dropdown-item>
              <el-dropdown-item v-if="row.status === 'available'" command="unavailable">
                <el-icon><CircleCloseFilled /></el-icon>设置不可用
              </el-dropdown-item>
              <el-dropdown-item v-if="needsSub2Rerun(row.sub2_status)" command="relogin">
                <el-icon><RefreshRight /></el-icon>重登并更新 SUB2
              </el-dropdown-item>
              <el-dropdown-item command="delete">
                <el-icon class="danger-icon"><Delete /></el-icon>
                <span class="danger-label">删除</span>
              </el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </template>
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
.batch-label { color: var(--el-text-color-regular); font-variant-numeric: tabular-nums; white-space: nowrap; }
.muted { color: var(--el-text-color-secondary); }
.quota-value { color: var(--el-text-color-secondary); font-variant-numeric: tabular-nums; }
.quota-available { color: var(--el-color-success); }
.quota-retry {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 64px;
  padding: 0;
  border: 0;
  background: transparent;
  color: var(--el-color-danger);
  font: inherit;
  font-variant-numeric: tabular-nums;
  gap: 4px;
  cursor: pointer;
}
.quota-retry:disabled { opacity: 0.6; cursor: not-allowed; }
.row-action-button { min-width: 30px; padding: 4px 8px; }
.danger-icon, .danger-label { color: var(--el-color-danger); }
</style>
