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
  MoreFilled,
  RefreshLeft,
  RefreshRight,
  Refresh,
  Tickets,
} from '@element-plus/icons-vue'
import ContentEmptyState from './ContentEmptyState.vue'
import TaskProgressCell from './TaskProgressCell.vue'
import StateDot from './StateDot.vue'
import { useTaskProgressClock } from '../composables/useTaskProgressClock'
import { useColumnWidths } from '../composables/useColumnWidths'
import type { MailboxRow, MailboxRowAction } from '../types/api'
import { needsSub2Rerun } from '../utils/mailboxFilters'
import {
  batchDetail,
  batchLabel,
  costDetail,
  costLabel,
  createdText,
  explanation,
  quotaDetail,
  quotaLabel,
  statusLabel,
  statusTagType,
  sub2Detail,
  sub2Label,
  sub2Tone,
} from '../utils/mailboxRowDisplay'
type DragColumn = { label?: string; noLabelText?: string }

const props = defineProps<{
  rows: MailboxRow[]
  loading: boolean
  loadingPasswords: string[]
  loadingTotp: string[]
  loadingQuotas: string[]
  loadingOpenAI: string[]
  quotaRetryDisabled: boolean
  openaiRetryDisabled: boolean
  rowMutationDisabled: boolean
  rowActionLoading: string[]
}>()

const emit = defineEmits<{
  select: [MailboxRow[]]
  email: [MailboxRow]
  password: [MailboxRow]
  totp: [MailboxRow]
  url: [MailboxRow]
  latestCode: [MailboxRow]
  quota: [MailboxRow]
  openai: [MailboxRow]
  action: [MailboxRowAction, MailboxRow]
}>()

const tableRef = ref<{ clearSelection: () => void } | null>(null)
const nowSeconds = useTaskProgressClock(() => props.rows)
const { colWidth: smsColWidth, handleHeaderDragend: onSmsHeaderDragend } = useColumnWidths('gptphone.table.widths.sms-mailbox')

function clearSelection() {
  tableRef.value?.clearSelection()
}

function quotaRetrying(row: MailboxRow) {
  return props.loadingQuotas.includes(row.row_id)
}

function openaiRetrying(row: MailboxRow) {
  return props.loadingOpenAI.includes(row.row_id)
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
    v-loading="loading"
    class="mailbox-table"
    :data="rows"
    row-key="row_id"
    height="100%"
    stripe
    border
    @header-dragend="(newWidth: number, oldWidth: number, column: DragColumn) => onSmsHeaderDragend(newWidth, oldWidth, column)"
    @selection-change="emit('select', $event)" size="small">
    <el-table-column type="selection" width="45" reserve-selection />
    <el-table-column label="批次" :width="smsColWidth('批次', 150)" show-overflow-tooltip>
      <template #default="{ row }">
        <div class="batch-cell">
          <el-tooltip :content="batchDetail(row)" placement="top" :show-after="250">
            <span class="batch-label">{{ batchLabel(row) }}</span>
          </el-tooltip>
          <span class="batch-subline">{{ createdText(row) || '-' }}</span>
        </div>
      </template>
    </el-table-column>
    <el-table-column label="邮箱" :min-width="smsColWidth('邮箱', 230)" show-overflow-tooltip>
      <template #default="{ row }">
        <el-tooltip v-if="row.email" content="点击复制邮箱" placement="top" :show-after="250">
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
    <el-table-column label="密码" :width="smsColWidth('密码', 94)" align="center">
      <template #default="{ row }">
        <el-tooltip content="复制明文密码" placement="top" :show-after="250">
          <el-button
            link
            class="password-copy"
            :loading="loadingPasswords.includes(row.row_id)"
            @click="emit('password', row)"
          >*****</el-button>
        </el-tooltip>
      </template>
    </el-table-column>
    <el-table-column label="2FA" :width="smsColWidth('2FA', 86)" align="center">
      <template #default="{ row }">
        <el-tooltip v-if="row.has_totp" content="复制临时 2FA 验证码" placement="top" :show-after="250">
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
    <el-table-column label="5h剩余" :width="smsColWidth('5h剩余', 92)" align="center">
      <template #default="{ row }">
        <el-tooltip :content="quotaDetail(row.quota_5h, row.quota_status, row.quota_error)" placement="top" :show-after="250">
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
          <span v-else :class="['quota-value', Number(row.quota_5h?.remaining_percent ?? 0) > 0 ? 'quota-available' : '']">{{ quotaLabel(row.quota_5h, row.quota_status) }}</span>
        </el-tooltip>
      </template>
    </el-table-column>
    <el-table-column label="7d剩余" :width="smsColWidth('7d剩余', 92)" align="center">
      <template #default="{ row }">
        <el-tooltip :content="quotaDetail(row.quota_7d, row.quota_status, row.quota_error)" placement="top" :show-after="250">
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
          <span v-else :class="['quota-value', Number(row.quota_7d?.remaining_percent ?? 0) > 0 ? 'quota-available' : '']">{{ quotaLabel(row.quota_7d, row.quota_status) }}</span>
        </el-tooltip>
      </template>
    </el-table-column>
    <el-table-column label="状态" :width="smsColWidth('状态', 150)">
      <template #default="{ row }">
        <el-tag :type="statusTagType(row)">
          {{ statusLabel(row) }}
        </el-tag>
      </template>
    </el-table-column>
    <el-table-column label="OpenAI 状态" :min-width="smsColWidth('OpenAI 状态', 170)" show-overflow-tooltip>
      <template #default="{ row }">
        <el-tooltip :content="`点击重新查询 OpenAI 状态 · ${sub2Detail(row)}`" placement="top" :show-after="250">
          <button
            type="button"
            class="openai-status-retry"
            :disabled="openaiRetryDisabled || openaiRetrying(row)"
            :aria-label="`重新查询 ${row.email || '该邮箱'} 的 OpenAI 状态`"
            @click="emit('openai', row)"
          >
            <StateDot :tone="sub2Tone(row)" :label="sub2Label(row)" />
            <el-icon :class="{ 'is-loading': openaiRetrying(row) }"><Refresh /></el-icon>
          </button>
        </el-tooltip>
      </template>
    </el-table-column>
    <el-table-column label="当前阶段" :min-width="smsColWidth('当前阶段', 220)" show-overflow-tooltip>
      <template #default="{ row }"><TaskProgressCell :progress="row.progress" :timing="row.timing" :now-seconds="nowSeconds" :status="row.task_status || row.status" /></template>
    </el-table-column>
    <el-table-column label="接码成本" :width="smsColWidth('接码成本', 110)" align="right">
      <template #default="{ row }">
        <el-tooltip v-if="row.sms_cost_cny != null" :content="costDetail(row)" placement="top" :show-after="250">
          <span class="sms-cost">{{ costLabel(row) }}</span>
        </el-tooltip>
        <span v-else class="muted">暂无</span>
      </template>
    </el-table-column>
    <el-table-column label="失败原因/说明" :min-width="smsColWidth('失败原因/说明', 300)" show-overflow-tooltip>
      <template #default="{ row }">{{ explanation(row) }}</template>
    </el-table-column>
    <el-table-column label="操作" :width="smsColWidth('操作', 82)" fixed="right" align="center">
      <template #default="{ row }">
        <el-dropdown
          trigger="click"
          :disabled="rowActionLoading(row)"
          @command="handleDropdownCommand($event, row)"
        >
          <el-button
            link
            class="row-action-button"
            :loading="rowActionLoading(row)"
            aria-label="打开该账号的常用操作"
            title="打开该账号的常用操作"
          >
            <el-icon><MoreFilled /></el-icon>
          </el-button>
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
              <el-dropdown-item command="copy_latest_code">
                <el-icon><Tickets /></el-icon>提取并复制最新验证码
              </el-dropdown-item>
              <el-dropdown-item
                v-if="row.status === 'available'"
                command="manual_used"
                :disabled="rowMutationDisabled"
              >
                <el-icon><CircleCheck /></el-icon>标记已手动接码
              </el-dropdown-item>
              <el-dropdown-item
                v-if="row.status === 'consumed' && row.manual_sms_received"
                command="manual_unused"
                :disabled="rowMutationDisabled"
              >
                <el-icon><RefreshLeft /></el-icon>标记未用并放回可用
              </el-dropdown-item>
              <el-dropdown-item
                v-if="row.status === 'available'"
                command="draft"
                :disabled="rowMutationDisabled"
              >
                <el-icon><Box /></el-icon>放入草稿箱
              </el-dropdown-item>
              <el-dropdown-item
                v-if="row.status === 'failed'"
                command="restore"
                :disabled="rowMutationDisabled"
              >
                <el-icon><RefreshLeft /></el-icon>恢复可用
              </el-dropdown-item>
              <el-dropdown-item
                v-if="row.status === 'available'"
                command="unavailable"
                :disabled="rowMutationDisabled"
              >
                <el-icon><CircleCloseFilled /></el-icon>设置不可用
              </el-dropdown-item>
              <el-dropdown-item
                v-if="needsSub2Rerun(row.sub2_status)"
                command="relogin"
                :disabled="rowMutationDisabled"
              >
                <el-icon><RefreshRight /></el-icon>重登并更新 SUB2
              </el-dropdown-item>
              <el-dropdown-item command="delete" :disabled="rowMutationDisabled">
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
  color: var(--el-text-color-primary);
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
.batch-cell { display: flex; flex-direction: column; gap: 1px; min-width: 0; }
.batch-subline { display: block; overflow: hidden; color: var(--el-text-color-secondary); font-size: 11px; line-height: 15px; text-overflow: ellipsis; white-space: nowrap; font-variant-numeric: tabular-nums; }
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
.openai-status-retry {
  display: inline-flex;
  align-items: center;
  max-width: 100%;
  padding: 0;
  border: 0;
  background: transparent;
  color: var(--el-color-primary);
  font: inherit;
  gap: 4px;
  cursor: pointer;
}
.openai-status-retry:disabled { cursor: not-allowed; opacity: 0.7; }
.openai-status-retry:focus-visible { outline: 2px solid var(--el-color-primary-light-5); outline-offset: 2px; border-radius: 2px; }
.row-action-button { min-width: 30px; padding: 4px 8px; }
.danger-icon, .danger-label { color: var(--el-color-danger); }
</style>
