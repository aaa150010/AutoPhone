<script setup lang="ts">
import { computed, ref } from 'vue'
import { Document, View } from '@element-plus/icons-vue'
import ContentEmptyState from './ContentEmptyState.vue'
import TaskDetailsDrawer from './TaskDetailsDrawer.vue'
import TaskProgressCell from './TaskProgressCell.vue'
import TaskVerificationInput from './TaskVerificationInput.vue'
import { useTaskProgressClock } from '../composables/useTaskProgressClock'
import type { RuntimeTask } from '../types/api'

const props = withDefaults(defineProps<{
  tasks: RuntimeTask[]
  openingMailboxUrls?: readonly string[]
}>(), {
  openingMailboxUrls: () => [],
})
const emit = defineEmits<{
  copyAccount: [RuntimeTask]
  mailboxUrl: [RuntimeTask]
}>()

const nowSeconds = useTaskProgressClock(
  () => props.tasks,
  () => props.tasks.some(task => Boolean(task.manual_verification?.can_submit)),
)
const detailsOpen = ref(false)
const selectedTaskKey = ref('')

function taskTooltip(row: RuntimeTask) {
  const details = []
  if (row.batch_id) details.push(`运行批次 ${row.batch_id}`)
  if (Number(row.ordinal) > 0) details.push(`批内序号 ${Math.floor(Number(row.ordinal))}`)
  return details.join(' · ') || `任务 ${row.task_id}`
}

function taskRowKey(row: RuntimeTask) {
  return `${String(row.batch_id || 'legacy')}::${row.task_id}`
}

const selectedTask = computed(() => {
  if (!selectedTaskKey.value) return null
  return props.tasks.find(row => taskRowKey(row) === selectedTaskKey.value) || null
})

function statusLabel(status?: string) {
  const value = String(status || '').toLowerCase()
  if (value === 'success') return '成功'
  if (value === 'failed') return '失败'
  if (value === 'retryable_infra') return '基础设施可重试'
  if (value === 'retryable_email') return '邮箱可重试'
  if (value === 'repair_pending') return '待修复'
  if (value === 'email_damaged') return '邮箱不可用'
  if (value === 'account_banned') return '封禁'
  if (value === 'stopped' || value === 'stopped_before_start') return '停止'
  return value ? '运行中' : '-'
}

function statusType(status?: string) {
  const value = String(status || '').toLowerCase()
  if (value === 'success') return 'success'
  if (value === 'failed' || value === 'email_damaged' || value === 'account_banned') return 'danger'
  if (value === 'stopped' || value === 'stopped_before_start') return 'info'
  return 'warning'
}

function failureCause(row: RuntimeTask) {
  const failure = row.failure
  if (!failure) {
    const value = String(row.error || row.reason || '').trim()
    return value.toLowerCase() === 'sub2_uploaded' ? '-' : value || '-'
  }
  const message = String(failure.public_message || '').trim()
  const prefix = `${failure.node_label}失败：`
  return message.startsWith(prefix) ? message.slice(prefix.length) : message || '-'
}

function failureTooltip(row: RuntimeTask) {
  const failure = row.failure
  if (!failure) return ''
  const codes = [failure.node_code, failure.error_code, failure.provider_code].filter(Boolean).join(' / ')
  const technical = String(failure.technical_summary || '').trim()
  return technical ? `${codes} · ${technical}` : codes
}

function costLabel(row: RuntimeTask) {
  const value = row.result?.sms_cost_cny
  return value == null ? '暂无' : `¥${Number(value).toFixed(2)}`
}

function costTooltip(row: RuntimeTask) {
  const result = row.result
  if (!result || result.sms_cost_cny == null) return ''
  const usd = result.sms_cost_usd == null ? '暂无' : `$${Number(result.sms_cost_usd).toFixed(4)}`
  const rate = result.sms_exchange_rate == null ? '暂无' : Number(result.sms_exchange_rate).toFixed(4)
  return `美元报价 ${usd} · USD/CNY ${rate} · ${result.sms_exchange_date || '未知日期'}`
}

function openDetails(row: RuntimeTask) {
  selectedTaskKey.value = taskRowKey(row)
  detailsOpen.value = true
}
</script>

<template>
  <el-table class="task-table" :data="tasks" :row-key="taskRowKey" stripe height="100%">
    <el-table-column label="账号" min-width="215">
      <template #default="{ row }">
        <el-tooltip v-if="row.account || row.email" content="点击复制账号或邮箱" placement="top">
          <button type="button" class="copyable-account" aria-label="复制账号或邮箱" @click="emit('copyAccount', row)">
            {{ row.account || row.email }}
          </button>
        </el-tooltip>
        <span v-else>-</span>
        <small class="task-id" :title="taskTooltip(row)">{{ row.task_id }}</small>
      </template>
    </el-table-column>
    <el-table-column label="链路进度" min-width="250">
      <template #default="{ row }">
        <TaskProgressCell :progress="row.progress" :timing="row.timing" :now-seconds="nowSeconds" :status="row.status" />
      </template>
    </el-table-column>
    <el-table-column label="结果" width="132" align="center">
      <template #default="{ row }"><el-tag :type="statusType(row.status)">{{ statusLabel(row.status) }}</el-tag></template>
    </el-table-column>
    <el-table-column label="验证 / 操作" width="280" align="center">
      <template #default="{ row }">
        <div class="task-actions">
          <TaskVerificationInput
            v-if="row.manual_verification"
            :task-id="row.task_id"
            :request="row.manual_verification"
            :now-seconds="nowSeconds"
          />
          <el-tooltip v-if="row.has_mailbox_url" content="打开取件网页" placement="top">
            <el-button link :icon="View" :loading="openingMailboxUrls.includes(row.task_id)" :disabled="openingMailboxUrls.includes(row.task_id)" aria-label="打开取件网页" @click="emit('mailboxUrl', row)" />
          </el-tooltip>
          <el-tooltip content="查看任务链路详情" placement="top">
            <el-button link :icon="Document" aria-label="查看任务链路详情" @click="openDetails(row)" />
          </el-tooltip>
        </div>
      </template>
    </el-table-column>
    <el-table-column label="接码成本" width="110" align="right">
      <template #default="{ row }">
        <el-tooltip v-if="row.result?.sms_cost_cny != null" :content="costTooltip(row)" placement="top">
          <span class="sms-cost">{{ costLabel(row) }}</span>
        </el-tooltip>
        <span v-else class="muted">暂无</span>
      </template>
    </el-table-column>
    <el-table-column label="说明" min-width="280" show-overflow-tooltip>
      <template #default="{ row }">
        <el-tooltip v-if="row.failure" :content="failureTooltip(row)" placement="top">
          <span class="failure-detail"><span class="failure-node">{{ row.failure.node_label }}</span><span>{{ failureCause(row) }}</span></span>
        </el-tooltip>
        <span v-else>{{ failureCause(row) }}</span>
      </template>
    </el-table-column>
    <template #empty><ContentEmptyState /></template>
  </el-table>

  <TaskDetailsDrawer v-model="detailsOpen" :task="selectedTask" :now-seconds="nowSeconds" />
</template>

<style scoped>
.task-table { width: 100%; height: 100%; min-height: 0; }
.task-id { display: block; overflow: hidden; color: var(--el-text-color-secondary); font-size: 10px; line-height: 14px; text-overflow: ellipsis; white-space: nowrap; }
.copyable-account { display: block; max-width: 100%; overflow: hidden; padding: 0; border: 0; background: transparent; color: var(--el-color-primary); font: inherit; text-align: left; text-overflow: ellipsis; white-space: nowrap; cursor: copy; }
.copyable-account:focus-visible { outline: 2px solid var(--el-color-primary-light-5); outline-offset: 2px; border-radius: 2px; }
.task-actions { display: inline-flex; align-items: center; justify-content: center; gap: 6px; min-width: 0; }
.failure-detail { display: inline-flex; max-width: 100%; align-items: center; gap: 6px; }
.failure-node { flex: none; color: var(--el-color-danger); font-weight: 600; }
.failure-detail > span:last-child { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.sms-cost { color: var(--el-color-success); font-variant-numeric: tabular-nums; cursor: help; }
.muted { color: var(--el-text-color-secondary); }
</style>
