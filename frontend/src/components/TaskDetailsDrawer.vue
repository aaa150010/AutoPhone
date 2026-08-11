<script setup lang="ts">
import { computed } from 'vue'
import type { RuntimeTask, TaskStageGroup, TaskStageTiming } from '../types/api'

const props = defineProps<{
  modelValue: boolean
  task: RuntimeTask | null
  nowSeconds: number
}>()

const emit = defineEmits<{ 'update:modelValue': [boolean] }>()

const standardNodes: Array<{ code: string; label: string; group: TaskStageGroup }> = [
  { code: 'queue_waiting', label: '排队等待', group: 'queue' },
  { code: 'queue_reserved', label: '邮箱已预留', group: 'queue' },
  { code: 'oauth_create_node', label: 'OAuth 创建节点', group: 'oauth' },
  { code: 'oauth_session', label: '建立 OAuth 会话', group: 'oauth' },
  { code: 'oauth_authorize_node', label: 'OAuth 授权节点', group: 'oauth' },
  { code: 'email_slot_waiting', label: '等待邮箱验证槽', group: 'email' },
  { code: 'email_login', label: '邮箱登录', group: 'email' },
  { code: 'email_password', label: '验证邮箱密码', group: 'email' },
  { code: 'email_code_waiting', label: '等待邮箱验证码', group: 'email' },
  { code: 'email_code_verifying', label: '验证邮箱验证码', group: 'email' },
  { code: 'mfa_otp_verifying', label: '验证 2FA 动态码', group: 'email' },
  { code: 'phone_acquiring', label: '正在获取手机号', group: 'phone' },
  { code: 'phone_submitting', label: '正在提交手机号', group: 'phone' },
  { code: 'sms_waiting', label: '等待短信验证码', group: 'sms' },
  { code: 'sms_verifying', label: '验证短信验证码', group: 'sms' },
  { code: 'finalizing_profile', label: '完善账号资料', group: 'finalizing' },
  { code: 'finalizing_callback', label: '获取 OAuth 回调', group: 'finalizing' },
  { code: 'finalizing_token', label: '交换 OAuth Token', group: 'finalizing' },
  { code: 'finalizing_upload', label: '上传账号凭据', group: 'finalizing' },
  { code: 'finalizing_save', label: '保存任务结果', group: 'finalizing' },
]

const terminalStatuses = new Set([
  'success', 'failed', 'stopped', 'stopped_before_start', 'retryable_infra',
  'retryable_email', 'repair_pending', 'email_damaged', 'account_banned',
])
const failureStatuses = new Set([
  'failed', 'retryable_infra', 'retryable_email', 'repair_pending',
  'email_damaged', 'account_banned',
])

const open = computed({
  get: () => props.modelValue,
  set: value => emit('update:modelValue', value),
})
const timing = computed(() => props.task?.progress?.timing || props.task?.timing || props.task?.result?.timing || null)
const stageByCode = computed(() => new Map(
  (timing.value?.stages || []).map(stage => [stage.code, stage]),
))
const normalizedStatus = computed(() => String(props.task?.status || '').trim().toLowerCase())
const isTerminal = computed(() => terminalStatuses.has(normalizedStatus.value))
const currentCode = computed(() => String(props.task?.progress?.code || ''))
const failureCode = computed(() => String(props.task?.failure?.node_code || ''))

function formatSeconds(value: unknown) {
  const seconds = Math.max(0, Number(value || 0))
  if (!Number.isFinite(seconds)) return '0 秒'
  if (seconds > 0 && seconds < 10 && !Number.isInteger(seconds)) {
    return `${seconds.toFixed(2).replace(/0+$/, '').replace(/\.$/, '')} 秒`
  }
  return `${Math.floor(seconds)} 秒`
}

function liveStageElapsed(stage: TaskStageTiming | undefined, code: string) {
  let elapsed = Number(stage?.elapsed_seconds || 0)
  const progress = props.task?.progress
  if (progress?.code === code && progress.finished_at == null && progress.entered_at) {
    elapsed += Math.max(0, props.nowSeconds - Number(progress.entered_at))
  }
  return formatSeconds(elapsed)
}

function nodeState(code: string) {
  const visited = stageByCode.value.has(code)
  const current = currentCode.value === code
  const failed = failureCode.value === code
    || (current && failureStatuses.has(normalizedStatus.value))
  if (failed) return { label: '失败', type: 'danger' as const, className: 'is-failed' }
  if (current && !isTerminal.value) return { label: '当前', type: 'warning' as const, className: 'is-current' }
  if (visited || (current && normalizedStatus.value === 'success')) {
    return { label: '完成', type: 'success' as const, className: 'is-completed' }
  }
  return { label: '未到达', type: 'info' as const, className: 'is-pending' }
}

function checkpointLabel() {
  const labels = {
    saved: '已保存',
    restored: '已恢复',
    available: '可恢复',
    claimed: '已认领',
    disabled: '未启用',
    expired: '已过期',
    invalid: '已失效',
  }
  return props.task?.checkpoint ? labels[props.task.checkpoint.state] : ''
}

function checkpointType() {
  const state = props.task?.checkpoint?.state
  if (state === 'saved' || state === 'available') return 'success'
  if (state === 'restored' || state === 'claimed') return 'primary'
  if (state === 'expired' || state === 'invalid') return 'danger'
  return 'info'
}
</script>

<template>
  <el-drawer
    v-model="open"
    class="task-details-drawer"
    title="任务链路详情"
    size="720px"
    append-to-body
    destroy-on-close
  >
    <template v-if="task">
      <el-descriptions :column="2" border size="small" class="summary-grid">
        <el-descriptions-item label="账号">{{ task.account || task.email || '-' }}</el-descriptions-item>
        <el-descriptions-item label="任务状态">{{ task.status || '-' }}</el-descriptions-item>
        <el-descriptions-item label="运行批次">{{ task.batch_id || '-' }}</el-descriptions-item>
        <el-descriptions-item label="批内序号">{{ task.ordinal || '-' }}</el-descriptions-item>
        <el-descriptions-item label="排队耗时">{{ formatSeconds(timing?.queue_elapsed_seconds) }}</el-descriptions-item>
        <el-descriptions-item label="执行耗时">{{ formatSeconds(timing?.execution_elapsed_seconds) }}</el-descriptions-item>
      </el-descriptions>

      <section v-if="task.checkpoint" class="detail-section checkpoint-section">
        <h3>检查点恢复</h3>
        <div class="checkpoint-row">
          <el-tag :type="checkpointType()">{{ checkpointLabel() }}</el-tag>
          <span>恢复节点：{{ task.checkpoint.resume_stage || '-' }}</span>
          <span>已保存：{{ formatSeconds(task.checkpoint.age_seconds ?? task.checkpoint.age) }}</span>
          <span v-if="task.checkpoint.reason">{{ task.checkpoint.reason }}</span>
        </div>
      </section>

      <section class="detail-section">
        <h3>完整链路</h3>
        <div class="chain-list">
          <div
            v-for="(node, index) in standardNodes"
            :key="node.code"
            class="chain-row"
            :class="nodeState(node.code).className"
          >
            <span class="chain-index">{{ index + 1 }}</span>
            <div class="chain-copy">
              <strong>{{ node.label }}</strong>
              <code>{{ node.code }}</code>
            </div>
            <span class="chain-visits">{{ stageByCode.get(node.code)?.visits || 0 }} 次</span>
            <span class="chain-elapsed">{{ liveStageElapsed(stageByCode.get(node.code), node.code) }}</span>
            <el-tag :type="nodeState(node.code).type" size="small">{{ nodeState(node.code).label }}</el-tag>
          </div>
        </div>
      </section>

      <section v-if="timing?.segments?.length" class="detail-section">
        <h3>细分耗时</h3>
        <el-table :data="timing.segments" size="small" stripe>
          <el-table-column prop="label" label="细分阶段" min-width="210" />
          <el-table-column prop="code" label="代码" min-width="190" />
          <el-table-column label="访问" width="70" align="right">
            <template #default="{ row }">{{ row.visits }} 次</template>
          </el-table-column>
          <el-table-column label="耗时" width="90" align="right">
            <template #default="{ row }">{{ formatSeconds(row.elapsed_seconds) }}</template>
          </el-table-column>
        </el-table>
      </section>

      <section v-if="task.failure" class="detail-section failure-section">
        <h3>失败诊断</h3>
        <el-descriptions :column="2" border size="small">
          <el-descriptions-item label="失败节点">{{ task.failure.node_label }} / {{ task.failure.node_code }}</el-descriptions-item>
          <el-descriptions-item label="可重试">{{ task.failure.retryable ? '是' : '否' }}</el-descriptions-item>
          <el-descriptions-item label="错误代码">{{ task.failure.error_code || '-' }}</el-descriptions-item>
          <el-descriptions-item label="Provider Code">{{ task.failure.provider_code || '-' }}</el-descriptions-item>
          <el-descriptions-item label="HTTP 状态">{{ task.failure.http_status ?? '-' }}</el-descriptions-item>
          <el-descriptions-item label="公开原因">{{ task.failure.public_message || '-' }}</el-descriptions-item>
          <el-descriptions-item v-if="task.failure.technical_summary" label="技术摘要" :span="2">
            {{ task.failure.technical_summary }}
          </el-descriptions-item>
          <el-descriptions-item v-if="task.failure.action_hint" label="处理建议" :span="2">
            {{ task.failure.action_hint }}
          </el-descriptions-item>
        </el-descriptions>
      </section>
    </template>
  </el-drawer>
</template>

<style scoped>
.summary-grid { margin-bottom: 16px; }
.detail-section { margin-top: 18px; }
.detail-section h3 { margin: 0 0 8px; color: var(--el-text-color-primary); font-size: 14px; line-height: 20px; font-weight: 680; letter-spacing: 0; }
.checkpoint-row { display: flex; align-items: center; gap: 12px; min-height: 32px; color: var(--el-text-color-regular); font-size: 12px; }
.chain-list { border-block: 1px solid var(--el-border-color-lighter); }
.chain-row { display: grid; grid-template-columns: 28px minmax(220px, 1fr) 56px 78px 68px; align-items: center; min-height: 42px; border-bottom: 1px solid var(--el-border-color-lighter); font-size: 12px; }
.chain-row:last-child { border-bottom: 0; }
.chain-index { color: var(--el-text-color-secondary); font-variant-numeric: tabular-nums; text-align: center; }
.chain-copy { display: flex; align-items: baseline; gap: 8px; min-width: 0; }
.chain-copy strong { overflow: hidden; color: var(--el-text-color-primary); font-size: 13px; text-overflow: ellipsis; white-space: nowrap; }
.chain-copy code { overflow: hidden; color: var(--el-text-color-secondary); font-size: 10px; text-overflow: ellipsis; white-space: nowrap; }
.chain-visits,
.chain-elapsed { color: var(--el-text-color-secondary); font-variant-numeric: tabular-nums; text-align: right; }
.chain-row > .el-tag { justify-self: end; }
.chain-row.is-current { background: var(--el-color-warning-light-9); }
.chain-row.is-failed { background: var(--el-color-danger-light-9); }
.chain-row.is-completed .chain-index { color: var(--el-color-success); }
.chain-row.is-pending { opacity: .72; }
.failure-section { padding-bottom: 12px; }
</style>
