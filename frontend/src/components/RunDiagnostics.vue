<script setup lang="ts">
import { computed } from 'vue'
import { Cellphone, ChatDotRound, Clock, Connection, FirstAidKit, Message, UploadFilled } from '@element-plus/icons-vue'
import WorkspacePanel from './WorkspacePanel.vue'
import type { RuntimeState, SmsRuntimeAlert, TaskStageGroup } from '../types/api'

const props = defineProps<{
  runtime: RuntimeState
  alerts?: readonly SmsRuntimeAlert[]
}>()

const stages: Array<{ key: TaskStageGroup; label: string; icon: any }> = [
  { key: 'queue', label: '排队等待', icon: Clock },
  { key: 'oauth', label: 'OAuth 节点', icon: Connection },
  { key: 'email', label: '邮箱验证', icon: Message },
  { key: 'phone', label: '获取手机号', icon: Cellphone },
  { key: 'sms', label: '短信接码', icon: ChatDotRound },
  { key: 'finalizing', label: '收尾上传', icon: UploadFilled },
]

const concurrencyRows = computed(() => [
  { label: '任务', ...(props.runtime.concurrency?.task || {}) },
  { label: 'Node', ...(props.runtime.concurrency?.node || {}) },
  { label: '邮箱验证码', ...(props.runtime.concurrency?.email || {}) },
])

const smsKeys = computed(() => props.runtime.sms_key_statuses || [])
const anomalies = computed(() => {
  const rows: Array<{ id: string; level: string; message: string }> = []
  if (props.runtime.sms_safe_stop) {
    rows.push({ id: 'sms-safe-stop', level: 'error', message: 'SMS Key 已全部耗尽，运行已进入安全停止' })
  }
  for (const alert of props.alerts || props.runtime.sms_alerts || []) {
    if (alert.level === 'warning' || alert.level === 'error') {
      rows.push({ id: alert.id, level: alert.level, message: alert.message })
    }
  }
  if (props.runtime.notification?.status === 'failed') {
    rows.push({ id: 'notification-failed', level: 'warning', message: props.runtime.notification.error || '最近一次邮件通知发送失败' })
  }
  return rows.slice(0, 4)
})

function keyType(status?: string) {
  if (status === 'ready' || status === 'available' || status === 'healthy') return 'success'
  if (status === 'cooldown' || status === 'busy') return 'warning'
  if (status === 'disabled' || status === 'exhausted' || status === 'failed') return 'danger'
  return 'info'
}
</script>

<template>
  <div class="diagnostics-grid">
    <WorkspacePanel title="运行管线" :icon="Connection" fill body-padding="compact">
      <div class="pipeline">
        <div v-for="stage in stages" :key="stage.key" class="stage-row">
          <el-icon><component :is="stage.icon" /></el-icon>
          <span>{{ stage.label }}</span>
          <strong>{{ runtime.stage_counts?.[stage.key] || 0 }}</strong>
        </div>
      </div>
      <div class="concurrency-row">
        <div v-for="item in concurrencyRows" :key="item.label">
          <span>{{ item.label }}</span>
          <strong>{{ Number(item.active || 0) }}/{{ Number(item.limit || 0) }}</strong>
          <small v-if="Number(item.waiting || 0)">等待 {{ item.waiting }}</small>
        </div>
      </div>
    </WorkspacePanel>

    <WorkspacePanel title="服务健康" :icon="FirstAidKit" fill body-padding="compact">
      <div class="health-content">
        <div class="key-list">
          <div v-if="!smsKeys.length" class="empty-line">暂无 SMS Key 状态</div>
          <div v-for="key in smsKeys" :key="key.fingerprint" class="key-row">
            <el-tag size="small" effect="light" :type="keyType(key.status)">Key {{ key.index }}</el-tag>
            <span>{{ key.fingerprint }}</span>
            <strong>{{ key.balance_usd == null ? '余额未知' : `$${Number(key.balance_usd).toFixed(2)}` }}</strong>
          </div>
        </div>
        <div class="anomaly-list">
          <div v-if="!anomalies.length" class="healthy-line"><el-icon><CircleCheck /></el-icon>未发现运行异常</div>
          <div v-for="item in anomalies" :key="item.id" class="anomaly-row" :class="item.level">
            <el-icon><Warning /></el-icon><span>{{ item.message }}</span>
          </div>
        </div>
      </div>
    </WorkspacePanel>
  </div>
</template>

<style scoped>
.diagnostics-grid { display: grid; grid-template-columns: minmax(0, 3fr) minmax(360px, 2fr); gap: 8px; min-width: 0; min-height: 0; }
.pipeline { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 4px; }
.stage-row { display: grid; grid-template-columns: 17px minmax(0, 1fr) auto; align-items: center; gap: 3px; min-width: 0; min-height: 42px; padding: 0 4px; border: 1px solid var(--workspace-border); border-radius: 5px; background: #f8fafc; }
.stage-row .el-icon { color: var(--el-color-primary); font-size: 14px; }
.stage-row span { overflow: hidden; color: var(--el-text-color-regular); font-size: 10px; white-space: nowrap; }
.stage-row strong { font-size: 16px; font-variant-numeric: tabular-nums; }
.concurrency-row { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 18px; margin-top: 9px; padding: 0 3px; }
.concurrency-row > div { display: flex; align-items: baseline; gap: 6px; min-width: 0; }
.concurrency-row span { color: var(--el-text-color-secondary); font-size: 11px; }
.concurrency-row strong { font-size: 13px; font-variant-numeric: tabular-nums; }
.concurrency-row small { color: var(--el-color-warning); font-size: 10px; }
.health-content { display: grid; grid-template-columns: minmax(190px, 1fr) minmax(190px, 1fr); gap: 8px; height: 100%; min-height: 0; }
.key-list,
.anomaly-list { min-height: 0; overflow: auto; }
.key-row { display: grid; grid-template-columns: auto minmax(0, 1fr) auto; align-items: center; gap: 6px; min-height: 29px; border-bottom: 1px solid var(--el-border-color-lighter); }
.key-row span { overflow: hidden; color: var(--el-text-color-secondary); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 10px; text-overflow: ellipsis; white-space: nowrap; }
.key-row strong { font-size: 11px; font-weight: 600; }
.healthy-line,
.empty-line { display: flex; align-items: center; gap: 5px; min-height: 29px; color: var(--el-text-color-secondary); font-size: 11px; }
.healthy-line { color: var(--el-color-success); }
.anomaly-row { display: flex; align-items: flex-start; gap: 5px; padding: 5px 0; border-bottom: 1px solid var(--el-border-color-lighter); color: var(--el-color-warning); font-size: 11px; line-height: 16px; }
.anomaly-row.error { color: var(--el-color-danger); }
.anomaly-row .el-icon { flex: 0 0 auto; margin-top: 1px; }
</style>
