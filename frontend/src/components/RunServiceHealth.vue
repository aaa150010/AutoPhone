<script setup lang="ts">
import { computed } from 'vue'
import { CircleCheckFilled, Clock, WarningFilled } from '@element-plus/icons-vue'
import type { RuntimeState, SmsRuntimeAlert } from '../types/api'

const props = defineProps<{
  runtime: RuntimeState
  alerts?: readonly SmsRuntimeAlert[]
}>()

const smsKeys = computed(() => props.runtime.sms_key_statuses || [])
const anomalies = computed(() => {
  const rows: Array<{ id: string; level: string; message: string }> = []
  if (props.runtime.sms_safe_stop) {
    rows.push({ id: 'sms-safe-stop', level: 'error', message: '所有 SMS 平台均不可用，运行已进入安全停止' })
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
  if (['usable', 'ready', 'available', 'healthy'].includes(String(status || ''))) return 'success'
  if (['cooldown', 'busy', 'rate_limited', 'network_error'].includes(String(status || ''))) return 'warning'
  if (['disabled', 'exhausted', 'failed', 'invalid', 'insufficient_balance', 'error'].includes(String(status || ''))) return 'danger'
  return 'info'
}

function keyStatusLabel(status?: string) {
  const labels: Record<string, string> = {
    usable: '可用',
    ready: '正常',
    available: '正常',
    healthy: '正常',
    cooldown: '冷却中',
    busy: '使用中',
    rate_limited: '请求限流',
    network_error: '网络异常',
    disabled: '已停用',
    exhausted: '已耗尽',
    failed: '不可用',
    invalid: 'Key 无效',
    insufficient_balance: '余额不足',
    error: '检查失败',
    unchecked: '未预检',
  }
  return labels[String(status || '')] || '状态未知'
}

function providerLabel(provider?: string) {
  const labels: Record<string, string> = {
    smsbower: 'SMSBower',
    herosms: 'HeroSMS',
    '5sim': '5SIM',
  }
  const value = String(provider || 'smsbower').toLowerCase()
  return labels[value] || value
}

const onlineKeyCount = computed(() => smsKeys.value.filter(key => keyType(key.status) === 'success').length)
const hasDanger = computed(() => (
  props.runtime.sms_safe_stop
  || anomalies.value.some(item => item.level === 'error')
  || smsKeys.value.some(key => keyType(key.status) === 'danger')
))
const hasWarning = computed(() => (
  anomalies.value.length > 0
  || smsKeys.value.some(key => keyType(key.status) === 'warning')
))
const healthTone = computed(() => {
  if (hasDanger.value) return 'danger'
  if (hasWarning.value) return 'warning'
  if (!smsKeys.value.length || onlineKeyCount.value < smsKeys.value.length) return 'info'
  return 'success'
})
const healthLabel = computed(() => {
  if (healthTone.value === 'danger') return '运行异常'
  if (healthTone.value === 'warning') return '需要关注'
  if (healthTone.value === 'info') return '等待预检'
  return '全部正常'
})
const healthDetail = computed(() => (
  smsKeys.value.length
    ? `${onlineKeyCount.value} / ${smsKeys.value.length} 个 SMS Key 可用`
    : 'SMS Key 尚未预检'
))
const summaryIcon = computed(() => healthTone.value === 'success' ? CircleCheckFilled : healthTone.value === 'info' ? Clock : WarningFilled)
</script>

<template>
  <div class="service-health">
    <div class="health-summary" :class="healthTone">
      <span class="summary-icon"><el-icon><component :is="summaryIcon" /></el-icon></span>
      <div>
        <strong>{{ healthLabel }}</strong>
        <small>{{ healthDetail }}</small>
      </div>
    </div>

    <div class="health-list">
      <div v-if="!smsKeys.length" class="empty-line">
        <el-icon><Clock /></el-icon><span>暂无 Key 状态</span>
      </div>
      <div v-for="key in smsKeys" :key="`${key.provider || key.platform}-${key.fingerprint}`" class="key-row" :title="key.message || keyStatusLabel(key.status)">
        <i class="key-dot" :class="keyType(key.status)" />
        <div class="key-copy">
          <strong>{{ providerLabel(key.provider || key.platform) }} #{{ key.index }}</strong>
          <span>{{ key.fingerprint }}</span>
        </div>
        <div class="key-value">
          <strong>{{ key.balance_usd == null ? '-' : `$${Number(key.balance_usd).toFixed(2)}` }}</strong>
          <small>{{ keyStatusLabel(key.status) }}<template v-if="Number(key.in_flight || 0)"> · {{ key.in_flight }} 使用中</template></small>
        </div>
      </div>
      <div v-for="item in anomalies" :key="item.id" class="anomaly-row" :class="item.level">
        <el-icon><WarningFilled /></el-icon><span>{{ item.message }}</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.service-health {
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
  width: 100%;
  height: 100%;
  min-height: 0;
  padding: 9px;
  overflow: hidden;
}
.health-summary { display: flex; align-items: center; gap: 9px; min-height: 58px; padding: 8px 9px; border-radius: 5px; }
.summary-icon { display: grid; place-items: center; flex: 0 0 30px; width: 30px; height: 30px; border-radius: 5px; }
.summary-icon .el-icon { font-size: 17px; }
.health-summary > div { min-width: 0; }
.health-summary strong,
.health-summary small { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.health-summary strong { font-size: 12px; line-height: 17px; font-weight: 650; }
.health-summary small { margin-top: 1px; font-size: 10px; line-height: 14px; }
.health-summary.success { background: #eaf8f0; color: #286c49; }
.health-summary.success .summary-icon { background: #d7f2e2; color: #277c50; }
.health-summary.warning { background: #fff5e8; color: #a65f00; }
.health-summary.warning .summary-icon { background: #ffe8c2; color: #cf7a00; }
.health-summary.danger { background: #fff0f0; color: #aa3838; }
.health-summary.danger .summary-icon { background: #ffdede; color: #d94a4a; }
.health-summary.info { background: #eff6ff; color: #426889; }
.health-summary.info .summary-icon { background: #dcecff; color: #287fd8; }
.health-list { min-height: 0; margin-top: 5px; overflow-x: hidden; overflow-y: auto; }
.key-row { display: flex; align-items: center; gap: 7px; min-height: 35px; padding: 5px 1px; border-bottom: 1px solid #e7ecf2; }
.key-dot { flex: 0 0 7px; width: 7px; height: 7px; border-radius: 50%; background: var(--el-color-info); }
.key-dot.success { background: var(--el-color-success); }
.key-dot.warning { background: var(--el-color-warning); }
.key-dot.danger { background: var(--el-color-danger); }
.key-copy { display: flex; align-items: baseline; gap: 5px; min-width: 0; }
.key-copy strong { flex: 0 0 auto; font-size: 11px; line-height: 15px; }
.key-copy span { overflow: hidden; color: #7d899a; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 9px; line-height: 13px; text-overflow: ellipsis; white-space: nowrap; }
.key-value { min-width: 70px; margin-left: auto; text-align: right; }
.key-value strong,
.key-value small { display: block; white-space: nowrap; }
.key-value strong { color: #344055; font-size: 10px; line-height: 14px; font-weight: 650; }
.key-value small { color: #7d899a; font-size: 9px; line-height: 12px; }
.empty-line { display: flex; align-items: center; gap: 5px; min-height: 34px; color: #7d899a; font-size: 11px; }
.anomaly-row { display: flex; align-items: flex-start; gap: 5px; padding: 5px 1px; border-bottom: 1px solid #f3e6d1; color: #b66b00; font-size: 10px; line-height: 14px; }
.anomaly-row.error { color: var(--el-color-danger); }
.anomaly-row .el-icon { flex: 0 0 auto; margin-top: 1px; }
.anomaly-row span { min-width: 0; overflow-wrap: anywhere; }
</style>
