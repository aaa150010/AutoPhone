<script setup lang="ts">
import { computed } from 'vue'
import type { RuntimeState, SmsRuntimeAlert } from '../types/api'

const props = defineProps<{
  runtime: RuntimeState
  alerts?: readonly SmsRuntimeAlert[]
}>()

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
  <div class="service-health">
    <section class="key-section">
      <div class="section-heading">
        <span>SMS Key</span>
        <small>{{ smsKeys.length ? `${smsKeys.length} 个` : '未预检' }}</small>
      </div>
      <div class="key-list">
        <div v-if="!smsKeys.length" class="empty-line">暂无可展示的 Key 状态</div>
        <div v-for="key in smsKeys" :key="key.fingerprint" class="key-row">
          <i class="key-dot" :class="keyType(key.status)" />
          <div class="key-copy">
            <div><strong>Key {{ key.index }}</strong><span>{{ key.fingerprint }}</span></div>
            <small>{{ key.balance_usd == null ? '余额未知' : `$${Number(key.balance_usd).toFixed(2)}` }}</small>
          </div>
        </div>
      </div>
    </section>

    <section class="anomaly-section">
      <div class="section-heading"><span>异常提醒</span></div>
      <div class="anomaly-list">
        <div v-if="!anomalies.length" class="healthy-line"><el-icon><CircleCheck /></el-icon>未发现运行异常</div>
        <div v-for="item in anomalies" :key="item.id" class="anomaly-row" :class="item.level">
          <el-icon><Warning /></el-icon><span>{{ item.message }}</span>
        </div>
      </div>
    </section>
  </div>
</template>

<style scoped>
.service-health { display: grid; grid-template-rows: minmax(84px, 1fr) auto; width: 100%; height: 100%; min-height: 0; overflow: hidden; }
.key-section { display: flex; flex-direction: column; min-height: 0; padding: 8px 11px 6px; }
.section-heading { display: flex; align-items: baseline; gap: 7px; flex: 0 0 auto; min-height: 24px; color: #526074; font-size: 12px; line-height: 18px; font-weight: 650; }
.section-heading small { color: var(--el-text-color-secondary); font-size: 11px; font-weight: 400; }
.key-list { min-height: 0; overflow-x: hidden; overflow-y: auto; }
.key-row { display: flex; align-items: flex-start; gap: 7px; min-height: 42px; padding: 6px 1px; border-bottom: 1px solid var(--el-border-color-lighter); }
.key-dot { flex: 0 0 7px; width: 7px; height: 7px; margin-top: 5px; border-radius: 50%; background: var(--el-color-info); }
.key-dot.success { background: var(--el-color-success); }
.key-dot.warning { background: var(--el-color-warning); }
.key-dot.danger { background: var(--el-color-danger); }
.key-copy { min-width: 0; }
.key-copy > div { display: flex; align-items: baseline; gap: 6px; min-width: 0; }
.key-copy strong { flex: 0 0 auto; font-size: 12px; line-height: 16px; }
.key-copy span { overflow: hidden; color: var(--el-text-color-secondary); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 10px; line-height: 14px; text-overflow: ellipsis; white-space: nowrap; }
.key-copy > small { display: block; color: #526074; font-size: 11px; line-height: 15px; }
.anomaly-section { min-height: 70px; max-height: 112px; padding: 8px 11px; overflow: hidden; border-top: 1px solid var(--workspace-border); }
.anomaly-list { max-height: 72px; overflow-x: hidden; overflow-y: auto; }
.healthy-line,
.empty-line { display: flex; align-items: center; gap: 5px; min-height: 30px; color: var(--el-text-color-secondary); font-size: 12px; }
.healthy-line { color: var(--el-color-success); }
.anomaly-row { display: flex; align-items: flex-start; gap: 5px; padding: 3px 0; color: var(--el-color-warning); font-size: 11px; line-height: 15px; }
.anomaly-row.error { color: var(--el-color-danger); }
.anomaly-row .el-icon { flex: 0 0 auto; margin-top: 1px; }
</style>
