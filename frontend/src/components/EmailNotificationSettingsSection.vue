<script setup lang="ts">
import SecretInput from './SecretInput.vue'
import type { NotificationRuntimeStatus } from '../types/api'

const props = defineProps<{
  modelValue: any
  testing?: boolean
  status?: NotificationRuntimeStatus
}>()
const emit = defineEmits<{
  'update:modelValue': [any]
  test: []
}>()

function current() {
  return props.modelValue.email_notification || {}
}

function updateEmail(values: Record<string, any>) {
  emit('update:modelValue', {
    ...props.modelValue,
    email_notification: { ...current(), ...values },
  })
}

function updateEvent(key: string, value: any) {
  updateEmail({ events: { ...(current().events || {}), [key]: Boolean(value) } })
}

function statusText() {
  if (!props.status?.status) return ''
  const labels = { queued: '等待发送', sent: '最近发送成功', failed: '最近发送失败' }
  const time = props.status.timestamp
    ? new Date(props.status.timestamp * 1000).toLocaleString('zh-CN', { hour12: false })
    : ''
  return `${labels[props.status.status]}${time ? ` · ${time}` : ''}`
}
</script>

<template>
  <section class="settings-section notification-section">
    <div class="section-heading">
      <div>
        <h2>QQ 邮箱通知</h2>
        <span v-if="statusText()" :class="status?.status">{{ statusText() }}</span>
      </div>
      <el-switch
        :model-value="Boolean(current().enabled)"
        active-text="启用"
        inactive-text="关闭"
        @update:model-value="updateEmail({ enabled: $event })"
      />
    </div>

    <el-row :gutter="10">
      <el-col :span="12">
        <el-form-item label="发件账号">
          <el-input
            :model-value="current().username"
            placeholder="name@qq.com"
            @update:model-value="updateEmail({ username: $event })"
          />
        </el-form-item>
      </el-col>
      <el-col :span="12">
        <SecretInput
          :model-value="current().password || ''"
          secret-id="notification_email_password"
          label="SMTP 授权码"
          @update:model-value="updateEmail({ password: $event })"
        />
      </el-col>
    </el-row>

    <el-row :gutter="10">
      <el-col :span="12">
        <el-form-item label="发件人地址">
          <el-input
            :model-value="current().sender"
            placeholder="默认使用发件账号"
            @update:model-value="updateEmail({ sender: $event })"
          />
        </el-form-item>
      </el-col>
      <el-col :span="12">
        <el-form-item label="停滞阈值（分钟）">
          <el-input-number
            :model-value="Number(current().stalled_minutes || 10)"
            :min="5"
            :max="120"
            controls-position="right"
            @update:model-value="updateEmail({ stalled_minutes: Number($event || 10) })"
          />
        </el-form-item>
      </el-col>
    </el-row>

    <el-form-item label="收件邮箱">
      <el-select
        :model-value="current().recipients || []"
        multiple
        filterable
        allow-create
        default-first-option
        :reserve-keyword="false"
        placeholder="输入邮箱后回车，可添加多个"
        @update:model-value="updateEmail({ recipients: $event })"
      />
    </el-form-item>

    <el-form-item label="通知事件">
      <div class="event-grid">
        <el-checkbox :model-value="current().events?.batch_completed !== false" @update:model-value="updateEvent('batch_completed', $event)">批次完成</el-checkbox>
        <el-checkbox :model-value="current().events?.unexpected_stop !== false" @update:model-value="updateEvent('unexpected_stop', $event)">异常结束</el-checkbox>
        <el-checkbox :model-value="current().events?.stalled !== false" @update:model-value="updateEvent('stalled', $event)">运行停滞</el-checkbox>
        <el-checkbox :model-value="current().events?.sms_exhausted !== false" @update:model-value="updateEvent('sms_exhausted', $event)">SMS Key 耗尽</el-checkbox>
        <el-checkbox :model-value="current().events?.sms_balance_low !== false" @update:model-value="updateEvent('sms_balance_low', $event)">SMS Key 余额低于 $1</el-checkbox>
        <el-checkbox :model-value="Boolean(current().events?.manual_stop)" @update:model-value="updateEvent('manual_stop', $event)">手动停止</el-checkbox>
      </div>
    </el-form-item>

    <div class="notification-actions">
      <el-button :loading="testing" @click="emit('test')">
        <el-icon><Promotion /></el-icon>发送测试通知
      </el-button>
      <el-text v-if="status?.error" type="danger" truncated>{{ status.error }}</el-text>
    </div>
  </section>
</template>

<style scoped>
.section-heading { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 10px; padding-top: 3px; }
.section-heading h2 { margin: 0; font-size: 14px; line-height: 20px; font-weight: 680; letter-spacing: 0; }
.section-heading span { display: block; margin-top: 3px; color: var(--el-text-color-secondary); font-size: 12px; line-height: 18px; }
.section-heading span.sent { color: var(--el-color-success); }
.section-heading span.failed { color: var(--el-color-danger); }
.notification-section :deep(.el-input-number),
.notification-section :deep(.el-select) { width: 100%; }
.event-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); width: 100%; }
.event-grid :deep(.el-checkbox) { margin-right: 0; }
.notification-actions { display: flex; align-items: center; gap: 10px; min-height: 32px; }
.notification-actions .el-text { min-width: 0; flex: 1; }
</style>
