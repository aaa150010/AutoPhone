<script setup lang="ts">
import RuntimeSettingsSection from './RuntimeSettingsSection.vue'
import SmsSettingsSection from './SmsSettingsSection.vue'
import IntegrationSettingsSection from './IntegrationSettingsSection.vue'
import EmailNotificationSettingsSection from './EmailNotificationSettingsSection.vue'
import type { SmsKeyStatus } from '../types/api'
import type { NotificationRuntimeStatus } from '../types/api'

defineProps<{
  modelValue: any
  smsKeyStatuses?: SmsKeyStatus[]
  testingNotification?: boolean
  notificationStatus?: NotificationRuntimeStatus
}>()
const emit = defineEmits<{ 'update:modelValue': [any]; testNotification: [] }>()
</script>

<template>
  <el-form label-position="top" size="small" class="settings-form">
    <RuntimeSettingsSection
      :model-value="modelValue"
      @update:model-value="emit('update:modelValue', $event)"
    />
    <SmsSettingsSection
      :model-value="modelValue"
      :statuses="smsKeyStatuses"
      @update:model-value="emit('update:modelValue', $event)"
    />

    <IntegrationSettingsSection
      :model-value="modelValue"
      @update:model-value="emit('update:modelValue', $event)"
    />
    <el-divider />
    <EmailNotificationSettingsSection
      :model-value="modelValue"
      :testing="testingNotification"
      :status="notificationStatus"
      @update:model-value="emit('update:modelValue', $event)"
      @test="emit('testNotification')"
    />
  </el-form>
</template>

<style scoped>
.settings-form { box-sizing: border-box; width: 100%; padding-inline: 5px; }
.settings-form > :deep(.settings-section + .settings-section) { margin-top: 12px; }
.settings-form > :deep(.el-divider) { margin: 16px 0 12px; }
</style>
