<script setup lang="ts">
import RuntimeSettingsSection from './RuntimeSettingsSection.vue'
import SmsSettingsSection from './SmsSettingsSection.vue'
import IntegrationSettingsSection from './IntegrationSettingsSection.vue'
import type { SmsKeyStatus } from '../types/api'

defineProps<{ modelValue: any; smsKeyStatuses?: SmsKeyStatus[] }>()
const emit = defineEmits<{ 'update:modelValue': [any] }>()
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
  </el-form>
</template>

<style scoped>
.settings-form { max-width: 760px; }
.settings-form > :deep(.settings-section + .settings-section) { margin-top: 8px; }
</style>
