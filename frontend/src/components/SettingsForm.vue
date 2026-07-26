<script setup lang="ts">
import RuntimeSettingsSection from './RuntimeSettingsSection.vue'
import SmsSettingsSection from './SmsSettingsSection.vue'
import IntegrationSettingsSection from './IntegrationSettingsSection.vue'

defineProps<{ modelValue: any }>()
const emit = defineEmits<{ 'update:modelValue': [any] }>()
</script>

<template>
  <el-form label-position="top" size="small" class="settings-form">
    <el-divider content-position="center">基础设置</el-divider>
    <RuntimeSettingsSection
      :model-value="modelValue"
      @update:model-value="emit('update:modelValue', $event)"
    />
    <SmsSettingsSection
      :model-value="modelValue"
      @update:model-value="emit('update:modelValue', $event)"
    />

    <el-divider content-position="center">SUB2 与 nvtoken</el-divider>
    <IntegrationSettingsSection
      :model-value="modelValue"
      @update:model-value="emit('update:modelValue', $event)"
    />
  </el-form>
</template>

<style scoped>
.settings-form { max-width: 760px; }
</style>
