<script setup lang="ts">
import SecretInput from './SecretInput.vue'

const props = defineProps<{ modelValue: any }>()
const emit = defineEmits<{ 'update:modelValue': [any] }>()

function update(key: string, value: any) {
  emit('update:modelValue', { ...props.modelValue, [key]: value })
}
</script>

<template>
  <div class="settings-section">
    <el-row :gutter="10">
      <el-col :span="12">
        <el-form-item label="SMS 最低价格">
          <el-input
            :model-value="modelValue.sms_min_price || '0.01'"
            @update:model-value="update('sms_min_price', $event)"
          />
        </el-form-item>
      </el-col>
      <el-col :span="12">
        <el-form-item label="SMS 最高价格">
          <el-input
            :model-value="modelValue.max_price || '0.1'"
            @update:model-value="update('max_price', $event)"
          />
        </el-form-item>
      </el-col>
    </el-row>

    <el-row :gutter="10">
      <el-col :span="12">
        <el-form-item label="SMS 超时（秒）">
          <el-input-number
            :model-value="Number(modelValue.sms_timeout || 30)"
            :min="1"
            :max="3600"
            controls-position="right"
            @update:model-value="update('sms_timeout', String($event ?? 30))"
          />
        </el-form-item>
      </el-col>
      <el-col :span="12">
        <el-form-item label="每号最大尝试（0=不限）">
          <el-input-number
            :model-value="Number(modelValue.phone_max_attempts ?? 0)"
            :min="0"
            :max="1000"
            controls-position="right"
            @update:model-value="update('phone_max_attempts', Number($event ?? 0))"
          />
        </el-form-item>
      </el-col>
    </el-row>

    <SecretInput
      :model-value="modelValue.sms_api_key || ''"
      secret-id="sms_api_key"
      label="SMS API Key"
      @update:model-value="update('sms_api_key', $event)"
    />
  </div>
</template>

<style scoped>
.settings-section :deep(.el-input-number) { width: 100%; }
</style>
