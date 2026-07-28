<script setup lang="ts">
import SmsApiKeyEditor from './SmsApiKeyEditor.vue'
import type { SmsKeyStatus } from '../types/api'

const props = defineProps<{ modelValue: any; statuses?: SmsKeyStatus[] }>()
const emit = defineEmits<{ 'update:modelValue': [any] }>()

function update(key: string, value: any) {
  emit('update:modelValue', { ...props.modelValue, [key]: value })
}
</script>

<template>
  <div class="settings-section">
    <h2 class="section-title">SMS 接码</h2>
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
        <el-form-item label="每号最大尝试">
          <el-input-number
            :model-value="Number(modelValue.phone_max_attempts ?? 10)"
            :min="1"
            :max="10"
            controls-position="right"
            @update:model-value="update('phone_max_attempts', Number($event ?? 10))"
          />
        </el-form-item>
      </el-col>
    </el-row>

    <el-form-item label="手机阶段超时（秒）">
      <el-input-number
        :model-value="Number(modelValue.phone_session_cycle_seconds ?? 480)"
        :min="30"
        :max="480"
        controls-position="right"
        @update:model-value="update('phone_session_cycle_seconds', Number($event ?? 480))"
      />
    </el-form-item>

    <SmsApiKeyEditor
      :model-value="Array.isArray(modelValue.sms_api_keys) ? modelValue.sms_api_keys : [modelValue.sms_api_key || '']"
      :statuses="statuses"
      @update:model-value="update('sms_api_keys', $event)"
    />
  </div>
</template>

<style scoped>
.section-title { margin: 0 0 9px; font-size: 14px; line-height: 20px; font-weight: 680; letter-spacing: 0; }
.settings-section :deep(.el-input-number) { width: 100%; }
</style>
