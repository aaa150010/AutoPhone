<script setup lang="ts">
import SecretInput from './SecretInput.vue'

const props = defineProps<{ modelValue: any }>()
const emit = defineEmits<{ 'update:modelValue': [any] }>()

function update(key: string, value: any) {
  emit('update:modelValue', { ...props.modelValue, [key]: value })
}

function updateNested(group: string, key: string, value: any) {
  emit('update:modelValue', {
    ...props.modelValue,
    [group]: {
      ...(props.modelValue[group] || {}),
      [key]: value,
    },
  })
}
</script>

<template>
  <div class="settings-section">
    <h2 class="section-title">平台集成</h2>
    <el-row :gutter="10">
      <el-col :span="12">
        <el-form-item label="SUB2 地址">
          <el-input
            :model-value="modelValue.sub2api?.url"
            @update:model-value="updateNested('sub2api', 'url', $event)"
          />
        </el-form-item>
      </el-col>
      <el-col :span="12">
        <el-form-item label="SUB2 账号">
          <el-input
            :model-value="modelValue.sub2api?.email"
            @update:model-value="updateNested('sub2api', 'email', $event)"
          />
        </el-form-item>
      </el-col>
    </el-row>

    <el-row :gutter="10">
      <el-col :span="12">
        <SecretInput
          :model-value="modelValue.sub2api?.password || ''"
          secret-id="sub2_password"
          label="管理密码"
          @update:model-value="updateNested('sub2api', 'password', $event)"
        />
      </el-col>
      <el-col :span="12">
        <el-form-item label="SUB2 分组">
          <el-input
            :model-value="modelValue.sub2api?.group"
            @update:model-value="updateNested('sub2api', 'group', $event)"
          />
        </el-form-item>
      </el-col>
    </el-row>

    <el-row :gutter="10">
      <el-col :span="12">
        <el-form-item label="注册成功后自动上传 Pixel">
          <el-switch
            :model-value="modelValue.pixel_upload_enabled !== false"
            inline-prompt
            active-text="开"
            inactive-text="关"
            @update:model-value="update('pixel_upload_enabled', $event)"
          />
        </el-form-item>
      </el-col>
      <el-col :span="12">
        <el-form-item label="Pixel 上传 worker 数">
          <el-input-number
            :model-value="Number(modelValue.pixel_upload_concurrency ?? 2)"
            :min="1"
            :max="3"
            controls-position="right"
            @update:model-value="update('pixel_upload_concurrency', Number($event ?? 2))"
          />
        </el-form-item>
      </el-col>
    </el-row>
  </div>
</template>

<style scoped>
.section-title { margin: 0 0 9px; font-size: 14px; line-height: 20px; font-weight: 680; letter-spacing: 0; }
.settings-section :deep(.el-input-number) { width: 100%; }
</style>
