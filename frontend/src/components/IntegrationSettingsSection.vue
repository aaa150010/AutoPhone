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
    <div class="integration-block" data-settings-anchor="sub2">
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
    </div>

    <div class="integration-block" data-settings-anchor="online-mailbox">
      <el-row :gutter="10">
      <el-col :span="12">
        <el-form-item label="网站邮箱地址">
          <el-input
            :model-value="modelValue.online_mailbox?.base_url"
            placeholder="https://lynote.xyz/token-tool"
            @update:model-value="updateNested('online_mailbox', 'base_url', $event)"
          />
        </el-form-item>
      </el-col>
      <el-col :span="12">
        <SecretInput
          :model-value="modelValue.online_mailbox?.api_token || ''"
          secret-id="online_mailbox_api_token"
          label="网站邮箱 API 密钥"
          @update:model-value="updateNested('online_mailbox', 'api_token', $event)"
        />
      </el-col>
      </el-row>
    </div>
  </div>
</template>

<style scoped>
.section-title { margin: 0 0 9px; font-size: 14px; line-height: 20px; font-weight: 680; letter-spacing: 0; }
.settings-section :deep(.el-input-number) { width: 100%; }
.integration-block + .integration-block { margin-top: 16px; padding-top: 16px; border-top: 1px solid var(--el-border-color-lighter); }
</style>
