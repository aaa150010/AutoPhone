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

    <div class="integration-block" data-settings-anchor="free">
      <el-row :gutter="10">
      <el-col :span="12">
        <el-form-item label="Free 本次注册数量（0=自动）">
          <el-input-number
            :model-value="Number(modelValue.free_target_count ?? 0)"
            :min="0"
            :max="10000"
            controls-position="right"
            @update:model-value="update('free_target_count', Number($event ?? 0))"
          />
        </el-form-item>
      </el-col>
      <el-col :span="12">
        <el-form-item label="Free 注册并发数">
          <el-input-number
            :model-value="Number(modelValue.free_concurrency ?? 5)"
            :min="1"
            :max="32"
            controls-position="right"
            @update:model-value="update('free_concurrency', Number($event ?? 5))"
          />
        </el-form-item>
      </el-col>
      </el-row>

      <el-row :gutter="10">
      <el-col :span="12">
        <SecretInput
          :model-value="modelValue.free_register_password || ''"
          secret-id="free_register_password"
          label="Free 注册密码（固定）"
          disabled
          @update:model-value="update('free_register_password', $event)"
        />
      </el-col>
      </el-row>

      <el-form-item label="Free 代理出口探测地址">
      <el-input
        :model-value="modelValue.free_proxy_probe_url"
        placeholder="https://api.ipify.org"
        @update:model-value="update('free_proxy_probe_url', $event)"
      />
      </el-form-item>

      <el-form-item label="Free 代理池">
      <el-input
        :model-value="modelValue.free_proxy_pool_content"
        type="textarea"
        :rows="6"
        placeholder="每行一个代理 URL 或 主机:端口:用户名:密码"
        autocomplete="off"
        @update:model-value="update('free_proxy_pool_content', $event)"
      />
      </el-form-item>
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
