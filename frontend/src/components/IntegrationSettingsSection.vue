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

    <SecretInput
      :model-value="modelValue.sub2api?.password || ''"
      secret-id="sub2_password"
      label="管理密码"
      @update:model-value="updateNested('sub2api', 'password', $event)"
    />

    <el-form-item label="SUB2 分组">
      <el-input
        :model-value="modelValue.sub2api?.group"
        @update:model-value="updateNested('sub2api', 'group', $event)"
      />
    </el-form-item>

    <el-form-item class="nvtoken-toggle">
      <el-checkbox
        :model-value="modelValue.nvtoken_upload !== false"
        @update:model-value="update('nvtoken_upload', $event)"
      >上传 nvtoken 卡片</el-checkbox>
    </el-form-item>

    <el-form-item label="nvtoken 导入地址">
      <el-input
        :model-value="modelValue.nvtoken?.url"
        :disabled="modelValue.nvtoken_upload === false"
        @update:model-value="updateNested('nvtoken', 'url', $event)"
      />
    </el-form-item>

    <SecretInput
      :model-value="modelValue.nvtoken?.api_key || ''"
      secret-id="nvtoken_api_key"
      label="nvtoken API Key"
      :disabled="modelValue.nvtoken_upload === false"
      @update:model-value="updateNested('nvtoken', 'api_key', $event)"
    />
  </div>
</template>

<style scoped>
.nvtoken-toggle { margin-top: 2px; }
</style>
