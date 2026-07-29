<script setup lang="ts">
import { ref } from 'vue'
import SecretInput from './SecretInput.vue'

const props = defineProps<{ modelValue: any }>()
const emit = defineEmits<{ 'update:modelValue': [any] }>()
const expandedSections = ref<string[]>([])

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

    <el-collapse v-model="expandedSections" class="nvtoken-collapse">
      <el-collapse-item name="nvtoken">
        <template #title>
          <el-checkbox
            :model-value="modelValue.nvtoken_upload !== false"
            @click.stop
            @keydown.stop
            @update:model-value="update('nvtoken_upload', $event)"
          >上传 nvtoken 卡片</el-checkbox>
        </template>

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
      </el-collapse-item>
    </el-collapse>
  </div>
</template>

<style scoped>
.section-title { margin: 0 0 9px; font-size: 14px; line-height: 20px; font-weight: 680; letter-spacing: 0; }
.nvtoken-collapse {
  --el-collapse-header-height: 40px;
  border-top: 0;
  border-bottom: 0;
}
.nvtoken-collapse :deep(.el-collapse-item__header) {
  border-bottom-color: var(--el-border-color-lighter);
  font-size: 13px;
}
.nvtoken-collapse :deep(.el-collapse-item__wrap) { border-bottom: 0; }
.nvtoken-collapse :deep(.el-collapse-item__content) { padding: 10px 0 0; }
.nvtoken-collapse :deep(.el-checkbox) { margin-right: 0; }
</style>
