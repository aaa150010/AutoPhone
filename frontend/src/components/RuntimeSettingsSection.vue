<script setup lang="ts">
const props = defineProps<{ modelValue: any }>()
const emit = defineEmits<{ 'update:modelValue': [any] }>()

function update(key: string, value: any) {
  emit('update:modelValue', { ...props.modelValue, [key]: value })
}

function updateProxyScope(key: string, value: boolean | string | number) {
  emit('update:modelValue', {
    ...props.modelValue,
    proxy_scope: {
      ...(props.modelValue.proxy_scope || {}),
      [key]: Boolean(value),
    },
  })
}
</script>

<template>
  <div class="settings-section">
    <el-form-item label="代理地址">
      <el-input
        :model-value="modelValue.proxy"
        placeholder="http://127.0.0.1:7897"
        @update:model-value="update('proxy', $event)"
      />
    </el-form-item>

    <div class="proxy-scope">
      <el-checkbox
        :model-value="Boolean(modelValue.proxy_scope?.sms)"
        @update:model-value="updateProxyScope('sms', $event)"
      >SMS 走代理</el-checkbox>
      <el-checkbox
        :model-value="Boolean(modelValue.proxy_scope?.email)"
        @update:model-value="updateProxyScope('email', $event)"
      >邮箱取码走代理</el-checkbox>
      <el-checkbox
        :model-value="Boolean(modelValue.proxy_scope?.upload)"
        @update:model-value="updateProxyScope('upload', $event)"
      >SUB2 走代理</el-checkbox>
    </div>

    <el-row :gutter="10">
      <el-col :span="12">
        <el-form-item label="目标数量">
          <el-input-number
            :model-value="Number(modelValue.target_count || 1)"
            :min="1"
            :max="10000"
            controls-position="right"
            @update:model-value="update('target_count', String($event ?? 1))"
          />
        </el-form-item>
      </el-col>
      <el-col :span="12">
        <el-form-item label="并发数">
          <el-input-number
            :model-value="Number(modelValue.concurrency || 5)"
            :min="1"
            :max="100"
            controls-position="right"
            @update:model-value="update('concurrency', String($event ?? 5))"
          />
        </el-form-item>
      </el-col>
    </el-row>

    <el-row :gutter="10">
      <el-col :span="12">
        <el-form-item label="Node 并发数">
          <el-input-number
            :model-value="Number(modelValue.node_concurrency || 5)"
            :min="1"
            :max="100"
            controls-position="right"
            @update:model-value="update('node_concurrency', String($event ?? 5))"
          />
        </el-form-item>
      </el-col>
      <el-col :span="12">
        <el-form-item label="Node 超时（秒）">
          <el-input-number
            :model-value="Number(modelValue.node_timeout ?? 45)"
            :min="1"
            :max="3600"
            controls-position="right"
            @update:model-value="update('node_timeout', Number($event ?? 45))"
          />
        </el-form-item>
      </el-col>
    </el-row>

    <el-row :gutter="10">
      <el-col :span="12">
        <el-form-item label="鉴权额外重试次数">
          <el-input-number
            :model-value="Number(modelValue.auth_session_retries ?? 1)"
            :min="0"
            :max="10"
            controls-position="right"
            @update:model-value="update('auth_session_retries', Number($event ?? 1))"
          />
        </el-form-item>
      </el-col>
    </el-row>

  </div>
</template>

<style scoped>
.settings-section :deep(.el-input-number) { width: 100%; }
.proxy-scope {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 16px;
  margin: -2px 0 10px;
}
.proxy-scope :deep(.el-checkbox) { margin-right: 0; }
</style>
