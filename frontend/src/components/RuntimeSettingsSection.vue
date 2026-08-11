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
    <h2 class="section-title">运行参数</h2>
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
      >SUB2 / NV 走代理</el-checkbox>
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
            :max="8"
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
        <el-form-item label="邮箱登录并发数">
          <el-input-number
            :model-value="Number(modelValue.auto_email_login_concurrency ?? 5)"
            :min="1"
            :max="Math.max(1, Number(modelValue.concurrency || 5))"
            controls-position="right"
            @update:model-value="update('auto_email_login_concurrency', Number($event ?? 5))"
          />
        </el-form-item>
      </el-col>
      <el-col :span="12">
        <el-form-item label="鉴权额外重试次数">
          <el-input-number
            :model-value="Number(modelValue.auth_session_retries ?? 1)"
            :min="0"
            :max="4"
            controls-position="right"
            @update:model-value="update('auth_session_retries', Number($event ?? 1))"
          />
        </el-form-item>
      </el-col>
    </el-row>

    <el-row :gutter="10">
      <el-col :span="12">
        <el-form-item label="手机提交并发数">
          <el-input-number
            :model-value="Number(modelValue.phone_submission_concurrency ?? 2)"
            :min="1"
            :max="5"
            controls-position="right"
            @update:model-value="update('phone_submission_concurrency', Number($event ?? 2))"
          />
        </el-form-item>
      </el-col>
      <el-col :span="12">
        <el-form-item label="邮箱验证码等待超时（秒）">
          <el-input-number
            :model-value="Number(modelValue.email_code_timeout ?? 60)"
            :min="30"
            :max="600"
            controls-position="right"
            @update:model-value="update('email_code_timeout', Number($event ?? 60))"
          />
        </el-form-item>
      </el-col>
    </el-row>

    <el-row :gutter="10">
      <el-col :span="12">
        <el-form-item label="OpenAI 链路保护">
          <el-switch
            :model-value="modelValue.openai_connectivity_guard !== false"
            @update:model-value="update('openai_connectivity_guard', Boolean($event))"
          />
        </el-form-item>
      </el-col>
      <el-col :span="12">
        <el-form-item label="协议健康并发上限">
          <el-input-number
            :model-value="Number(modelValue.protocol_concurrency_ceiling ?? 12)"
            :min="8"
            :max="15"
            controls-position="right"
            @update:model-value="update('protocol_concurrency_ceiling', Number($event ?? 12))"
          />
        </el-form-item>
      </el-col>
    </el-row>

    <el-form-item label="保守自适应任务并发">
      <el-switch
        :model-value="modelValue.adaptive_task_concurrency !== false"
        @update:model-value="update('adaptive_task_concurrency', Boolean($event))"
      />
    </el-form-item>

    <el-row :gutter="10">
      <el-col :span="12">
        <el-form-item label="20 条在途任务优化">
          <el-switch
            :model-value="modelValue.task_inflight_optimization !== false"
            @update:model-value="update('task_inflight_optimization', Boolean($event))"
          />
        </el-form-item>
      </el-col>
      <el-col :span="12">
        <el-form-item label="在途任务上限">
          <el-input-number
            :model-value="Number(modelValue.task_inflight_limit ?? 20)"
            :min="1"
            :max="20"
            controls-position="right"
            :disabled="modelValue.task_inflight_optimization === false"
            @update:model-value="update('task_inflight_limit', Number($event ?? 20))"
          />
        </el-form-item>
      </el-col>
    </el-row>

    <el-form-item label="手机号绑定兼容">
      <el-switch
        :model-value="modelValue.phone_binding_compatibility !== false"
        @update:model-value="update('phone_binding_compatibility', Boolean($event))"
      />
    </el-form-item>

  </div>
</template>

<style scoped>
.section-title { margin: 0 0 9px; font-size: 14px; line-height: 20px; font-weight: 680; letter-spacing: 0; }
.settings-section :deep(.el-input-number) { width: 100%; }
.proxy-scope {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 16px;
  margin: -2px 0 10px;
}
.proxy-scope :deep(.el-checkbox) { margin-right: 0; }
</style>
