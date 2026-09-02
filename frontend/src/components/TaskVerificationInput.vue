<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import { Check } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { ApiError, submitManualVerification } from '../api/client'
import type { ManualVerificationRequest } from '../types/api'
import { manualVerificationRequestKey } from '../utils/manualVerification'

const props = defineProps<{
  taskId: string
  request: ManualVerificationRequest
  nowSeconds: number
}>()

const emit = defineEmits<{ accepted: [] }>()
const code = ref('')
const submitting = ref(false)
const acceptedRequestKey = ref('')
const inputRef = ref<any>()

const requestKey = computed(() => manualVerificationRequestKey(props.taskId, props.request))

const kindLabel = computed(() => ({
  email_otp: '邮箱码',
  sms_otp: '短信码',
  totp: '2FA 码',
}[props.request.input_kind]))

const remainingSeconds = computed(() => Math.max(
  0,
  Math.floor(Number(props.request.deadline_at || 0) - props.nowSeconds),
))

const canSubmit = computed(() => (
  props.request.can_submit
  && props.request.capabilities?.includes('submit')
  && remainingSeconds.value > 0
  && acceptedRequestKey.value !== requestKey.value
))

watch(
  requestKey,
  () => {
    code.value = ''
    acceptedRequestKey.value = ''
    void focusInput()
  },
)

async function focusInput() {
  await nextTick()
  if (canSubmit.value) inputRef.value?.focus?.()
}

onMounted(() => {
  void focusInput()
})

async function submit() {
  const submittedCode = code.value.trim()
  if (!submittedCode || !canSubmit.value || submitting.value) return
  const submittedKind = props.request.input_kind
  const submittedGeneration = props.request.generation
  const submittedLabel = kindLabel.value
  const submittedRequestKey = requestKey.value
  code.value = ''
  submitting.value = true
  try {
    await submitManualVerification({
      task_id: props.taskId,
      input_kind: submittedKind,
      generation: submittedGeneration,
      code: submittedCode,
    })
    acceptedRequestKey.value = submittedRequestKey
    ElMessage.success(`${submittedLabel}已提交`)
    emit('accepted')
  } catch (error) {
    const message = error instanceof ApiError
      ? String(error.payload?.error || error.message)
      : '验证码提交失败'
    ElMessage.error(message || '验证码提交失败')
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <div class="verification-input">
    <el-input
      ref="inputRef"
      v-model="code"
      :placeholder="kindLabel"
      :maxlength="12"
      :disabled="!canSubmit || submitting"
      autocomplete="one-time-code"
      inputmode="numeric"
      :aria-label="`输入${kindLabel}`"
      @keyup.enter="submit"
    >
      <template #suffix><span class="countdown">{{ remainingSeconds }}s</span></template>
    </el-input>
    <el-tooltip :content="`提交${kindLabel}`" placement="top">
      <el-button
        type="primary"
        :icon="Check"
        :loading="submitting"
        :disabled="!canSubmit || !code.trim()"
        :aria-label="`提交${kindLabel}`"
        @click="submit"
      />
    </el-tooltip>
  </div>
</template>

<style scoped>
.verification-input { display: flex; align-items: center; gap: 5px; width: 100%; max-width: 176px; min-width: 0; }
.verification-input :deep(.el-input) { min-width: 0; }
.verification-input :deep(.el-input__wrapper) { padding-inline: 7px; }
.verification-input :deep(.el-input__inner) { min-width: 0; font-variant-numeric: tabular-nums; }
.verification-input :deep(.el-button) { flex: 0 0 28px; width: 28px; padding: 0; }
.countdown { color: var(--el-text-color-secondary); font-size: 10px; font-variant-numeric: tabular-nums; }
</style>
