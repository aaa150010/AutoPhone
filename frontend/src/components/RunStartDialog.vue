<script setup lang="ts">
import { ref } from 'vue'

const props = withDefaults(defineProps<{ loading?: boolean }>(), { loading: false })
const emit = defineEmits<{ confirm: [{ runMode: 'register' | 'free_register' }] }>()
const visible = ref(false)
const runMode = ref<'register' | 'free_register'>('register')

function open() {
  runMode.value = 'register'
  visible.value = true
}

function confirm() {
  if (props.loading) return
  visible.value = false
  emit('confirm', { runMode: runMode.value })
}

defineExpose({ open })
</script>

<template>
  <el-dialog
    v-model="visible"
    title="选择运行模式"
    width="460px"
    :close-on-click-modal="false"
    :close-on-press-escape="!loading"
    :show-close="!loading"
  >
    <el-radio-group v-model="runMode" class="mode-options">
      <el-radio value="register" border>批量接码/OAuth</el-radio>
      <el-radio value="free_register" border>批量注册 Free</el-radio>
    </el-radio-group>
    <template #footer>
      <el-button :disabled="loading" @click="visible = false">取消</el-button>
      <el-button type="primary" :loading="loading" @click="confirm">确认运行</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.mode-options { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; width: 100%; }
.mode-options :deep(.el-radio) { display: flex; align-items: center; width: 100%; height: 48px; margin: 0; }
</style>
