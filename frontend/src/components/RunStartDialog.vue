<script setup lang="ts">
import { ref } from 'vue'

const props = withDefaults(defineProps<{ loading?: boolean }>(), { loading: false })
const emit = defineEmits<{ confirm: [{ runMode: 'register' }] }>()
const visible = ref(false)

function open() {
  visible.value = true
}

function confirm() {
  if (props.loading) return
  visible.value = false
  emit('confirm', { runMode: 'register' })
}

defineExpose({ open })
</script>

<template>
  <el-dialog
    v-model="visible"
    title="启动接码 / OAuth"
    width="460px"
    :close-on-click-modal="false"
    :close-on-press-escape="!loading"
    :show-close="!loading"
  >
    <p class="dialog-copy">Free 注册请进入“运行配置 &gt; Free 注册运行”选择全协议或 RoxyBrowser 链路。</p>
    <template #footer>
      <el-button :disabled="loading" @click="visible = false">取消</el-button>
      <el-button type="primary" :loading="loading" @click="confirm">确认运行</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.dialog-copy { margin: 0; color: var(--el-text-color-secondary); font-size: 13px; line-height: 20px; }
</style>
