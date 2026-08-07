<script setup lang="ts">
import { useRunUploadSelection } from '../composables/useRunUploadSelection'

const props = defineProps<{
  nvConfigured: boolean
  loading?: boolean
}>()
const emit = defineEmits<{
  confirm: [{ pixel: boolean; nv: boolean }]
}>()

const { visible, pixel, nv, nvDisabled, open, targets } = useRunUploadSelection(
  () => props.nvConfigured,
)

function confirm() {
  if (props.loading) return
  visible.value = false
  emit('confirm', targets())
}

defineExpose({ open })
</script>

<template>
  <el-dialog
    v-model="visible"
    title="开始运行"
    width="420px"
    :close-on-click-modal="false"
    :close-on-press-escape="!loading"
    :show-close="!loading"
  >
    <div class="upload-targets">
      <el-checkbox v-model="pixel" border>上传到 Pixel</el-checkbox>
      <el-tooltip
        :disabled="!nvDisabled"
        content="NV 地址或 API Key 未配置"
        placement="top"
      >
        <span>
          <el-checkbox v-model="nv" border :disabled="nvDisabled">上传到 NV</el-checkbox>
        </span>
      </el-tooltip>
    </div>
    <template #footer>
      <el-button :disabled="loading" @click="visible = false">取消</el-button>
      <el-button type="primary" :loading="loading" @click="confirm">确认运行</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.upload-targets { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; padding: 4px 0; }
.upload-targets :deep(.el-checkbox) { width: 100%; height: 42px; margin-right: 0; }
.upload-targets > span { display: block; min-width: 0; }
</style>
