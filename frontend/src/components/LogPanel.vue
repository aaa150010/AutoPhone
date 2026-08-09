<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import type { ScrollbarInstance } from 'element-plus'
import { CircleCheckFilled } from '@element-plus/icons-vue'
import ContentEmptyState from './ContentEmptyState.vue'

const props = defineProps<{
  logs: readonly any[]
  autoScroll?: boolean
}>()

const scrollbar = ref<ScrollbarInstance>()
const sub2UploadSuccessPattern = /^T\d{3}-[0-9a-f]{6} 成功上传 SUB2: (?:<email>|[^\s@]+@[^\s@]+)$/i

const renderedLogs = computed(() => {
  const occurrences = new Map<string, number>()
  return (props.logs || []).map((log) => {
    const time = String(log?.time || '')
    const level = String(log?.type || log?.level || '')
    const message = String(log?.message || log?.text || log || '')
    const baseKey = `${time}\u0000${level}\u0000${message}`
    const occurrence = occurrences.get(baseKey) || 0
    occurrences.set(baseKey, occurrence + 1)
    return {
      key: `${baseKey}\u0000${occurrence}`,
      time,
      level,
      message,
      isSub2UploadSuccess: sub2UploadSuccessPattern.test(message),
    }
  })
})

const logTail = computed(() => {
  const logs = renderedLogs.value
  const last = logs[logs.length - 1]
  if (last && typeof last === 'object') {
    return `${logs.length}:${last.key}`
  }
  return `${logs.length}:${String(last || '')}`
})

async function scrollToBottom() {
  await nextTick()
  const instance = scrollbar.value
  const wrap = instance?.wrapRef
  if (!instance || !wrap) return
  instance.scrollTo({ top: wrap.scrollHeight, behavior: 'auto' })
}

watch(logTail, () => {
  if (props.autoScroll !== false) scrollToBottom()
}, { flush: 'post' })

watch(() => props.autoScroll, (enabled) => {
  if (enabled !== false) scrollToBottom()
}, { flush: 'post' })

onMounted(scrollToBottom)
</script>

<template>
  <div class="log-panel">
    <el-scrollbar
      ref="scrollbar"
      class="log-scroll"
      :class="{ 'is-empty': !renderedLogs.length }"
      tabindex="0"
    >
      <ContentEmptyState v-if="!renderedLogs.length" />
      <template v-else>
        <div
          v-for="log in renderedLogs"
          :key="log.key"
          v-memo="[log.key]"
          class="log-line"
          :class="{ 'is-sub2-upload-success': log.isSub2UploadSuccess }"
        >
          <span class="log-time">{{ log.time }}</span>
          <b
            class="log-message"
            :class="[log.level, { 'sub2-upload-success-message': log.isSub2UploadSuccess }]"
          >
            <el-icon v-if="log.isSub2UploadSuccess" class="sub2-success-icon" aria-hidden="true">
              <CircleCheckFilled />
            </el-icon>
            <span class="log-message-text">{{ log.message }}</span>
          </b>
        </div>
      </template>
    </el-scrollbar>
  </div>
</template>

<style scoped>
.log-panel { position: relative; display: flex; flex-direction: column; width: 100%; height: 100%; min-height: 0; }
.log-scroll { min-height: 0; flex: 1; }
.log-scroll :deep(.el-scrollbar__view) { min-height: 100%; }
.log-scroll.is-empty :deep(.el-scrollbar__view) { height: 100%; }
.log-line { display: flex; gap: 12px; padding: 7px 14px; border-bottom: 1px solid var(--el-border-color-lighter); font-size: 13px; line-height: 20px; }
.log-time { color: var(--el-text-color-secondary); white-space: nowrap; }
.log-message { min-width: 0; overflow-wrap: anywhere; font-weight: 600; }
.log-message-text { min-width: 0; }
.success { color: var(--el-color-success); }
.error { color: var(--el-color-danger); }
.warning,
.warn { color: var(--el-color-warning); }
.log-line.is-sub2-upload-success {
  background: #dcfce7;
  border-bottom-color: #86d3a3;
  box-shadow: inset 4px 0 0 #16a34a, inset 0 0 0 1px #86d3a3;
}
.log-line.is-sub2-upload-success .log-time { color: #166534; font-weight: 600; }
.log-line.is-sub2-upload-success b.log-message.sub2-upload-success-message {
  display: inline-flex;
  align-items: flex-start;
  gap: 7px;
  color: #05602a;
  font-size: 14px;
  font-weight: 800;
  letter-spacing: 0;
}
.sub2-success-icon {
  flex: 0 0 16px;
  width: 16px;
  height: 20px;
  color: #16a34a;
  font-size: 16px;
}
</style>
