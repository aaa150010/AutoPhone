<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import type { ScrollbarInstance } from 'element-plus'
import { CircleCheckFilled } from '@element-plus/icons-vue'
import ContentEmptyState from './ContentEmptyState.vue'

/** A run-log row as delivered by the runtime state API. */
type RunLogEntry = string | { time?: string; level?: string; type?: string; message?: string; text?: string }

const props = defineProps<{
  logs: readonly RunLogEntry[]
  autoScroll?: boolean
}>()

const scrollbar = ref<ScrollbarInstance>()
const sub2UploadSuccessPattern = /^T\d{3}-[0-9a-f]{6} 成功上传 SUB2: (?:<email>|[^\s@]+@[^\s@]+)$/i
const LEVEL_CLASSES: Record<string, string> = {
  error: 'log-error',
  danger: 'log-error',
  success: 'log-success',
  warning: 'log-warn',
  warn: 'log-warn',
  debug: 'log-debug',
}

const renderedLogs = computed(() => {
  const occurrences = new Map<string, number>()
  return (props.logs || []).map((log) => {
    const entry = typeof log === 'string' ? { message: log } : log
    const time = String(entry?.time || '')
    const level = String(entry?.type || entry?.level || '').toLowerCase()
    const message = String(entry?.message || entry?.text || entry || '')
    const baseKey = `${time}\u0000${level}\u0000${message}`
    const occurrence = occurrences.get(baseKey) || 0
    occurrences.set(baseKey, occurrence + 1)
    return {
      key: `${baseKey}\u0000${occurrence}`,
      time,
      level,
      levelClass: LEVEL_CLASSES[level] || '',
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
          :class="[log.levelClass, { 'is-sub2-upload-success': log.isSub2UploadSuccess }]"
        >
          <span class="log-time">{{ log.time }}</span>
          <span class="log-message">
            <el-icon v-if="log.isSub2UploadSuccess" class="sub2-success-icon" aria-hidden="true">
              <CircleCheckFilled />
            </el-icon>
            <span class="log-message-text">{{ log.message }}</span>
          </span>
        </div>
      </template>
    </el-scrollbar>
  </div>
</template>

<style scoped>
/* Matches the FreeTaskLogDialog terminal styling so both log surfaces read
   as the same diagnostic surface. */
.log-panel { position: relative; display: flex; flex-direction: column; width: 100%; height: 100%; min-height: 0; background: #101923; color: #dbe7f2; font: 12px/18px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; scrollbar-color: #577b9d #101923; }
.log-scroll { min-height: 0; flex: 1; }
.log-scroll :deep(.el-scrollbar__view) { min-height: 100%; }
.log-scroll.is-empty :deep(.el-scrollbar__view) { height: 100%; }
.log-line { display: flex; gap: 10px; padding: 3px 12px; white-space: pre-wrap; word-break: break-word; }
.log-time { flex: 0 0 auto; padding-top: 1px; color: #8ca0b5; white-space: nowrap; }
.log-message { display: inline-flex; align-items: flex-start; gap: 6px; min-width: 0; }
.log-message-text { min-width: 0; }
.log-error { color: #ff8791; }
.log-warn { color: #f5bc72; }
.log-success { color: #71dbb1; }
.log-debug { color: #9ba9b7; }
.log-line.is-sub2-upload-success { background: rgb(47 158 109 / 0.16); box-shadow: inset 3px 0 0 var(--el-color-success); }
.log-line.is-sub2-upload-success .log-time { color: #71dbb1; font-weight: 600; }
.log-line.is-sub2-upload-success .log-message { color: #71dbb1; font-weight: 700; }
.sub2-success-icon { flex: 0 0 14px; width: 14px; height: 17px; color: #71dbb1; font-size: 14px; }
.log-panel :deep(.content-empty) { background: transparent; }
.log-panel :deep(.content-empty .el-empty__description p) { color: #91a8bd; }
</style>
