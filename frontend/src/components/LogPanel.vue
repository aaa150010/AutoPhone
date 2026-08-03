<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import type { ScrollbarInstance } from 'element-plus'
import ContentEmptyState from './ContentEmptyState.vue'

const props = defineProps<{
  logs: any[]
  autoScroll?: boolean
}>()

const scrollbar = ref<ScrollbarInstance>()

const renderedLogs = computed(() => {
  const occurrences = new Map<string, number>()
  return (props.logs || []).map((log) => {
    const time = String(log?.time || '')
    const level = String(log?.type || log?.level || '')
    const message = String(log?.message || log?.text || log || '')
    const baseKey = `${time}\u0000${level}\u0000${message}`
    const occurrence = occurrences.get(baseKey) || 0
    occurrences.set(baseKey, occurrence + 1)
    return { key: `${baseKey}\u0000${occurrence}`, time, level, message }
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
        <div v-for="log in renderedLogs" :key="log.key" v-memo="[log.key]" class="log-line">
          <span>{{ log.time }}</span>
          <b :class="log.level">{{ log.message }}</b>
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
.log-line span { color: var(--el-text-color-secondary); white-space: nowrap; }
.log-line b { min-width: 0; overflow-wrap: anywhere; font-weight: 600; }
.success { color: var(--el-color-success); }
.error { color: var(--el-color-danger); }
.warning,
.warn { color: var(--el-color-warning); }
</style>
