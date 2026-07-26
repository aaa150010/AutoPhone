<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import { Bottom, VideoPause } from '@element-plus/icons-vue'
import type { ScrollbarInstance } from 'element-plus'

const props = defineProps<{ logs: any[] }>()

const scrollbar = ref<ScrollbarInstance>()
const autoScroll = ref(true)
const programmaticScroll = ref(false)
const bottomTolerance = 24

const logTail = computed(() => {
  const logs = props.logs || []
  const last = logs[logs.length - 1]
  if (last && typeof last === 'object') {
    return `${logs.length}:${last.time || ''}:${last.message || last.text || ''}`
  }
  return `${logs.length}:${String(last || '')}`
})

async function scrollToBottom() {
  await nextTick()
  const instance = scrollbar.value
  const wrap = instance?.wrapRef
  if (!instance || !wrap) return

  programmaticScroll.value = true
  instance.setScrollTop(wrap.scrollHeight)
  window.requestAnimationFrame(() => {
    programmaticScroll.value = false
  })
}

function handleScroll({ scrollTop }: { scrollTop: number; scrollLeft: number }) {
  if (!autoScroll.value || programmaticScroll.value) return
  const wrap = scrollbar.value?.wrapRef
  if (!wrap) return

  const distanceToBottom = wrap.scrollHeight - wrap.clientHeight - scrollTop
  if (distanceToBottom > bottomTolerance) autoScroll.value = false
}

function toggleAutoScroll() {
  autoScroll.value = !autoScroll.value
  if (autoScroll.value) scrollToBottom()
}

watch(logTail, () => {
  if (autoScroll.value) scrollToBottom()
}, { flush: 'post' })

onMounted(scrollToBottom)
</script>

<template>
  <div class="log-panel">
    <div class="log-toolbar">
      <el-button size="small" plain @click="toggleAutoScroll">
        <el-icon><VideoPause v-if="autoScroll" /><Bottom v-else /></el-icon>
        {{ autoScroll ? '暂停滚动' : '继续滚动' }}
      </el-button>
    </div>
    <el-scrollbar ref="scrollbar" class="log-scroll" tabindex="0" @scroll="handleScroll">
      <div v-for="(log, index) in logs" :key="index" class="log-line">
        <span>{{ log.time || '' }}</span>
        <b :class="log.type || log.level">{{ log.message || log.text || log }}</b>
      </div>
    </el-scrollbar>
  </div>
</template>

<style scoped>
.log-panel { position: relative; display: flex; flex-direction: column; width: 100%; height: 100%; min-height: 0; }
.log-toolbar { flex: 0 0 auto; display: flex; justify-content: flex-end; margin-bottom: 4px; }
.log-toolbar :deep(.el-button) { padding: 4px 7px; }
.log-scroll { min-height: 0; flex: 1; }
.log-line { display: flex; gap: 12px; padding: 6px 2px; border-bottom: 1px solid var(--el-border-color-lighter); font-size: 12px; }
.log-line span { color: var(--el-text-color-secondary); white-space: nowrap; }
.log-line b { min-width: 0; overflow-wrap: anywhere; font-weight: 600; }
.success { color: var(--el-color-success); }
.error { color: var(--el-color-danger); }
.warning,
.warn { color: var(--el-color-warning); }
</style>
