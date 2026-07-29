<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { Bottom, VideoPause } from '@element-plus/icons-vue'
import type { ScrollbarInstance } from 'element-plus'
import ContentEmptyState from './ContentEmptyState.vue'

const props = defineProps<{ logs: any[] }>()

const scrollbar = ref<ScrollbarInstance>()
const autoScroll = ref(true)
const programmaticScroll = ref(false)
const bottomTolerance = 24
let scrollToken = 0

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

function finishProgrammaticScroll(token: number, startedAt: number) {
  window.requestAnimationFrame(() => {
    if (token !== scrollToken) return
    const wrap = scrollbar.value?.wrapRef
    if (!wrap) {
      programmaticScroll.value = false
      return
    }
    const distance = wrap.scrollHeight - wrap.clientHeight - wrap.scrollTop
    if (distance <= 1 || Date.now() - startedAt > 500) {
      programmaticScroll.value = false
      return
    }
    finishProgrammaticScroll(token, startedAt)
  })
}

async function scrollToBottom(smooth = true) {
  await nextTick()
  const instance = scrollbar.value
  const wrap = instance?.wrapRef
  if (!instance || !wrap) return

  const target = wrap.scrollHeight - wrap.clientHeight
  const distance = target - wrap.scrollTop
  if (distance <= 1) return

  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches
  const shouldSmooth = smooth && !reducedMotion && distance <= Math.max(600, wrap.clientHeight * 2)
  const token = ++scrollToken
  programmaticScroll.value = true
  instance.scrollTo({ top: target, behavior: shouldSmooth ? 'smooth' : 'auto' })
  if (shouldSmooth) {
    finishProgrammaticScroll(token, Date.now())
  } else {
    window.requestAnimationFrame(() => {
      if (token !== scrollToken) return
      programmaticScroll.value = false
    })
  }
}

function pauseAutoScroll() {
  if (!autoScroll.value) return
  scrollToken += 1
  programmaticScroll.value = false
  autoScroll.value = false
}

function handleScroll({ scrollTop }: { scrollTop: number; scrollLeft: number }) {
  if (!autoScroll.value || programmaticScroll.value) return
  const wrap = scrollbar.value?.wrapRef
  if (!wrap) return

  const distanceToBottom = wrap.scrollHeight - wrap.clientHeight - scrollTop
  if (distanceToBottom > bottomTolerance) {
    scrollToken += 1
    programmaticScroll.value = false
    autoScroll.value = false
  }
}

function toggleAutoScroll() {
  autoScroll.value = !autoScroll.value
  if (autoScroll.value) scrollToBottom()
}

watch(logTail, () => {
  if (autoScroll.value) scrollToBottom()
}, { flush: 'post' })

onMounted(() => scrollToBottom(false))
onBeforeUnmount(() => {
  scrollToken += 1
})
</script>

<template>
  <div class="log-panel">
    <div v-if="renderedLogs.length" class="log-toolbar">
      <el-button plain @click="toggleAutoScroll">
        <el-icon><VideoPause v-if="autoScroll" /><Bottom v-else /></el-icon>
        {{ autoScroll ? '暂停滚动' : '继续滚动' }}
      </el-button>
    </div>
    <el-scrollbar
      ref="scrollbar"
      class="log-scroll"
      tabindex="0"
      @scroll="handleScroll"
      @wheel.passive="pauseAutoScroll"
      @touchstart.passive="pauseAutoScroll"
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
.log-toolbar { flex: 0 0 auto; display: flex; justify-content: flex-end; margin-bottom: 6px; }
.log-toolbar :deep(.el-button) { min-height: 32px; padding: 6px 11px; font-size: 13px; }
.log-scroll { min-height: 0; flex: 1; }
.log-scroll :deep(.el-scrollbar__view) { min-height: 100%; }
.log-line { display: flex; gap: 12px; padding: 7px 4px; border-bottom: 1px solid var(--el-border-color-lighter); font-size: 13px; line-height: 20px; }
.log-line span { color: var(--el-text-color-secondary); white-space: nowrap; }
.log-line b { min-width: 0; overflow-wrap: anywhere; font-weight: 600; }
.success { color: var(--el-color-success); }
.error { color: var(--el-color-danger); }
.warning,
.warn { color: var(--el-color-warning); }
</style>
