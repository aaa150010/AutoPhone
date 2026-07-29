<script setup lang="ts">
import { computed } from 'vue'
import type { TaskProgress, TaskStageGroup } from '../types/api'

const props = defineProps<{
  progress?: TaskProgress | null
  nowSeconds: number
}>()

const elapsedSeconds = computed(() => {
  const progress = props.progress
  if (!progress?.entered_at) return 0
  const end = progress.finished_at ?? props.nowSeconds
  return Math.max(0, Math.floor(end - progress.entered_at))
})

const tagType = computed(() => {
  const tones: Record<TaskStageGroup, 'primary' | 'success' | 'warning' | 'info'> = {
    queue: 'info',
    oauth: 'warning',
    email: 'primary',
    phone: 'warning',
    sms: 'success',
    finalizing: 'primary',
  }
  return tones[props.progress?.group || 'queue']
})

const tooltip = computed(() => {
  const progress = props.progress
  if (!progress) return ''
  const entered = progress.entered_at
    ? new Date(progress.entered_at * 1000).toLocaleTimeString('zh-CN', { hour12: false })
    : '未知'
  return `进入节点 ${entered} · 已停留 ${elapsedSeconds.value} 秒`
})
</script>

<template>
  <el-tooltip v-if="progress" :content="tooltip" placement="top">
    <div class="progress-cell">
      <el-tag :type="tagType" effect="light">{{ progress.label }}</el-tag>
      <span>{{ elapsedSeconds }} 秒</span>
    </div>
  </el-tooltip>
  <span v-else class="muted">暂无</span>
</template>

<style scoped>
.progress-cell { display: flex; align-items: center; gap: 8px; min-width: 0; white-space: nowrap; }
.progress-cell span { color: var(--el-text-color-secondary); font-size: 13px; font-variant-numeric: tabular-nums; }
.muted { color: var(--el-text-color-secondary); }
</style>
