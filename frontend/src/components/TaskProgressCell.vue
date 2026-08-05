<script setup lang="ts">
import { computed } from 'vue'
import type { TaskProgress, TaskStageGroup, TaskTiming } from '../types/api'

const props = defineProps<{
  progress?: TaskProgress | null
  timing?: TaskTiming | null
  nowSeconds: number
}>()

const resolvedTiming = computed(() => props.progress?.timing || props.timing || null)

const elapsedSeconds = computed(() => {
  const progress = props.progress
  if (!progress?.entered_at) return 0
  const end = progress.finished_at ?? props.nowSeconds
  return Math.max(0, Math.floor(end - progress.entered_at))
})

const totalElapsedSeconds = computed(() => {
  const timing = resolvedTiming.value
  if (!timing?.started_at) return Number(timing?.elapsed_seconds || 0)
  const end = timing.finished_at ?? props.nowSeconds
  return Math.max(Number(timing.elapsed_seconds || 0), Math.floor(end - timing.started_at))
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
  const timing = resolvedTiming.value
  if (!progress && !timing) return ''
  const entered = progress?.entered_at
    ? new Date(progress.entered_at * 1000).toLocaleTimeString('zh-CN', { hour12: false })
    : '未知'
  const stages = (timing?.stages || [])
    .map(stage => `${stage.label} ${Math.floor(Number(stage.elapsed_seconds || 0))} 秒${stage.visits > 1 ? `（${stage.visits} 次）` : ''}`)
    .join(' · ')
  const current = progress ? `进入节点 ${entered} · 当前 ${elapsedSeconds.value} 秒` : ''
  return [current, `总耗时 ${totalElapsedSeconds.value} 秒`, stages].filter(Boolean).join(' · ')
})
</script>

<template>
  <el-tooltip v-if="progress || resolvedTiming" :content="tooltip" placement="top">
    <div class="progress-cell">
      <el-tag v-if="progress" :type="tagType" effect="light">{{ progress.label }}</el-tag>
      <span v-if="progress">当前 {{ elapsedSeconds }} 秒 / 总 {{ totalElapsedSeconds }} 秒</span>
      <span v-else>总 {{ totalElapsedSeconds }} 秒</span>
    </div>
  </el-tooltip>
  <span v-else class="muted">暂无</span>
</template>

<style scoped>
.progress-cell { display: flex; align-items: center; gap: 8px; min-width: 0; white-space: nowrap; }
.progress-cell span { color: var(--el-text-color-secondary); font-size: 13px; font-variant-numeric: tabular-nums; }
.muted { color: var(--el-text-color-secondary); }
</style>
