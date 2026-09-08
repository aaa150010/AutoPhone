<script setup lang="ts">
import { computed } from 'vue'
import type { TaskProgress, TaskStageGroup, TaskTiming } from '../types/api'
import { TASK_TERMINAL_STATUSES } from '../utils/taskResultViews'

const props = defineProps<{
  progress?: TaskProgress | null
  timing?: TaskTiming | null
  nowSeconds: number
  status?: string
}>()

const terminalStatuses = TASK_TERMINAL_STATUSES

const normalizedStatus = computed(() => String(props.status || '').trim().toLowerCase())
const terminal = computed(() => terminalStatuses.has(normalizedStatus.value))
const successful = computed(() => normalizedStatus.value === 'success')

const resolvedTiming = computed(() => props.progress?.timing || props.timing || null)

const elapsedSeconds = computed(() => {
  const progress = props.progress
  if (!progress?.entered_at) return 0
  const end = progress.finished_at ?? props.nowSeconds
  return Math.max(0, Math.floor(end - progress.entered_at))
})

const totalElapsedSeconds = computed(() => {
  const timing = resolvedTiming.value
  // 总耗时只统计实际执行：起点用 execution_started_at，剔除排队等待。
  if (timing?.execution_started_at != null) {
    const end = timing.finished_at ?? props.nowSeconds
    return Math.max(
      Math.floor(Number(timing.execution_elapsed_seconds || 0)),
      Math.max(0, Math.floor(end - timing.execution_started_at)),
    )
  }
  // 旧数据/排队中任务：无执行起点时沿用原有 started_at 口径。
  if (!timing?.started_at) return Math.floor(Number(timing?.elapsed_seconds || 0))
  const end = timing.finished_at ?? props.nowSeconds
  return Math.max(Math.floor(Number(timing.elapsed_seconds || 0)), Math.floor(end - timing.started_at))
})

const queueElapsedSeconds = computed(() => {
  const timing = resolvedTiming.value
  if (!timing) return 0
  if (timing.execution_started_at != null) return Number(timing.queue_elapsed_seconds || 0)
  const queuedAt = Number(timing.queued_at || timing.started_at || 0)
  const end = timing.finished_at ?? props.nowSeconds
  return queuedAt ? Math.max(0, Math.floor(end - queuedAt)) : Number(timing.queue_elapsed_seconds || 0)
})

const executionElapsedSeconds = computed(() => {
  const timing = resolvedTiming.value
  if (!timing?.execution_started_at) return Number(timing?.execution_elapsed_seconds || 0)
  const end = timing.finished_at ?? props.nowSeconds
  return Math.max(Number(timing.execution_elapsed_seconds || 0), Math.floor(end - timing.execution_started_at))
})

function formatSeconds(value: unknown) {
  const seconds = Math.max(0, Number(value || 0))
  if (!Number.isFinite(seconds)) return '0'
  if (seconds > 0 && seconds < 10 && !Number.isInteger(seconds)) {
    return seconds.toFixed(2).replace(/0+$/, '').replace(/\.$/, '')
  }
  return String(Math.floor(seconds))
}

const tagType = computed(() => {
  const tones: Record<TaskStageGroup, 'primary' | 'success' | 'warning' | 'info'> = {
    queue: 'info',
    oauth: 'warning',
    email: 'primary',
    phone: 'warning',
    sms: 'success',
    free: 'primary',
    finalizing: 'primary',
  }
  return tones[props.progress?.group || 'queue']
})

interface StageColumn {
  key: string
  label: string
  seconds: string
  visits: number
}

const stageColumns = computed<StageColumn[]>(() =>
  (resolvedTiming.value?.stages || []).map((stage, index) => ({
    key: `${stage.code}-${index}`,
    label: stage.label || stage.code,
    seconds: formatSeconds(stage.elapsed_seconds),
    visits: Number(stage.visits || 0),
  })),
)

const segmentColumns = computed<StageColumn[]>(() =>
  (resolvedTiming.value?.segments || []).map((segment, index) => ({
    key: `${segment.code}-${index}`,
    label: segment.label || segment.code,
    seconds: formatSeconds(segment.elapsed_seconds),
    visits: Number(segment.visits || 0),
  })),
)

const enteredAtLabel = computed(() => {
  const entered = props.progress?.entered_at
  if (!entered) return ''
  return new Date(entered * 1000).toLocaleTimeString('zh-CN', { hour12: false })
})

const hasTimingDetails = computed(() => stageColumns.value.length > 0 || segmentColumns.value.length > 0)
</script>

<template>
  <el-popover
    v-if="progress || resolvedTiming"
    trigger="hover"
    placement="top"
    :persistent="false"
    :show-after="200"
    popper-class="task-progress-popover"
    width="auto"
  >
    <template #reference>
      <div class="progress-cell">
        <el-tag v-if="progress" :type="tagType" effect="light">{{ progress.label }}</el-tag>
        <span class="progress-seconds">{{ totalElapsedSeconds }}s</span>
      </div>
    </template>
    <div class="progress-popover-body">
      <div class="popover-summary">
        <span v-if="enteredAtLabel">进入节点 {{ enteredAtLabel }}</span>
        <span>{{ terminal ? (successful ? '末次节点' : '停在节点') : '当前' }} {{ elapsedSeconds }} 秒</span>
        <span>总耗时 {{ totalElapsedSeconds }} 秒</span>
        <span>排队 {{ queueElapsedSeconds }} 秒 · 执行 {{ executionElapsedSeconds }} 秒</span>
      </div>
      <template v-if="hasTimingDetails">
        <div v-if="stageColumns.length" class="popover-section">
          <div class="popover-section-title">节点耗时</div>
          <div class="popover-grid">
            <div v-for="stage in stageColumns" :key="stage.key" class="popover-grid-cell">
              <span class="cell-label" :title="stage.visits > 1 ? `${stage.label}（${stage.visits} 次）` : stage.label">{{ stage.label }}</span>
              <span class="cell-value">{{ stage.seconds }}s<span v-if="stage.visits > 1" class="cell-visits">×{{ stage.visits }}</span></span>
            </div>
          </div>
        </div>
        <div v-if="segmentColumns.length" class="popover-section">
          <div class="popover-section-title">细分耗时</div>
          <div class="popover-grid">
            <div v-for="segment in segmentColumns" :key="segment.key" class="popover-grid-cell">
              <span class="cell-label" :title="segment.visits > 1 ? `${segment.label}（${segment.visits} 次）` : segment.label">{{ segment.label }}</span>
              <span class="cell-value">{{ segment.seconds }}s<span v-if="segment.visits > 1" class="cell-visits">×{{ segment.visits }}</span></span>
            </div>
          </div>
        </div>
      </template>
    </div>
  </el-popover>
  <span v-else class="muted">暂无</span>
</template>

<style scoped>
.progress-cell { display: flex; align-items: center; gap: 8px; min-width: 0; white-space: nowrap; }
.progress-cell :deep(.el-tag) { max-width: 220px; overflow: hidden; text-overflow: ellipsis; }
.progress-seconds { color: var(--el-text-color-secondary); font-size: 12px; font-variant-numeric: tabular-nums; }
.muted { color: var(--el-text-color-secondary); }

.progress-popover-body { max-width: 560px; }
.popover-summary { display: flex; flex-wrap: wrap; gap: 4px 12px; font-size: 12px; color: var(--el-text-color-secondary); margin-bottom: 8px; }
.popover-section { margin-top: 8px; }
.popover-section-title { font-size: 12px; font-weight: 600; color: var(--el-text-color-primary); margin-bottom: 6px; }
.popover-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: 6px 10px; }
.popover-grid-cell { display: flex; flex-direction: column; gap: 1px; min-width: 0; padding: 4px 6px; background: var(--el-fill-color-light); border-radius: 4px; }
.cell-label { font-size: 12px; color: var(--el-text-color-regular); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.cell-value { font-size: 12px; color: var(--el-text-color-secondary); font-variant-numeric: tabular-nums; }
.cell-visits { margin-left: 3px; color: var(--el-color-warning); }
</style>
