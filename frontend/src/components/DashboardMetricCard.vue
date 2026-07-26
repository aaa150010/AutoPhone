<script setup lang="ts">
import { computed } from 'vue'
import RollingMetricValue from './RollingMetricValue.vue'

const props = defineProps<{
  title: string
  value: string | number
  icon: any
  tone?: 'primary' | 'success' | 'danger' | 'warning'
  compact?: boolean
}>()

const numericValue = computed(() => (
  typeof props.value === 'number' && Number.isFinite(props.value) ? props.value : null
))
</script>

<template>
  <el-card
    shadow="never"
    class="metric-card"
    :class="[`tone-${tone || 'primary'}`, { compact }]"
  >
    <el-icon class="metric-icon"><component :is="icon" /></el-icon>
    <div class="metric-copy">
      <span>{{ title }}</span>
      <strong>
        <RollingMetricValue v-if="numericValue !== null" :value="numericValue" />
        <template v-else>{{ value }}</template>
      </strong>
    </div>
  </el-card>
</template>

<style scoped>
.metric-card { height: 100%; padding: 0; }
.metric-card :deep(.el-card__body) { width: 100%; height: 100%; display: flex; flex-direction: row; align-items: center; gap: 10px; padding: 10px 12px; }
.metric-icon { flex: 0 0 32px; width: 32px; height: 32px; border-radius: 6px; font-size: 18px; }
.metric-copy { min-width: 0; display: flex; flex-direction: column; }
.metric-copy span,
.metric-copy strong { display: block; }
.metric-copy span { color: var(--el-text-color-secondary); font-size: 12px; line-height: 16px; }
.metric-copy strong { margin-top: 3px; color: var(--el-text-color-primary); font-size: 20px; line-height: 23px; font-variant-numeric: tabular-nums; }
.metric-card.compact { min-height: 54px; }
.metric-card.compact :deep(.el-card__body) { gap: 7px; padding: 7px 8px; }
.metric-card.compact .metric-icon { flex-basis: 28px; width: 28px; height: 28px; font-size: 16px; }
.metric-card.compact .metric-copy span { font-size: 11px; line-height: 14px; }
.metric-card.compact .metric-copy strong { margin-top: 1px; font-size: 17px; line-height: 19px; }
.tone-primary .metric-icon { background: var(--el-color-primary-light-9); color: var(--el-color-primary); }
.tone-success .metric-icon { background: var(--el-color-success-light-9); color: var(--el-color-success); }
.tone-danger .metric-icon { background: var(--el-color-danger-light-9); color: var(--el-color-danger); }
.tone-warning .metric-icon { background: var(--el-color-warning-light-9); color: var(--el-color-warning); }
</style>
