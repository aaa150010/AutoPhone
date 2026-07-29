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
.metric-card { height: 100%; min-height: 78px; padding: 0; border-color: var(--workspace-border); border-radius: var(--workspace-radius); background: var(--workspace-surface); box-shadow: var(--workspace-shadow); }
.metric-card :deep(.el-card__body) { width: 100%; height: 100%; display: flex; flex-direction: row; align-items: center; gap: 12px; padding: 11px 13px; }
.metric-icon { flex: 0 0 38px; width: 38px; height: 38px; border-radius: 7px; font-size: 21px; }
.metric-copy { min-width: 0; display: flex; flex-direction: column; }
.metric-copy span,
.metric-copy strong { display: block; }
.metric-copy span { color: var(--el-text-color-secondary); font-size: 13px; line-height: 18px; }
.metric-copy strong { margin-top: 2px; color: #18212f; font-size: 22px; line-height: 25px; font-variant-numeric: tabular-nums; }
.metric-card.compact { min-height: 58px; }
.metric-card.compact :deep(.el-card__body) { gap: 9px; padding: 8px 10px; }
.metric-card.compact .metric-icon { flex-basis: 32px; width: 32px; height: 32px; font-size: 18px; }
.metric-card.compact .metric-copy span { font-size: 12px; line-height: 16px; }
.metric-card.compact .metric-copy strong { margin-top: 1px; font-size: 18px; line-height: 21px; }
.tone-primary .metric-icon { background: var(--el-color-primary-light-9); color: var(--el-color-primary); }
.tone-success .metric-icon { background: var(--el-color-success-light-9); color: var(--el-color-success); }
.tone-danger .metric-icon { background: var(--el-color-danger-light-9); color: var(--el-color-danger); }
.tone-warning .metric-icon { background: var(--el-color-warning-light-9); color: var(--el-color-warning); }
</style>
