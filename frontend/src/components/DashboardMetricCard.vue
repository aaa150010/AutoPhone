<script setup lang="ts">
import { computed } from 'vue'
import RollingMetricValue from './RollingMetricValue.vue'

const props = defineProps<{
  title: string
  value: string | number
  icon: any
  tone?: 'primary' | 'success' | 'danger' | 'warning'
  compact?: boolean
  framed?: boolean
}>()

const numericValue = computed(() => (
  typeof props.value === 'number' && Number.isFinite(props.value) ? props.value : null
))
</script>

<template>
  <div
    class="metric-card"
    :class="[`tone-${tone || 'primary'}`, { compact, framed }]"
  >
    <el-icon class="metric-icon"><component :is="icon" /></el-icon>
    <div class="metric-copy">
      <span>{{ title }}</span>
      <strong class="metric-value">
        <RollingMetricValue v-if="numericValue !== null" :value="numericValue" />
        <template v-else>{{ value }}</template>
      </strong>
    </div>
  </div>
</template>

<style scoped>
.metric-card { display: flex; align-items: center; gap: 11px; width: 100%; min-width: 0; min-height: 78px; padding: 8px 10px; text-align: left; }
.metric-card.framed { height: 78px; border: 1px solid var(--workspace-border); border-radius: 6px; background: #fff; box-shadow: 0 1px 3px rgba(22, 34, 51, .07); }
.metric-icon { display: grid; place-items: center; flex: 0 0 36px; width: 36px; height: 36px; border-radius: 6px; font-size: 19px; }
.metric-copy { display: flex; flex-direction: column; justify-content: center; min-width: 0; }
.metric-copy span { overflow: hidden; color: var(--el-text-color-secondary); font-size: 13px; line-height: 18px; text-overflow: ellipsis; white-space: nowrap; }
.metric-value { display: block; max-width: 100%; overflow: hidden; margin-top: 1px; color: #18212f; font-size: 22px; line-height: 25px; font-variant-numeric: tabular-nums; text-overflow: ellipsis; white-space: nowrap; }
.metric-card.compact { min-height: 52px; padding: 7px 5px; }
.metric-card.compact .metric-icon { flex-basis: 30px; width: 30px; height: 30px; font-size: 16px; }
.metric-card.compact .metric-copy span { font-size: 12px; line-height: 15px; }
.metric-card.compact .metric-value { margin-top: 0; font-size: 18px; line-height: 21px; }
.tone-primary .metric-icon { background: var(--el-color-primary-light-9); color: var(--el-color-primary); }
.tone-success .metric-icon { background: var(--el-color-success-light-9); color: var(--el-color-success); }
.tone-danger .metric-icon { background: var(--el-color-danger-light-9); color: var(--el-color-danger); }
.tone-warning .metric-icon { background: var(--el-color-warning-light-9); color: var(--el-color-warning); }
</style>
