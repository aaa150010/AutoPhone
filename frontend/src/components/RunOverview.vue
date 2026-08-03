<script setup lang="ts">
import { computed } from 'vue'
import DashboardMetricCard from './DashboardMetricCard.vue'

type MetricTone = 'primary' | 'success' | 'danger' | 'warning'

const props = defineProps<{
  metrics: ReadonlyArray<{
    title: string
    value: string | number
    icon: any
    tone?: MetricTone
  }>
  completed: number
  target: number
}>()

const progress = computed(() => {
  if (!props.target) return 0
  return Math.min(100, Math.round((props.completed / props.target) * 100))
})

</script>

<template>
  <div class="run-overview">
    <div class="metric-list">
      <DashboardMetricCard
        v-for="metric in metrics"
        :key="metric.title"
        :title="metric.title"
        :value="metric.value"
        :icon="metric.icon"
        :tone="metric.tone"
        compact
      />
    </div>

    <section class="progress-section">
      <div class="section-label">本轮进度</div>
      <div class="progress-copy">
        <strong>{{ progress }}%</strong>
        <span>{{ completed }} / {{ target || '-' }}</span>
      </div>
      <el-progress :percentage="progress" :stroke-width="6" :show-text="false" />
    </section>

  </div>
</template>

<style scoped>
.run-overview { display: grid; grid-template-rows: minmax(0, 1fr) auto; width: 100%; height: 100%; min-height: 0; overflow: hidden; }
.metric-list { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); min-height: 0; padding: 6px 9px 2px; }
.metric-list :deep(.metric-card) { border-bottom: 1px solid var(--el-border-color-lighter); }
.metric-list :deep(.metric-card:nth-child(even)) { padding-left: 10px; border-left: 1px solid var(--el-border-color-lighter); }
.metric-list :deep(.metric-card:nth-last-child(-n + 2)) { border-bottom: 0; }
.metric-list :deep(.metric-card:last-child:nth-child(odd)) { grid-column: 1 / -1; }
.metric-list :deep(.metric-card.compact) { min-height: 42px; padding-top: 4px; padding-bottom: 4px; }
.metric-list :deep(.metric-card.compact .metric-icon) { flex-basis: 28px; width: 28px; height: 28px; }
.section-label { color: #718096; font-size: 12px; line-height: 18px; font-weight: 650; }
.progress-section { margin: 0 10px; padding: 7px 0 9px; border-top: 1px solid var(--workspace-border); }
.progress-copy { display: flex; align-items: baseline; gap: 8px; margin: 1px 0 5px; }
.progress-copy strong { color: #172033; font-size: 20px; line-height: 24px; font-variant-numeric: tabular-nums; }
.progress-copy span { color: var(--el-text-color-secondary); font-size: 12px; font-variant-numeric: tabular-nums; }
</style>
