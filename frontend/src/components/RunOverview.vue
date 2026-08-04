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
}>()

const primaryMetrics = computed(() => props.metrics.slice(0, 2))
const resultMetrics = computed(() => props.metrics.slice(2, 5))
</script>

<template>
  <div class="run-overview">
    <div class="primary-metrics">
      <DashboardMetricCard
        v-for="metric in primaryMetrics"
        :key="metric.title"
        :title="metric.title"
        :value="metric.value"
        :icon="metric.icon"
        :tone="metric.tone"
        compact
      />
    </div>

    <div class="result-strip">
      <DashboardMetricCard
        v-for="metric in resultMetrics"
        :key="metric.title"
        :title="metric.title"
        :value="metric.value"
        :icon="metric.icon"
        :tone="metric.tone"
        compact
      />
    </div>
  </div>
</template>

<style scoped>
.run-overview {
  display: grid;
  grid-template-rows: minmax(0, 1fr) 58px;
  gap: 7px;
  width: 100%;
  height: 100%;
  min-height: 0;
  padding: 9px;
  overflow: hidden;
}
.primary-metrics,
.result-strip { display: grid; min-width: 0; min-height: 0; }
.primary-metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 7px; }
.result-strip { grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 5px; }
.primary-metrics :deep(.metric-card),
.result-strip :deep(.metric-card) {
  height: 100%;
  min-height: 0;
  border-radius: 5px;
}
.primary-metrics :deep(.metric-card) { justify-content: center; padding: 9px; }
.primary-metrics :deep(.metric-card.tone-primary) { background: #eff6ff; }
.primary-metrics :deep(.metric-card.tone-warning) { background: #fff5e8; }
.primary-metrics :deep(.metric-icon) { flex-basis: 30px; width: 30px; height: 30px; }
.primary-metrics :deep(.metric-copy) { align-items: center; text-align: center; }
.primary-metrics :deep(.metric-value) { font-size: 26px; line-height: 30px; }
.result-strip :deep(.metric-card) { justify-content: center; padding: 6px 4px; text-align: center; }
.result-strip :deep(.metric-icon) { display: none; }
.result-strip :deep(.metric-copy) { align-items: center; }
.result-strip :deep(.metric-copy > span) { font-size: 10px; line-height: 13px; }
.result-strip :deep(.metric-value) { margin-top: 1px; font-size: 16px; line-height: 20px; }
.result-strip :deep(.metric-card.is-numeric .metric-value) { font-size: 22px; line-height: 26px; }
.result-strip :deep(.tone-success) { background: #edf9f2; }
.result-strip :deep(.tone-danger) { background: #fff0f0; }
.result-strip :deep(.tone-primary) { background: #eaf8fb; }
.result-strip :deep(.tone-success .metric-copy > span),
.result-strip :deep(.tone-success .metric-value) { color: #247d50; }
.result-strip :deep(.tone-danger .metric-copy > span),
.result-strip :deep(.tone-danger .metric-value) { color: #be4545; }
.result-strip :deep(.tone-primary .metric-copy > span),
.result-strip :deep(.tone-primary .metric-value) { color: #237d98; }
</style>
