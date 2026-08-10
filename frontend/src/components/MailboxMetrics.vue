<script setup lang="ts">
import {
  CircleCheckFilled,
  CircleCloseFilled,
  Collection,
  Message,
  TakeawayBox,
  VideoPlay,
} from '@element-plus/icons-vue'
import { managedMailboxCount } from '../utils/mailboxRows'
import DashboardMetricCard from './DashboardMetricCard.vue'

const props = defineProps<{
  counts: Record<string, number>
  activeFilter: string
  draftOpen: boolean
}>()

const emit = defineEmits<{
  filter: [value: string]
  draft: []
}>()

const metrics = [
  { key: 'managed', title: '管理中', icon: Collection, tone: 'primary', filter: 'all' },
  { key: 'available', title: '可用', icon: Message, tone: 'primary', filter: 'available' },
  { key: 'running', title: '运行中', icon: VideoPlay, tone: 'warning', filter: 'running' },
  { key: 'success', title: '已使用', icon: CircleCheckFilled, tone: 'success', filter: 'consumed' },
  { key: 'failed', title: '失败', icon: CircleCloseFilled, tone: 'danger', filter: 'failed' },
  { key: 'draft', title: '草稿箱', icon: TakeawayBox, tone: 'warning', filter: 'draft' },
] as const

function activate(metric: (typeof metrics)[number]) {
  if (metric.key === 'draft') emit('draft')
  else emit('filter', metric.filter)
}

function metricValue(metric: (typeof metrics)[number]) {
  return metric.key === 'managed'
    ? managedMailboxCount(props.counts)
    : props.counts[metric.key] || 0
}
</script>

<template>
  <div class="mailbox-metrics">
    <DashboardMetricCard
      v-for="metric in metrics"
      :key="metric.key"
      :title="metric.title"
      :value="metricValue(metric)"
      :icon="metric.icon"
      :tone="metric.tone"
      :active="metric.key === 'draft' ? draftOpen : !draftOpen && activeFilter === metric.filter"
      interactive
      framed
      @activate="activate(metric)"
    />
  </div>
</template>

<style scoped>
.mailbox-metrics { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 7px; min-width: 0; }
</style>
