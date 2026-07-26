<script setup lang="ts">
import { computed } from 'vue'
import { CircleCheckFilled, CircleCloseFilled, Message, Monitor } from '@element-plus/icons-vue'
import DashboardMetricCard from './DashboardMetricCard.vue'

const props = defineProps<{ runtime: any }>()

const successful = computed(() => Number(
  props.runtime?.summary?.success
  ?? props.runtime?.tasks?.filter((task: any) => task.status === 'success').length
  ?? 0,
))
const failed = computed(() => Number(
  props.runtime?.summary?.failed
  ?? props.runtime?.tasks?.filter((task: any) => task.status === 'failed').length
  ?? 0,
))
</script>

<template>
  <div class="metrics">
    <DashboardMetricCard
      title="状态"
      :value="runtime?.running ? '运行中' : '未运行'"
      :icon="Monitor"
      :tone="runtime?.running ? 'success' : 'warning'"
    />
    <DashboardMetricCard title="邮箱可用总数" :value="runtime?.pool?.available || 0" :icon="Message" />
    <DashboardMetricCard title="成功数量" :value="successful" :icon="CircleCheckFilled" tone="success" />
    <DashboardMetricCard title="失败数量" :value="failed" :icon="CircleCloseFilled" tone="danger" />
  </div>
</template>

<style scoped>
.metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px; margin-bottom: 10px; }
@media (max-width: 700px) { .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
</style>
