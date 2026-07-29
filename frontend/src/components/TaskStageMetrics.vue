<script setup lang="ts">
import { Cellphone, ChatDotRound, Clock, Connection, Message, UploadFilled } from '@element-plus/icons-vue'
import DashboardMetricCard from './DashboardMetricCard.vue'
import type { TaskStageCounts, TaskStageGroup } from '../types/api'

defineProps<{ counts?: Partial<TaskStageCounts> }>()

const stages: Array<{
  key: TaskStageGroup
  title: string
  icon: any
  tone: 'primary' | 'success' | 'warning'
}> = [
  { key: 'queue', title: '排队等待', icon: Clock, tone: 'primary' },
  { key: 'oauth', title: 'OAuth 节点', icon: Connection, tone: 'warning' },
  { key: 'email', title: '邮箱验证', icon: Message, tone: 'primary' },
  { key: 'phone', title: '获取手机号', icon: Cellphone, tone: 'warning' },
  { key: 'sms', title: '短信接码', icon: ChatDotRound, tone: 'success' },
  { key: 'finalizing', title: '收尾上传', icon: UploadFilled, tone: 'primary' },
]
</script>

<template>
  <div class="stage-metrics">
    <DashboardMetricCard
      v-for="stage in stages"
      :key="stage.key"
      compact
      :title="stage.title"
      :value="counts?.[stage.key] || 0"
      :icon="stage.icon"
      :tone="stage.tone"
    />
  </div>
</template>

<style scoped>
.stage-metrics { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 8px; }
@media (max-width: 700px) {
  .stage-metrics { grid-template-columns: repeat(3, minmax(0, 1fr)); }
}
</style>
