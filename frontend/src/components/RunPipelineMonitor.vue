<script setup lang="ts">
import { computed } from 'vue'
import { Cellphone, ChatDotRound, Clock, Connection, Message, UploadFilled } from '@element-plus/icons-vue'
import type { RuntimeState, TaskStageGroup } from '../types/api'

const props = defineProps<{ runtime: RuntimeState }>()

const stages: Array<{ key: TaskStageGroup; label: string; icon: any }> = [
  { key: 'queue', label: '排队等待', icon: Clock },
  { key: 'oauth', label: 'OAuth 节点', icon: Connection },
  { key: 'email', label: '邮箱验证', icon: Message },
  { key: 'phone', label: '获取手机号', icon: Cellphone },
  { key: 'sms', label: '短信接码', icon: ChatDotRound },
  { key: 'finalizing', label: '收尾上传', icon: UploadFilled },
]

const concurrencyRows = computed(() => [
  { label: '任务', ...(props.runtime.concurrency?.task || {}) },
  { label: 'Node', ...(props.runtime.concurrency?.node || {}) },
  { label: '邮箱码', ...(props.runtime.concurrency?.email || {}) },
])
</script>

<template>
  <div class="pipeline-monitor">
    <div class="pipeline-grid">
      <div v-for="stage in stages" :key="stage.key" class="stage-row">
        <el-icon><component :is="stage.icon" /></el-icon>
        <div class="stage-copy">
          <span>{{ stage.label }}</span>
          <strong>{{ runtime.stage_counts?.[stage.key] || 0 }}</strong>
        </div>
      </div>
    </div>

    <div class="concurrency-grid">
      <div v-for="item in concurrencyRows" :key="item.label" class="concurrency-item">
        <span>{{ item.label }}</span>
        <strong>{{ Number(item.active || 0) }}/{{ Number(item.limit || 0) }}</strong>
        <small v-if="Number(item.waiting || 0)">等 {{ item.waiting }}</small>
      </div>
    </div>
  </div>
</template>

<style scoped>
.pipeline-monitor { display: grid; grid-template-rows: minmax(0, 1fr) 56px; width: 100%; height: 100%; min-height: 0; overflow: hidden; }
.pipeline-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); min-height: 0; padding: 4px 10px; }
.stage-row { display: flex; align-items: center; gap: 7px; min-width: 0; padding: 5px 4px; border-bottom: 1px solid var(--el-border-color-lighter); }
.stage-row:nth-child(even) { padding-left: 10px; border-left: 1px solid var(--el-border-color-lighter); }
.stage-row:nth-last-child(-n + 2) { border-bottom: 0; }
.stage-row > .el-icon { flex: 0 0 auto; color: var(--el-color-primary); font-size: 15px; }
.stage-copy { display: flex; flex-direction: column; min-width: 0; }
.stage-copy span { overflow: hidden; color: var(--el-text-color-regular); font-size: 11px; line-height: 15px; text-overflow: ellipsis; white-space: nowrap; }
.stage-copy strong { color: #202938; font-size: 16px; line-height: 18px; font-variant-numeric: tabular-nums; }
.concurrency-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); margin: 0 10px; border-top: 1px solid var(--workspace-border); }
.concurrency-item { display: flex; flex-direction: column; justify-content: center; min-width: 0; padding: 6px 7px; }
.concurrency-item + .concurrency-item { border-left: 1px solid var(--el-border-color-lighter); }
.concurrency-item span { overflow: hidden; color: var(--el-text-color-secondary); font-size: 11px; line-height: 14px; text-overflow: ellipsis; white-space: nowrap; }
.concurrency-item strong { font-size: 13px; line-height: 17px; font-variant-numeric: tabular-nums; }
.concurrency-item small { color: var(--el-color-warning); font-size: 10px; line-height: 12px; }
</style>
