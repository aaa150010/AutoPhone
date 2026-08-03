<script setup lang="ts">
import { computed } from 'vue'
import { Cellphone, ChatDotRound, Clock, Connection, Message, UploadFilled } from '@element-plus/icons-vue'
import type { RuntimeState, TaskStageGroup } from '../types/api'

const props = defineProps<{ runtime: RuntimeState }>()

const stages: Array<{ key: TaskStageGroup; label: string; icon: any }> = [
  { key: 'queue', label: '排队', icon: Clock },
  { key: 'oauth', label: 'OAuth', icon: Connection },
  { key: 'email', label: '邮箱验证', icon: Message },
  { key: 'phone', label: '取号', icon: Cellphone },
  { key: 'sms', label: '接码', icon: ChatDotRound },
  { key: 'finalizing', label: '上传', icon: UploadFilled },
]

function numeric(value: unknown) {
  const parsed = Number(value || 0)
  return Number.isFinite(parsed) ? Math.max(0, parsed) : 0
}

function stageCount(key: TaskStageGroup) {
  return numeric(props.runtime.stage_counts?.[key])
}

const furthestActiveIndex = computed(() => {
  let result = -1
  stages.forEach((stage, index) => {
    if (stageCount(stage.key) > 0) result = index
  })
  return result
})

function stageState(index: number, key: TaskStageGroup) {
  if (stageCount(key) > 0) return key === 'queue' ? 'is-waiting' : 'is-active'
  if (furthestActiveIndex.value > index) return 'is-done'
  return 'is-pending'
}

function connectorState(index: number) {
  if (furthestActiveIndex.value <= index) return 'is-pending'
  return index === furthestActiveIndex.value - 1 ? 'is-active' : 'is-done'
}

const concurrencyRows = computed(() => [
  { label: '任务容量', value: props.runtime.concurrency?.task || {} },
  { label: 'Node 容量', value: props.runtime.concurrency?.node || {} },
  { label: '邮箱码容量', value: props.runtime.concurrency?.email || {} },
].map((item) => {
  const active = numeric(item.value.active)
  const limit = numeric(item.value.limit)
  return {
    label: item.label,
    active,
    limit,
    waiting: numeric(item.value.waiting),
    usage: limit > 0 ? Math.min(100, (active / limit) * 100) : 0,
  }
}))
</script>

<template>
  <div class="pipeline-monitor">
    <div class="pipeline-flow" aria-label="运行管线流程">
      <template v-for="(stage, index) in stages" :key="stage.key">
        <div class="flow-node" :class="stageState(index, stage.key)">
          <span class="node-icon"><el-icon><component :is="stage.icon" /></el-icon></span>
          <small>{{ stage.label }}</small>
          <strong>{{ stageCount(stage.key) }}</strong>
        </div>
        <i v-if="index < stages.length - 1" class="flow-line" :class="connectorState(index)" />
      </template>
    </div>

    <div class="capacity-grid">
      <div v-for="item in concurrencyRows" :key="item.label" class="capacity-item">
        <div class="capacity-copy">
          <span>{{ item.label }}</span>
          <strong>{{ item.active }}/{{ item.limit }}</strong>
          <small v-if="item.waiting">等 {{ item.waiting }}</small>
        </div>
        <b class="capacity-track"><i :style="{ width: `${item.usage}%` }" /></b>
      </div>
    </div>
  </div>
</template>

<style scoped>
.pipeline-monitor {
  display: grid;
  grid-template-rows: minmax(0, 1fr) 58px;
  width: 100%;
  height: 100%;
  min-height: 0;
  overflow: hidden;
}
.pipeline-flow { display: flex; align-items: flex-start; min-width: 0; padding: 22px 12px 10px; }
.flow-node { flex: 0 0 42px; min-width: 0; text-align: center; }
.node-icon {
  display: grid;
  place-items: center;
  width: 28px;
  height: 28px;
  margin: 0 auto 5px;
  border: 1px solid #d5dde8;
  border-radius: 50%;
  background: #f7f9fc;
  color: #8390a3;
}
.node-icon .el-icon { font-size: 14px; }
.flow-node small {
  display: block;
  min-height: 24px;
  overflow: hidden;
  color: #6e7b8d;
  font-size: 9px;
  line-height: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.flow-node strong { color: #2c374b; font-size: 12px; line-height: 15px; font-weight: 600; font-variant-numeric: tabular-nums; }
.flow-node.is-done .node-icon { border-color: #9edbb9; background: #ebf8f0; color: #2a955c; }
.flow-node.is-active .node-icon { border-color: #91c4f7; background: #eaf4ff; color: #287fd8; box-shadow: 0 0 0 3px rgba(64, 158, 255, .08); }
.flow-node.is-waiting .node-icon { border-color: #efc278; background: #fff5e8; color: #cf7a00; }
.flow-line { flex: 1 1 auto; min-width: 5px; height: 2px; margin-top: 13px; background: #dfe5ed; }
.flow-line.is-done { background: #65be8c; }
.flow-line.is-active { background: #4a9ee8; }
.capacity-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 9px; padding: 3px 12px 10px; }
.capacity-item { min-width: 0; }
.capacity-copy { display: flex; align-items: baseline; gap: 4px; min-width: 0; margin-bottom: 5px; }
.capacity-copy span { overflow: hidden; color: #788496; font-size: 9px; line-height: 13px; text-overflow: ellipsis; white-space: nowrap; }
.capacity-copy strong { margin-left: auto; color: #344055; font-size: 10px; font-weight: 600; font-variant-numeric: tabular-nums; }
.capacity-copy small { color: #cf7a00; font-size: 9px; white-space: nowrap; }
.capacity-track { display: block; height: 4px; overflow: hidden; border-radius: 2px; background: #e7ecf2; }
.capacity-track i { display: block; height: 100%; border-radius: inherit; background: #4a9ee8; }
</style>
