<script setup lang="ts">
import { computed } from 'vue'
import { Cellphone, ChatDotRound, Clock, Connection, Message, UploadFilled, WarningFilled } from '@element-plus/icons-vue'
import type { RuntimeState, TaskStageGroup } from '../types/api'
import { buildTaskCapacityView } from '../utils/runtimeCapacity'

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
  { key: 'task', label: '任务容量', value: props.runtime.concurrency?.task || {} },
  { key: 'node', label: 'Node 容量', value: props.runtime.concurrency?.node || {} },
  { key: 'protocol', label: '协议容量', value: props.runtime.concurrency?.protocol || {} },
  { key: 'email', label: '邮箱码容量', value: props.runtime.concurrency?.email || {} },
  { key: 'phone', label: '手机提交', value: props.runtime.concurrency?.phone || {} },
].map((item) => {
  const active = numeric(item.value.active)
  const limit = numeric(item.value.limit)
  const base = numeric(item.value.base)
  const pauseRemaining = numeric(item.value.pause_remaining_seconds)
  const taskCapacity = item.key === 'task' ? buildTaskCapacityView(item.value) : null
  return {
    key: item.key,
    label: item.label,
    active,
    limit,
    base,
    isTask: item.key === 'task',
    pauseRemaining,
    waiting: numeric(item.value.waiting),
    usage: limit > 0 ? Math.min(100, (active / limit) * 100) : 0,
    taskCapacity,
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
      <div
        v-for="item in concurrencyRows"
        :key="item.key"
        class="capacity-item"
        :class="{ 'is-task-capacity': item.isTask, 'is-degraded': item.taskCapacity?.degraded }"
      >
        <div class="capacity-copy">
          <span>
            {{ item.label }}<template v-if="!item.isTask && item.base"> · 基{{ item.base }}</template>
            <el-tooltip
              v-if="item.taskCapacity?.degraded"
              :content="item.taskCapacity.tooltip"
              placement="top"
            >
              <i class="capacity-reason" tabindex="0" :aria-label="item.taskCapacity.reasonLabel">
                <el-icon><WarningFilled /></el-icon>
              </i>
            </el-tooltip>
          </span>
          <strong v-if="item.taskCapacity">运行 {{ item.taskCapacity.active }} / 当前 {{ item.taskCapacity.currentLimit }}</strong>
          <strong v-else>{{ item.active }}/{{ item.limit }}</strong>
          <template v-if="!item.isTask">
            <small v-if="item.pauseRemaining">停 {{ item.pauseRemaining }}s</small>
            <small v-else-if="item.waiting">等 {{ item.waiting }}</small>
          </template>
        </div>
        <div v-if="item.taskCapacity" class="task-capacity-meta">
          <span>基线 {{ item.taskCapacity.base }} · 健康上限 {{ item.taskCapacity.healthCeiling }}</span>
          <small v-if="item.taskCapacity.pauseRemaining">暂停 {{ item.taskCapacity.pauseRemaining }}s</small>
          <small v-else-if="item.taskCapacity.waiting">等待 {{ item.taskCapacity.waiting }}</small>
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
.capacity-grid { display: grid; grid-template-columns: minmax(0, 1.55fr) repeat(4, minmax(0, 1fr)); gap: 7px; padding: 3px 12px 10px; }
.capacity-item { min-width: 0; }
.capacity-copy { display: flex; align-items: baseline; gap: 4px; min-width: 0; margin-bottom: 5px; }
.capacity-copy > span { display: flex; align-items: center; min-width: 0; overflow: hidden; color: #788496; font-size: 9px; line-height: 13px; text-overflow: ellipsis; white-space: nowrap; }
.capacity-copy strong { margin-left: auto; color: #344055; font-size: 10px; font-weight: 600; font-variant-numeric: tabular-nums; white-space: nowrap; }
.capacity-copy small { color: #cf7a00; font-size: 9px; white-space: nowrap; }
.capacity-reason { display: inline-flex; flex: 0 0 auto; margin-left: 3px; color: #cf7a00; cursor: help; font-size: 11px; }
.capacity-reason:focus-visible { outline: 1px solid #cf7a00; outline-offset: 1px; }
.task-capacity-meta { display: flex; align-items: center; gap: 4px; min-width: 0; margin: -2px 0 4px; font-size: 9px; line-height: 11px; }
.task-capacity-meta span { min-width: 0; overflow: hidden; color: #788496; text-overflow: ellipsis; white-space: nowrap; }
.task-capacity-meta small { flex: 0 0 auto; margin-left: auto; color: #cf7a00; font-size: 9px; white-space: nowrap; }
.capacity-track { display: block; height: 4px; overflow: hidden; border-radius: 2px; background: #e7ecf2; }
.capacity-track i { display: block; height: 100%; border-radius: inherit; background: #4a9ee8; }
.capacity-item.is-degraded .capacity-track i { background: #e6a23c; }
</style>
