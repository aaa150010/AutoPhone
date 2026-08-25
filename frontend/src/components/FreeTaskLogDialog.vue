<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { Aim, ArrowLeft, ArrowRight, Bottom, Refresh } from '@element-plus/icons-vue'
import { getFreeLogs } from '../api/client'
import type { FreeLogEntry } from '../types/api'
import {
  FREE_LOG_WINDOW_SIZE,
  clampFreeLogWindowStart,
  containingFreeLogWindowStart,
  effectiveFreeLogLevel,
  filterFreeLogs,
  freeLogContextText,
  freeLogLevelLabel,
  freeLogNodeCode,
  freeLogNodeLabel,
  isFreeLogError,
  latestFreeLogWindowStart,
  shouldShowFreeLogNodeCode,
  type FreeLogLevelFilter,
} from '../utils/freeTaskLogs'
import ContentEmptyState from './ContentEmptyState.vue'

interface FreeTaskLogContext {
  task_id?: string
  email?: string
  driver?: string
  stage?: string
  stage_label?: string
  ip_label?: string
  registration_ip?: string
  expected_exit_ip?: string
}

const props = defineProps<{
  modelValue: boolean
  task?: FreeTaskLogContext
}>()

const emit = defineEmits<{ 'update:modelValue': [boolean] }>()

const logs = ref<FreeLogEntry[]>([])
const loading = ref(false)
const levelFilter = ref<FreeLogLevelFilter>('all')
const nodeFilter = ref('')
const autoFollow = ref(true)
const windowStart = ref(0)
const logScroll = ref<HTMLElement>()
let requestGeneration = 0
let programmaticScroll = false
let scrollResetFrame = 0

const taskId = computed(() => String(props.task?.task_id || ''))
const driverLabel = computed(() => ({ roxybrowser: 'RoxyBrowser', protocol: '全协议', camoufox: 'Camoufox' } as Record<string, string>)[String(props.task?.driver || '')] || String(props.task?.driver || 'Free'))
const dialogTitle = computed(() => `${props.task?.email || 'Free 账号'} · ${driverLabel.value} 日志`)
const filteredLogs = computed(() => filterFreeLogs(logs.value, levelFilter.value, nodeFilter.value))
const visibleLogs = computed(() => filteredLogs.value.slice(windowStart.value, windowStart.value + FREE_LOG_WINDOW_SIZE))
const windowEnd = computed(() => Math.min(filteredLogs.value.length, windowStart.value + FREE_LOG_WINDOW_SIZE))
const hasPreviousWindow = computed(() => windowStart.value > 0)
const hasNextWindow = computed(() => windowEnd.value < filteredLogs.value.length)
const firstErrorIndex = computed(() => logs.value.findIndex(isFreeLogError))
const nodeOptions = computed(() => {
  const seen = new Set<string>()
  return logs.value.reduce<Array<{ code: string; label: string }>>((result, row) => {
    const code = freeLogNodeCode(row)
    if (!code || seen.has(code)) return result
    seen.add(code)
    const label = freeLogNodeLabel(row)
    result.push({ code, label: label && label.toLowerCase() !== code.toLowerCase() ? `${label} · ${code}` : code })
    return result
  }, [])
})
const levelOptions = computed(() => {
  const counts = logs.value.reduce<Record<string, number>>((result, row) => {
    const level = effectiveFreeLogLevel(row)
    result[level] = (result[level] || 0) + 1
    return result
  }, {})
  return [
    { value: 'all', label: `全部 ${logs.value.length}` },
    { value: 'error', label: `错误 ${counts.error || 0}` },
    { value: 'warn', label: `警告 ${counts.warn || 0}` },
    { value: 'success', label: `成功 ${counts.success || 0}` },
    { value: 'info', label: `信息 ${counts.info || 0}` },
    { value: 'debug', label: `调试 ${counts.debug || 0}` },
  ] as Array<{ value: FreeLogLevelFilter; label: string }>
})

function setDialogOpen(value: boolean) {
  emit('update:modelValue', value)
}

function setScrollTop(value: number) {
  if (!logScroll.value) return
  programmaticScroll = true
  logScroll.value.scrollTop = value
  window.cancelAnimationFrame(scrollResetFrame)
  scrollResetFrame = window.requestAnimationFrame(() => { programmaticScroll = false })
}

async function scrollToLatest() {
  autoFollow.value = true
  windowStart.value = latestFreeLogWindowStart(filteredLogs.value.length)
  await nextTick()
  setScrollTop(logScroll.value?.scrollHeight || 0)
}

async function moveWindow(direction: -1 | 1) {
  autoFollow.value = false
  windowStart.value = clampFreeLogWindowStart(
    filteredLogs.value.length,
    windowStart.value + direction * FREE_LOG_WINDOW_SIZE,
  )
  await nextTick()
  setScrollTop(0)
}

function handleScroll() {
  if (programmaticScroll || !logScroll.value) return
  const distance = logScroll.value.scrollHeight - logScroll.value.scrollTop - logScroll.value.clientHeight
  autoFollow.value = !hasNextWindow.value && distance <= 48
}

async function refresh(options: { forceLatest?: boolean; silent?: boolean } = {}) {
  const id = taskId.value
  if (!id || !props.modelValue) return
  const generation = ++requestGeneration
  const previousScrollTop = logScroll.value?.scrollTop || 0
  const followLatest = Boolean(options.forceLatest) || autoFollow.value
  if (!options.silent) loading.value = true
  try {
    const result = await getFreeLogs(id)
    if (generation !== requestGeneration || id !== taskId.value) return
    logs.value = Array.isArray(result.logs) ? result.logs : []
    windowStart.value = followLatest
      ? latestFreeLogWindowStart(filteredLogs.value.length)
      : clampFreeLogWindowStart(filteredLogs.value.length, windowStart.value)
    await nextTick()
    setScrollTop(followLatest ? (logScroll.value?.scrollHeight || 0) : previousScrollTop)
  } catch (error: any) {
    if (!options.silent) ElMessage.error(error?.message || 'Free 账号日志读取失败')
  } finally {
    if (generation === requestGeneration && !options.silent) loading.value = false
  }
}

async function openCurrentTask() {
  requestGeneration += 1
  logs.value = []
  levelFilter.value = 'all'
  nodeFilter.value = ''
  autoFollow.value = true
  windowStart.value = 0
  await nextTick()
  await refresh({ forceLatest: true })
}

async function locateFirstError() {
  const index = firstErrorIndex.value
  if (index < 0) return
  levelFilter.value = 'all'
  nodeFilter.value = ''
  autoFollow.value = false
  await nextTick()
  const position = filteredLogs.value.findIndex(entry => entry.index === index)
  windowStart.value = containingFreeLogWindowStart(position, filteredLogs.value.length)
  await nextTick()
  const row = logScroll.value?.querySelector<HTMLElement>(`[data-log-index="${index}"]`)
  if (row) setScrollTop(Math.max(0, row.offsetTop - 12))
}

watch(() => props.modelValue, (open) => {
  if (open && taskId.value) void openCurrentTask()
  if (!open) requestGeneration += 1
})

watch(taskId, (value, previous) => {
  if (props.modelValue && value && value !== previous) void openCurrentTask()
})

watch([levelFilter, nodeFilter], async () => {
  windowStart.value = autoFollow.value
    ? latestFreeLogWindowStart(filteredLogs.value.length)
    : clampFreeLogWindowStart(filteredLogs.value.length, windowStart.value)
  await nextTick()
  setScrollTop(autoFollow.value ? (logScroll.value?.scrollHeight || 0) : 0)
})

onBeforeUnmount(() => {
  requestGeneration += 1
  window.cancelAnimationFrame(scrollResetFrame)
})

defineExpose({ refresh })
</script>

<template>
  <el-dialog :model-value="modelValue" :title="dialogTitle" width="1040px" destroy-on-close @update:model-value="setDialogOpen">
    <div class="log-dialog-meta">
      <span>任务 {{ task?.task_id || '-' }}</span>
      <span>阶段 {{ task?.stage_label || task?.stage || '-' }}</span>
      <span>{{ task?.ip_label || '注册 IP' }} {{ task?.registration_ip || task?.expected_exit_ip || '-' }}</span>
      <el-button size="small" :icon="Refresh" :loading="loading" @click="refresh({ forceLatest: autoFollow })">刷新</el-button>
    </div>
    <div v-if="logs.length" class="log-dialog-controls">
      <el-select v-model="levelFilter" size="small" aria-label="日志级别" class="level-filter">
        <el-option v-for="item in levelOptions" :key="item.value" :label="item.label" :value="item.value" />
      </el-select>
      <el-select v-model="nodeFilter" size="small" clearable filterable placeholder="全部节点" aria-label="日志节点" class="node-filter">
        <el-option v-for="item in nodeOptions" :key="item.code" :label="item.label" :value="item.code" />
      </el-select>
      <span class="follow-control"><el-switch v-model="autoFollow" size="small" @change="autoFollow && scrollToLatest()" />自动跟随</span>
      <el-button size="small" :icon="Aim" :disabled="firstErrorIndex < 0" @click="locateFirstError">定位首个错误</el-button>
      <el-tooltip content="滚动到最新日志"><el-button circle size="small" :icon="Bottom" aria-label="滚动到最新日志" @click="scrollToLatest" /></el-tooltip>
      <span class="filtered-count">匹配 {{ filteredLogs.length }} / {{ logs.length }}</span>
      <span class="window-control">
        <el-tooltip content="查看较早日志"><el-button circle size="small" :icon="ArrowLeft" :disabled="!hasPreviousWindow" aria-label="查看较早日志" @click="moveWindow(-1)" /></el-tooltip>
        <small>{{ filteredLogs.length ? windowStart + 1 : 0 }}-{{ windowEnd }} / {{ filteredLogs.length }}</small>
        <el-tooltip content="查看较新日志"><el-button circle size="small" :icon="ArrowRight" :disabled="!hasNextWindow" aria-label="查看较新日志" @click="moveWindow(1)" /></el-tooltip>
      </span>
    </div>
    <div ref="logScroll" v-loading="loading" class="log-dialog-list" @scroll="handleScroll">
      <div
        v-for="entry in visibleLogs"
        :key="`${entry.index}-${entry.row.time || ''}-${entry.row.message || ''}`"
        :data-log-index="entry.index"
        :class="`log-${effectiveFreeLogLevel(entry.row)}`"
      >
        <small class="log-time">{{ entry.row.time || '' }}</small>
        <strong class="log-level">{{ freeLogLevelLabel(effectiveFreeLogLevel(entry.row)) }}</strong>
        <small class="log-task-id" :title="String(entry.row.task_id || taskId || '-')">任务 {{ entry.row.task_id || taskId || '-' }}</small>
        <span class="log-message">
          <b v-if="freeLogNodeLabel(entry.row) || freeLogNodeCode(entry.row)">
            {{ freeLogNodeLabel(entry.row) || freeLogNodeCode(entry.row) }}<code v-if="shouldShowFreeLogNodeCode(entry.row)">{{ freeLogNodeCode(entry.row) }}</code>
          </b>
          {{ entry.row.message || '' }}
          <em v-if="freeLogContextText(entry.row)">{{ freeLogContextText(entry.row) }}</em>
          <small v-if="entry.row.error_code || entry.row.provider_code" class="log-code">{{ entry.row.error_code || '' }}{{ entry.row.provider_code ? ` · Provider ${entry.row.provider_code}` : '' }}</small>
          <small v-if="entry.row.diagnostic || entry.row.technical_summary" class="log-diagnostic">{{ entry.row.diagnostic || entry.row.technical_summary }}</small>
          <small v-if="entry.row.action_hint" class="log-action">建议：{{ entry.row.action_hint }}</small>
        </span>
      </div>
      <ContentEmptyState v-if="!filteredLogs.length && !loading" :description="logs.length ? '没有符合筛选条件的日志' : '暂无账号日志'" />
    </div>
  </el-dialog>
</template>

<style scoped>
.log-dialog-meta, .log-dialog-controls { display: flex; align-items: center; gap: 12px; min-width: 0; }
.log-dialog-meta { margin-bottom: 8px; color: var(--el-text-color-secondary); font-size: 12px; }
.log-dialog-meta .el-button { margin-left: auto; }
.log-dialog-controls { min-height: 32px; margin-bottom: 8px; gap: 8px; }
.level-filter { width: 120px; }
.node-filter { width: 240px; }
.follow-control { display: inline-flex; align-items: center; gap: 6px; color: var(--el-text-color-regular); font-size: 12px; white-space: nowrap; }
.filtered-count { color: var(--el-text-color-secondary); font-size: 12px; font-variant-numeric: tabular-nums; white-space: nowrap; }
.window-control { display: inline-flex; align-items: center; gap: 5px; margin-left: auto; white-space: nowrap; }
.window-control small { min-width: 92px; color: var(--el-text-color-secondary); text-align: center; font-variant-numeric: tabular-nums; }
.log-dialog-list { position: relative; height: 560px; overflow: auto; padding: 9px 10px; border: 1px solid var(--workspace-border); border-radius: 4px; background: #101923; color: #dbe7f2; font: 12px/18px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; scrollbar-width: thin; scrollbar-color: #577b9d #101923; }
.log-dialog-list > div:not(.content-empty) { display: grid; grid-template-columns: 145px 36px 150px minmax(0, 1fr); gap: 8px; padding: 2px 0; white-space: pre-wrap; word-break: break-word; }
.log-dialog-list small { color: #8ca0b5; }
.log-time, .log-task-id { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.log-level { color: currentColor; font-size: 11px; font-weight: 700; }
.log-message { min-width: 0; }
.log-error { color: #ff8791; }
.log-warn { color: #f5bc72; }
.log-success { color: #71dbb1; }
.log-debug { color: #9ba9b7; }
.log-dialog-list b { margin-right: 7px; color: #78b4ef; font-weight: 650; }
.log-dialog-list code { margin-left: 5px; color: #91a8bd; font-size: 11px; }
.log-dialog-list em, .log-dialog-list .log-code, .log-dialog-list .log-diagnostic, .log-dialog-list .log-action { display: block; margin-top: 1px; font-style: normal; font-size: 11px; }
.log-dialog-list em { color: #91a8bd; }
.log-dialog-list .log-code { color: #b5c8d9; }
.log-dialog-list .log-diagnostic { color: #e0ad77; }
.log-dialog-list .log-action { color: #80c9ee; }
.log-dialog-list :deep(.content-empty) { background: transparent; }
.log-dialog-list :deep(.content-empty .el-empty__description p) { color: #91a8bd; }
</style>
