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
  detail?: string
  interactive?: boolean
  active?: boolean
}>()

const emit = defineEmits<{
  activate: []
}>()

const numericValue = computed(() => (
  typeof props.value === 'number' && Number.isFinite(props.value) ? props.value : null
))
</script>

<template>
  <component
    :is="interactive ? 'button' : 'div'"
    :type="interactive ? 'button' : undefined"
    class="metric-card"
    :class="[
      `tone-${tone || 'primary'}`,
      { compact, framed, active, 'is-interactive': interactive, 'is-numeric': numericValue !== null },
    ]"
    :aria-pressed="interactive ? active : undefined"
    @click="interactive && emit('activate')"
  >
    <el-icon class="metric-icon"><component :is="icon" /></el-icon>
    <div class="metric-copy">
      <span>{{ title }}</span>
      <strong class="metric-value">
        <RollingMetricValue v-if="numericValue !== null" :value="numericValue" />
        <template v-else>{{ value }}</template>
      </strong>
      <small v-if="detail" class="metric-detail">{{ detail }}</small>
    </div>
  </component>
</template>

<style scoped>
.metric-card { display: flex; align-items: center; gap: 9px; width: 100%; min-width: 0; min-height: 52px; padding: 6px 9px; border: 0; background: transparent; color: inherit; font: inherit; letter-spacing: 0; text-align: left; }
.metric-card.framed { height: 52px; border: 1px solid var(--workspace-border); border-radius: 6px; background: #fff; box-shadow: 0 1px 3px rgba(22, 34, 51, .07); }
.metric-card.is-interactive { cursor: pointer; transition: border-color .16s ease, box-shadow .16s ease, background-color .16s ease, transform .16s ease; }
.metric-card.is-interactive:hover { transform: translateY(-1px); border-color: var(--el-color-primary-light-5); background: var(--el-color-primary-light-9); box-shadow: 0 4px 10px rgba(22, 34, 51, .13); }
.metric-card.is-interactive:focus-visible { outline: 2px solid var(--el-color-primary-light-5); outline-offset: 2px; }
.metric-card.is-interactive.active { border-color: var(--el-color-primary); background: var(--el-color-primary-light-9); box-shadow: 0 0 0 1px var(--el-color-primary-light-5), 0 3px 8px rgba(22, 34, 51, .1); }
.metric-card.is-interactive:active { transform: translateY(0); }
@media (prefers-reduced-motion: reduce) { .metric-card.is-interactive { transition: none; } }
.metric-icon { display: grid; place-items: center; flex: 0 0 28px; width: 28px; height: 28px; border-radius: 5px; font-size: 16px; }
.metric-copy { display: flex; flex-direction: column; justify-content: center; min-width: 0; }
.metric-copy > span { overflow: hidden; color: var(--el-text-color-secondary); font-size: 13px; line-height: 18px; text-overflow: ellipsis; white-space: nowrap; }
.metric-value { display: block; max-width: 100%; overflow: hidden; margin-top: 0; color: #18212f; font-size: 21px; line-height: 24px; font-weight: 720; font-variant-numeric: tabular-nums; letter-spacing: 0; text-overflow: ellipsis; white-space: nowrap; }
.metric-detail { overflow: hidden; color: var(--el-text-color-secondary); font-size: 11px; line-height: 14px; font-variant-numeric: tabular-nums; text-overflow: ellipsis; white-space: nowrap; }
.metric-card.is-numeric .metric-value { font-size: 24px; line-height: 27px; }
.metric-card.compact { min-height: 46px; height: 46px; padding: 4px 6px; }
.metric-card.compact .metric-icon { flex-basis: 24px; width: 24px; height: 24px; font-size: 14px; }
.metric-card.compact .metric-copy > span { font-size: 12px; line-height: 15px; }
.metric-card.compact .metric-value { margin-top: 0; font-size: 17px; line-height: 20px; }
.metric-card.compact.is-numeric .metric-value { font-size: 21px; line-height: 24px; }
.tone-primary .metric-icon { background: var(--el-color-primary-light-9); color: var(--el-color-primary); }
.tone-success .metric-icon { background: var(--el-color-success-light-9); color: var(--el-color-success); }
.tone-danger .metric-icon { background: var(--el-color-danger-light-9); color: var(--el-color-danger); }
.tone-warning .metric-icon { background: var(--el-color-warning-light-9); color: var(--el-color-warning); }
</style>
