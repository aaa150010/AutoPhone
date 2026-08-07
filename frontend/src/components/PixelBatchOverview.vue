<script setup lang="ts">
import { computed } from 'vue'
import ContentEmptyState from './ContentEmptyState.vue'
import type { PixelBatchCounts, PixelOverview } from '../types/api'

const props = defineProps<{ overview: PixelOverview }>()

const EMPTY_COUNTS: PixelBatchCounts = {
  total: 0,
  completed: 0,
  success: 0,
  pending: 0,
  processing: 0,
  failed: 0,
  needs_confirmation: 0,
}

const batch = computed(() => props.overview.current_batch)
const source = computed(() => batch.value?.source || EMPTY_COUNTS)
const deliveries = computed(() => batch.value?.deliveries || EMPTY_COUNTS)

function dateLabel(value: number | string | null | undefined) {
  if (value == null || value === '') return '-'
  const numeric = Number(value)
  const date = Number.isFinite(numeric)
    ? new Date(numeric < 10_000_000_000 ? numeric * 1000 : numeric)
    : new Date(String(value))
  return Number.isNaN(date.getTime())
    ? '-'
    : date.toLocaleString('zh-CN', {
        hour12: false,
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
      })
}

function statusLabel(status: string) {
  const labels: Record<string, string> = {
    processing: '处理中',
    success: '全部成功',
    partial: '部分失败',
    failed: '失败',
    empty: '空批次',
  }
  return labels[String(status || '').toLowerCase()] || status || '未知'
}

function statusTone(status: string): 'success' | 'warning' | 'danger' | 'info' {
  const value = String(status || '').toLowerCase()
  if (value === 'success') return 'success'
  if (value === 'processing') return 'warning'
  if (['failed', 'partial'].includes(value)) return 'danger'
  return 'info'
}

function percentage(counts: PixelBatchCounts) {
  if (!counts.total) return 0
  return Math.min(100, Math.round((Number(counts.completed || 0) / counts.total) * 100))
}
</script>

<template>
  <section class="batch-overview" aria-label="当前 Pixel 上传批次">
    <template v-if="batch">
      <div class="batch-heading">
        <div class="batch-identity">
          <span class="section-label">当前批次</span>
          <el-tooltip :content="batch.batch_id" placement="top">
            <strong>{{ batch.batch_id }}</strong>
          </el-tooltip>
          <span>{{ dateLabel(batch.batch_started_at) }}</span>
        </div>
        <el-tag :type="statusTone(batch.status)" effect="light">{{ statusLabel(batch.status) }}</el-tag>
      </div>

      <div class="overview-dimensions">
        <div class="progress-dimension">
          <div class="dimension-heading">
            <span>来源账号</span>
            <strong>{{ source.completed }} / {{ source.total }}</strong>
          </div>
          <el-progress :percentage="percentage(source)" :stroke-width="8" :show-text="false" />
          <div class="count-line">
            <span class="success">六平台全成功 {{ source.success }}</span>
            <span>处理中 {{ source.processing }}</span>
            <span>等待 {{ source.pending }}</span>
            <span class="danger">失败 {{ source.failed }}</span>
          </div>
        </div>

        <div class="progress-dimension">
          <div class="dimension-heading">
            <span>目标投递（账号 × 6）</span>
            <strong>{{ deliveries.completed }} / {{ deliveries.total }}</strong>
          </div>
          <el-progress :percentage="percentage(deliveries)" :stroke-width="8" :show-text="false" />
          <div class="count-line">
            <span class="success">成功 {{ deliveries.success }}</span>
            <span>处理中 {{ deliveries.processing }}</span>
            <span>等待 {{ deliveries.pending }}</span>
            <span class="danger">失败 {{ deliveries.failed }}</span>
            <span class="warning">待确认 {{ deliveries.needs_confirmation }}</span>
          </div>
        </div>

        <div class="worker-dimension">
          <span class="section-label">队列 worker</span>
          <strong>{{ overview.queue.active_workers || 0 }} 活跃 / {{ overview.queue.configured_workers || 0 }} 配置</strong>
          <div class="worker-details">
            <span>存活 {{ overview.queue.alive_workers || 0 }}</span>
            <span>等待记录 {{ overview.queue.pending_records || 0 }}</span>
          </div>
        </div>
      </div>
    </template>
    <ContentEmptyState v-else description="暂无 Pixel 上传批次" />
    <el-alert v-if="overview.target_error" class="target-error" :title="overview.target_error" type="warning" :closable="false" show-icon />
  </section>
</template>

<style scoped>
.batch-overview {
  position: relative;
  min-width: 0;
  min-height: 0;
  padding: 10px 13px;
  border: 1px solid var(--workspace-border);
  border-radius: var(--workspace-radius);
  background: var(--workspace-surface);
  box-shadow: var(--workspace-shadow);
}
.batch-heading,
.batch-identity,
.dimension-heading,
.count-line,
.worker-details { display: flex; align-items: center; }
.batch-heading { justify-content: space-between; gap: 12px; margin-bottom: 9px; }
.batch-identity { min-width: 0; gap: 9px; }
.batch-identity strong {
  max-width: 360px;
  overflow: hidden;
  color: var(--el-text-color-primary);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.batch-identity > span:last-child { color: var(--el-text-color-secondary); font-size: 12px; white-space: nowrap; }
.section-label { color: var(--el-text-color-secondary); font-size: 12px; }
.overview-dimensions { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) 190px; gap: 0; }
.progress-dimension { min-width: 0; padding: 0 18px; border-right: 1px solid var(--workspace-border); }
.progress-dimension:first-child { padding-left: 0; }
.dimension-heading { justify-content: space-between; gap: 10px; margin-bottom: 5px; font-size: 12px; }
.dimension-heading strong { color: #18212f; font-size: 15px; font-variant-numeric: tabular-nums; }
.count-line { gap: 10px; margin-top: 5px; color: var(--el-text-color-secondary); font-size: 11px; white-space: nowrap; }
.success { color: var(--el-color-success); }
.danger { color: var(--el-color-danger); }
.warning { color: var(--el-color-warning); }
.worker-dimension { display: flex; flex-direction: column; justify-content: center; gap: 4px; padding-left: 18px; }
.worker-dimension strong { color: #18212f; font-size: 15px; font-variant-numeric: tabular-nums; }
.worker-details { gap: 12px; color: var(--el-text-color-secondary); font-size: 11px; }
.target-error { position: absolute; right: 12px; bottom: 8px; width: auto; max-width: 420px; padding-block: 3px; }
</style>
