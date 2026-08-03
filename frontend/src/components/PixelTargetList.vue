<script setup lang="ts">
import ContentEmptyState from './ContentEmptyState.vue'
import type { PixelTarget } from '../types/api'

defineProps<{
  targets: PixelTarget[]
  activeId: string
  loading?: boolean
  disabled?: boolean
}>()

const emit = defineEmits<{ select: [string] }>()

function checkedAt(value: string | null) {
  if (!value) return '未检测'
  const date = new Date(value)
  return Number.isNaN(date.getTime())
    ? '已检测'
    : date.toLocaleString('zh-CN', { hour12: false, month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}
</script>

<template>
  <div v-loading="loading" class="target-list">
    <button
      v-for="target in targets"
      :key="target.id"
      type="button"
      :disabled="disabled"
      class="target-row"
      :class="{ active: target.id === activeId }"
      @click="emit('select', target.id)"
    >
      <span class="target-status" :class="target.connected ? 'connected' : target.error ? 'failed' : 'idle'" />
      <span class="target-copy">
        <span class="target-heading">
          <strong>{{ target.id }}</strong>
          <el-tag v-if="!target.autoUpload" type="info" effect="plain" size="small">不自动上传</el-tag>
        </span>
        <span class="target-email">{{ target.email || '-' }}</span>
        <span class="target-meta">
          <span>{{ target.accountCount == null ? '账号数未知' : `${target.accountCount} 个账号` }}</span>
          <span>{{ checkedAt(target.lastCheckedAt) }}</span>
        </span>
        <span v-if="target.error" class="target-error">{{ target.error }}</span>
      </span>
    </button>
    <ContentEmptyState v-if="!loading && !targets.length" description="暂无 Pixel 目标" />
  </div>
</template>

<style scoped>
.target-list { min-height: 0; height: 100%; overflow: auto; }
.target-row {
  display: grid;
  grid-template-columns: 8px minmax(0, 1fr);
  gap: 9px;
  width: 100%;
  min-height: 82px;
  padding: 9px 10px;
  border: 0;
  border-bottom: 1px solid var(--el-border-color-lighter);
  border-radius: 0;
  background: #fff;
  color: inherit;
  text-align: left;
  cursor: pointer;
}
.target-row:hover { background: #f7faff; }
.target-row.active { background: #eef5ff; box-shadow: inset 3px 0 #2563eb; }
.target-row:disabled { cursor: default; opacity: .72; }
.target-status { width: 7px; height: 7px; margin-top: 6px; border-radius: 50%; background: #94a3b8; }
.target-status.connected { background: #16a34a; }
.target-status.failed { background: #dc2626; }
.target-copy { display: flex; flex-direction: column; gap: 3px; min-width: 0; }
.target-heading { display: flex; align-items: center; justify-content: space-between; gap: 6px; min-width: 0; }
.target-heading strong { color: #202938; font-size: 13px; line-height: 20px; }
.target-email,
.target-error { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.target-email { color: #536174; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; }
.target-meta { display: flex; justify-content: space-between; gap: 8px; color: #8792a4; font-size: 10px; }
.target-error { color: var(--el-color-danger); font-size: 10px; }
</style>
