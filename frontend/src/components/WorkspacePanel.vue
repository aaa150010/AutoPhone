<script setup lang="ts">
defineProps<{
  title?: string
  icon?: any
  fill?: boolean
  scroll?: boolean
  bodyPadding?: 'none' | 'compact' | 'normal'
}>()
</script>

<template>
  <el-card
    shadow="never"
    class="workspace-panel"
    :class="[
      `padding-${bodyPadding || 'normal'}`,
      { 'is-fill': fill, 'is-scroll': scroll, 'has-header': title || $slots.header || $slots.actions },
    ]"
  >
    <template v-if="title || $slots.header || $slots.actions" #header>
      <div class="panel-header">
        <slot name="header">
          <div class="panel-title">
            <el-icon v-if="icon"><component :is="icon" /></el-icon>
            <span>{{ title }}</span>
          </div>
        </slot>
        <div v-if="$slots.actions" class="panel-actions"><slot name="actions" /></div>
      </div>
    </template>
    <slot />
    <div v-if="$slots.footer" class="panel-footer"><slot name="footer" /></div>
  </el-card>
</template>

<style scoped>
.workspace-panel {
  min-width: 0;
  min-height: 0;
  border-color: var(--workspace-border);
  border-radius: var(--workspace-radius);
  background: var(--workspace-surface);
  box-shadow: var(--workspace-shadow);
}
.workspace-panel.is-fill { height: 100%; display: flex; flex-direction: column; }
.workspace-panel.is-fill > :deep(.el-card__body) { min-height: 0; flex: 1; }
.workspace-panel.is-scroll > :deep(.el-card__body) { overflow: auto; }
.workspace-panel > :deep(.el-card__header) { flex: 0 0 40px; height: 40px; padding: 0 11px; }
.workspace-panel > :deep(.el-card__body) { min-width: 0; }
.workspace-panel.padding-none > :deep(.el-card__body) { padding: 0; }
.workspace-panel.padding-compact > :deep(.el-card__body) { padding: 8px; }
.workspace-panel.padding-normal > :deep(.el-card__body) { padding: 10px 12px; }
.panel-header { display: flex; align-items: center; justify-content: space-between; gap: 10px; height: 39px; }
.panel-title { display: flex; align-items: center; gap: 7px; min-width: 0; color: var(--el-text-color-primary); font-size: 13px; font-weight: 650; }
.panel-title .el-icon { color: var(--el-color-primary); font-size: 15px; }
.panel-title span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.panel-actions { display: flex; align-items: center; gap: 5px; min-width: 0; }
.panel-actions :deep(.el-button + .el-button) { margin-left: 0; }
.panel-footer { padding: 8px 12px; border-top: 1px solid var(--workspace-border); }
</style>
