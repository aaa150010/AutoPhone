<script setup lang="ts">
withDefaults(defineProps<{
  tone?: 'success' | 'warning' | 'danger' | 'info' | 'primary'
  label: string
}>(), { tone: 'info' })
</script>

<template>
  <span class="state-dot" :class="`tone-${tone}`">
    <span class="state-dot__mark" aria-hidden="true" />
    <span class="state-dot__label">{{ label }}</span>
  </span>
</template>

<style scoped>
.state-dot { display: inline-flex; align-items: center; justify-content: center; gap: 6px; max-width: 100%; white-space: nowrap; }
.state-dot__mark { flex: 0 0 auto; width: 7px; height: 7px; border-radius: 50%; background: var(--el-color-info); }
.state-dot__label { min-width: 0; overflow: hidden; text-overflow: ellipsis; font-size: 12px; color: var(--el-text-color-regular); }
.tone-success .state-dot__mark { background: var(--el-color-success); }
.tone-warning .state-dot__mark { background: var(--el-color-warning); }
.tone-danger .state-dot__mark { background: var(--el-color-danger); }
.tone-primary .state-dot__mark { background: var(--el-color-primary); }
.tone-success .state-dot__label { color: var(--el-color-success); }
.tone-warning .state-dot__label { color: var(--el-color-warning-dark-2, #a65f00); }
.tone-danger .state-dot__label { color: var(--el-color-danger); }
</style>
