<script setup lang="ts">
defineProps<{ title: string; status?: string; tone?: 'success' | 'warning' | 'danger' | 'info' }>()
</script>

<template>
  <header class="page-toolbar">
    <div class="toolbar-heading">
      <h1>{{ title }}</h1>
      <el-tag v-if="status" size="small" effect="light" :type="tone || 'info'">{{ status }}</el-tag>
    </div>
    <div class="toolbar-actions"><slot /></div>
  </header>
</template>

<style scoped>
.page-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; height: 38px; min-height: 38px; padding: 0 4px; }
.toolbar-heading { display: flex; align-items: center; gap: 8px; min-width: 0; }
h1 { margin: 0; color: #18212f; font-size: 18px; line-height: 24px; font-weight: 680; letter-spacing: 0; }
.toolbar-actions { display: flex; align-items: center; gap: 6px; min-width: 0; }
.toolbar-actions :deep(.el-button + .el-button) { margin-left: 0; }
</style>
