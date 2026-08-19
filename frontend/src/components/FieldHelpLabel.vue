<script setup lang="ts">
import { QuestionFilled } from '@element-plus/icons-vue'

defineProps<{
  label: string
  help: string
}>()
</script>

<template>
  <span class="field-help-label">
    <span>{{ label }}</span>
    <el-tooltip :content="help" placement="top" :show-after="250">
      <el-icon class="help-icon" tabindex="0" :aria-label="`${label}说明`"><QuestionFilled /></el-icon>
    </el-tooltip>
  </span>
</template>

<style scoped>
.field-help-label { display: inline-flex; align-items: center; gap: 4px; min-width: 0; }
.help-icon { flex: 0 0 auto; color: var(--el-text-color-placeholder); font-size: 13px; cursor: help; }
.help-icon:hover, .help-icon:focus { color: var(--el-color-primary); outline: none; }
</style>
