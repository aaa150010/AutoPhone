<script setup lang="ts">
defineProps<{
  running: boolean
  hasPool: boolean
  saving: boolean
  preflighting: boolean
}>()

const emit = defineEmits<{
  save: []
  preflight: []
  start: []
  stop: []
}>()
</script>

<template>
  <div class="actions">
    <el-button :loading="saving" :disabled="running" @click="emit('save')">
      <el-icon><Check /></el-icon>保存配置
    </el-button>
    <el-button :loading="preflighting" :disabled="running" @click="emit('preflight')">
      <el-icon><CircleCheck /></el-icon>真实链路预检
    </el-button>
    <el-button type="primary" :disabled="running || !hasPool" @click="emit('start')">
      <el-icon><VideoPlay /></el-icon>开始运行
    </el-button>
    <el-button type="danger" plain :disabled="!running" @click="emit('stop')">
      <el-icon><VideoPause /></el-icon>停止
    </el-button>
  </div>
</template>

<style scoped>
.actions {
  display: flex;
  flex-wrap: nowrap;
  gap: 6px;
  margin-top: 8px;
}
.actions :deep(.el-button) {
  min-width: 0;
  margin-left: 0;
  padding: 5px 8px;
}
@media (max-width: 560px) {
  .actions { flex-wrap: wrap; }
}
</style>
