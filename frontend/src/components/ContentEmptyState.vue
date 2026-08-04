<script setup lang="ts">
withDefaults(defineProps<{
  description?: string
  imageSize?: number
}>(), {
  description: '暂无数据',
  imageSize: 58,
})
</script>

<template>
  <el-empty class="content-empty" :description="description" :image-size="imageSize" />
</template>

<style scoped>
.content-empty {
  box-sizing: border-box;
  width: 100%;
  height: 100%;
  min-height: 108px;
  padding: 12px 0;
  background: #fbfdff;
  color: #8a96a8;
  line-height: normal;
}
.content-empty :deep(.el-empty__description) { margin-top: 6px; }
.content-empty :deep(.el-empty__description p) {
  color: #8a96a8;
  font-size: 13px;
  line-height: 20px;
}
</style>
