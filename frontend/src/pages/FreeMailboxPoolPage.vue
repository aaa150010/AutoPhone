<script setup lang="ts">
import FreeMailboxPool from '../components/FreeMailboxPool.vue'
import PageToolbar from '../components/PageToolbar.vue'
</script>

<template>
  <div class="free-mailbox-page">
    <PageToolbar title="Free 注册邮箱池" status="独立邮箱池" tone="success" />
    <FreeMailboxPool />
  </div>
</template>

<style scoped>
.free-mailbox-page { display: grid; grid-template-rows: 44px minmax(0, 1fr); gap: 6px; width: 100%; height: 100%; min-width: 0; min-height: 0; }
</style>
