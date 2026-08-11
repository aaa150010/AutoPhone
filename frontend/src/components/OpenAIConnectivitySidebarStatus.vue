<script setup lang="ts">
import { computed } from 'vue'
import { Connection } from '@element-plus/icons-vue'
import type { RuntimeState } from '../types/api'
import { buildOpenAIConnectivityView } from '../utils/openAIConnectivity'

const props = defineProps<{ runtime: RuntimeState }>()
const emit = defineEmits<{ diagnose: [] }>()
const view = computed(() => buildOpenAIConnectivityView(props.runtime))
</script>

<template>
  <div class="connectivity-state" :class="`is-${view.tone}`">
    <div class="connectivity-heading">
      <el-icon><Connection /></el-icon>
      <span>{{ view.sidebarLabel }}</span>
    </div>
    <small>{{ view.sidebarDetail }}</small>
    <el-tooltip content="测试 OpenAI 链路" placement="right">
      <el-button class="diagnostic-button" link :icon="Connection" aria-label="测试 OpenAI 链路" @click="emit('diagnose')" />
    </el-tooltip>
  </div>
</template>

<style scoped>
.connectivity-state { margin-top: 8px; color: #6b778a; }
.connectivity-heading { display: flex; align-items: center; gap: 5px; min-width: 0; font-size: 10px; line-height: 14px; }
.connectivity-heading .el-icon { flex: 0 0 auto; font-size: 12px; }
.connectivity-heading span { min-width: 0; overflow: hidden; font-weight: 650; text-overflow: ellipsis; white-space: nowrap; }
.connectivity-state small { display: block; margin: 2px 0 0 17px; overflow: hidden; font-size: 9px; line-height: 13px; text-overflow: ellipsis; white-space: nowrap; }
.diagnostic-button { position: absolute; right: 0; top: 0; }
.connectivity-state { position: relative; padding-right: 20px; }
.connectivity-state.is-success { color: #16805f; }
.connectivity-state.is-warning { color: #a86513; }
.connectivity-state.is-danger { color: #b54949; }
</style>
