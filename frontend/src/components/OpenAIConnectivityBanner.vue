<script setup lang="ts">
import { Connection, SwitchButton } from '@element-plus/icons-vue'
import type { OpenAIConnectivityView } from '../utils/openAIConnectivity'

defineProps<{ view: OpenAIConnectivityView; disablingGuard?: boolean }>()
const emit = defineEmits<{ disableGuard: []; diagnose: [] }>()
</script>

<template>
  <el-alert
    v-if="view.banner"
    class="connectivity-banner"
    :type="view.banner.type"
    :closable="false"
    show-icon
  >
    <template #title>
      <div class="banner-copy">
        <strong>{{ view.banner.title }}</strong>
        <span>{{ view.banner.detail }}</span>
        <el-button
          v-if="view.status === 'outage' || view.status === 'recovering'"
          class="guard-action"
          type="danger"
          plain
          size="small"
          :loading="disablingGuard"
          @click="emit('disableGuard')"
        >
          <el-icon><SwitchButton /></el-icon>关闭保护
        </el-button>
        <el-button class="guard-action" type="primary" plain size="small" @click="emit('diagnose')">
          <el-icon><Connection /></el-icon>测试链路
        </el-button>
      </div>
    </template>
  </el-alert>
</template>

<style scoped>
.connectivity-banner { box-sizing: border-box; height: 40px; padding: 5px 10px; border-radius: 5px; }
.connectivity-banner :deep(.el-alert__content) { min-width: 0; padding: 0; }
.banner-copy { display: flex; align-items: center; gap: 10px; width: 100%; min-width: 0; }
.banner-copy strong { flex: 0 0 auto; font-size: 12px; line-height: 18px; letter-spacing: 0; }
.banner-copy span { flex: 1 1 auto; min-width: 0; overflow: hidden; font-size: 11px; line-height: 18px; text-overflow: ellipsis; white-space: nowrap; }
.guard-action { flex: 0 0 auto; height: 26px; padding: 0 8px; }
</style>
