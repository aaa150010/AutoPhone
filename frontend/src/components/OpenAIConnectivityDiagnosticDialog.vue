<script setup lang="ts">
import { computed, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Connection, Refresh, Setting } from '@element-plus/icons-vue'
import { ApiError, runOpenAIConnectivityDiagnostics } from '../api/client'
import type { OpenAIConnectivityDiagnostic } from '../types/api'

const emit = defineEmits<{ openSettings: [] }>()
const visible = ref(false)
const running = ref(false)
const reason = ref('')
const result = ref<OpenAIConnectivityDiagnostic | null>(null)
const errorMessage = ref('')

const overallType = computed(() => {
  if (result.value?.overall === 'healthy') return 'success'
  if (result.value?.overall === 'degraded') return 'warning'
  return 'error'
})

function originLabel(origin: string) {
  return origin === 'auth.openai.com' ? 'Auth' : origin === 'sentinel.openai.com' ? 'Sentinel' : origin
}

function originStatus(row: OpenAIConnectivityDiagnostic['network'][number]) {
  if (!row.reachable) return '连接失败'
  if (row.service_status === 'rate_limited') return '限流'
  if (row.service_status === 'upstream_error') return '服务异常'
  return '可达'
}

function originType(row: OpenAIConnectivityDiagnostic['network'][number]) {
  if (!row.reachable) return 'danger'
  return row.service_available === false ? 'warning' : 'success'
}

function open(message = '') {
  reason.value = message
  result.value = null
  errorMessage.value = ''
  visible.value = true
}

async function run() {
  if (running.value) return
  running.value = true
  errorMessage.value = ''
  try {
    result.value = (await runOpenAIConnectivityDiagnostics()).diagnostic
  } catch (error: any) {
    const payload = error instanceof ApiError ? error.payload : null
    errorMessage.value = String(payload?.failure?.public_message || error?.message || 'OpenAI 链路诊断失败')
    ElMessage.error(errorMessage.value)
  } finally {
    running.value = false
  }
}

function close() {
  if (!running.value) visible.value = false
}

function openSettings() {
  close()
  emit('openSettings')
}

defineExpose({ open })
</script>

<template>
  <el-dialog v-model="visible" title="OpenAI 链路诊断" width="760px" append-to-body destroy-on-close>
    <el-alert
      v-if="reason"
      class="diagnostic-reason"
      type="warning"
      :closable="false"
      show-icon
      :title="reason"
    />

    <div v-if="!result && !errorMessage" class="diagnostic-empty">
      <el-icon><Connection /></el-icon>
      <span>使用已保存代理检查 Auth、Sentinel 和 Node/Sentinel。</span>
    </div>
    <el-alert v-if="errorMessage" type="error" :closable="false" show-icon :title="errorMessage" />

    <template v-if="result">
      <el-alert
        class="diagnostic-summary"
        :type="overallType"
        :closable="false"
        show-icon
        :title="result.overall === 'healthy' ? '链路与 Sentinel 均正常' : result.overall === 'degraded' ? '链路可达，但服务状态或 Sentinel 深测异常' : '链路存在连接问题'"
      >
        <template #default>
          <span>代理{{ result.proxy_configured ? '已配置' : '未配置' }} · 总耗时 {{ result.elapsed_ms ?? '-' }} ms</span>
        </template>
      </el-alert>

      <el-table :data="result.network" size="small" border class="diagnostic-table">
        <el-table-column type="index" label="序号" width="58" align="center" fixed="left" />
        <el-table-column label="目标" min-width="170">
          <template #default="{ row }">{{ originLabel(row.origin) }}<small>{{ row.origin }}</small></template>
        </el-table-column>
        <el-table-column label="状态" width="85">
          <template #default="{ row }"><el-tag :type="originType(row)" size="small">{{ originStatus(row) }}</el-tag></template>
        </el-table-column>
        <el-table-column label="延迟" width="90">
          <template #default="{ row }">{{ row.latency_ms ?? '-' }} ms</template>
        </el-table-column>
        <el-table-column label="HTTP" width="75">
          <template #default="{ row }">{{ row.status_code ?? '-' }}</template>
        </el-table-column>
        <el-table-column label="原因" min-width="250">
          <template #default="{ row }">
            <span>{{ row.reason_label || '可达' }}</span>
            <small v-if="row.technical_summary">{{ row.technical_summary }}</small>
          </template>
        </el-table-column>
      </el-table>

      <div class="sentinel-result">
        <div class="result-heading"><strong>Node/Sentinel 深测</strong><el-tag :type="result.sentinel.ok ? 'success' : 'danger'" size="small">{{ result.sentinel.ok ? '通过' : result.sentinel.attempted ? '失败' : '已跳过' }}</el-tag></div>
        <p>{{ result.sentinel.public_message || result.sentinel.skipped_reason || '未返回诊断详情' }}</p>
        <small v-if="result.sentinel.latency_ms">耗时 {{ result.sentinel.latency_ms }} ms</small>
        <small v-if="result.sentinel.technical_summary">{{ result.sentinel.technical_summary }}</small>
      </div>
    </template>

    <template #footer>
      <el-button @click="openSettings"><el-icon><Setting /></el-icon>运行配置</el-button>
      <el-button :loading="running" type="primary" @click="run"><el-icon><Refresh /></el-icon>{{ result ? '重新测试' : '开始测试' }}</el-button>
      <el-button :disabled="running" @click="close">关闭</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.diagnostic-reason,
.diagnostic-summary { margin-bottom: 10px; }
.diagnostic-empty { display: flex; align-items: center; justify-content: center; gap: 8px; min-height: 150px; color: var(--el-text-color-secondary); }
.diagnostic-table { width: 100%; }
.diagnostic-table small { display: block; color: var(--el-text-color-secondary); font-size: 10px; line-height: 16px; }
.sentinel-result { margin-top: 12px; padding-top: 10px; border-top: 1px solid var(--workspace-border); }
.result-heading { display: flex; align-items: center; gap: 8px; }
.sentinel-result p { margin: 7px 0 3px; color: var(--el-text-color-regular); line-height: 20px; }
.sentinel-result small { display: block; color: var(--el-text-color-secondary); line-height: 18px; }
</style>
