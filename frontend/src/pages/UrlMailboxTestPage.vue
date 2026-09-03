<script setup lang="ts">
import { computed, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { CircleCheck, CircleClose, Connection, Link, Search } from '@element-plus/icons-vue'
import { ApiError, testMailboxUrl } from '../api/client'
import WorkspacePanel from '../components/WorkspacePanel.vue'
import type { MailboxUrlTestResult } from '../types/api'

const value = ref('')
const loading = ref(false)
const result = ref<MailboxUrlTestResult | null>(null)

const resultLabel = computed(() => result.value?.ok ? '已取到验证码' : result.value ? '未取到验证码' : '待测试')
const diagnostics = computed(() => result.value?.diagnostics || {
  listing_messages: 0,
  detail_links: 0,
  detail_refreshed: 0,
  detail_cache_hits: 0,
  detail_refresh_pending: 0,
  detail_errors: 0,
  openai_messages: 0,
  code_messages: 0,
})

async function runTest() {
  const input = value.value.trim()
  if (!input) {
    ElMessage.warning('请输入取件 URL')
    return
  }
  loading.value = true
  result.value = null
  try {
    result.value = await testMailboxUrl(input)
    if (result.value.ok) ElMessage.success('已识别到新的 OpenAI 验证码')
  } catch (error) {
    if (error instanceof ApiError) {
      result.value = {
        ok: false,
        code: error.payload.code,
        code_found: false,
        reason: error.payload.code || 'mailbox_url_test_failed',
        error: error.message,
        attempts: 0,
        elapsed_seconds: 0,
        resend_attempted: false,
        resend_succeeded: false,
        diagnostics: diagnostics.value,
      }
    } else {
      ElMessage.error('URL测试失败')
    }
  } finally {
    loading.value = false
  }
}

function clearTest() {
  value.value = ''
  result.value = null
}
</script>

<template>
  <div class="url-test-page">
    <div class="url-test-grid">
      <WorkspacePanel title="取件地址" :icon="Link" body-padding="normal">
        <template #actions>
          <el-button :disabled="loading" @click="clearTest"><el-icon><CircleClose /></el-icon>清空</el-button>
          <el-button type="primary" :loading="loading" :disabled="!value.trim()" @click="runTest">
            <el-icon><Search /></el-icon>开始测试
          </el-button>
        </template>
        <el-input
          v-model="value"
          type="textarea"
          :rows="5"
          resize="none"
          spellcheck="false"
          placeholder="粘贴完整 URL，或粘贴 邮箱---URL / 邮箱----URL / 邮箱|URL / 邮箱｜URL"
        />
        <div class="field-footer">
          <span>只测试读取，不写入邮箱池，也不改变任务状态</span>
          <el-tag size="small" type="info">5 秒轮询 · 60 秒超时</el-tag>
        </div>
      </WorkspacePanel>

      <WorkspacePanel title="测试结果" :icon="Connection" fill body-padding="normal">
        <div v-if="!result && !loading" class="result-empty">
          <el-icon><Link /></el-icon>
          <span>等待测试</span>
        </div>
        <div v-else class="result-content">
          <div class="result-banner" :class="{ success: result?.ok }">
            <el-icon><CircleCheck /></el-icon>
            <div>
              <strong>{{ loading ? '正在轮询邮箱详情' : resultLabel }}</strong>
              <span v-if="result?.error">{{ result.error }}</span>
              <span v-else-if="loading">详情会轮转刷新，最长等待 60 秒</span>
              <span v-else>{{ result?.reason }}</span>
            </div>
          </div>
          <div v-if="result?.ok && result.verification_code" class="verification-code">
            <span>提取成功的验证码</span>
            <strong>{{ result.verification_code }}</strong>
          </div>
          <div class="result-metrics">
            <div><span>轮询次数</span><strong>{{ result?.attempts || 0 }}</strong></div>
            <div><span>耗时</span><strong>{{ Number(result?.elapsed_seconds || 0).toFixed(1) }}s</strong></div>
            <div><span>详情链接</span><strong>{{ diagnostics.detail_links }}</strong></div>
            <div><span>已刷新</span><strong>{{ diagnostics.detail_refreshed }}</strong></div>
            <div><span>验证码邮件</span><strong>{{ diagnostics.code_messages }}</strong></div>
            <div><span>详情错误</span><strong>{{ diagnostics.detail_errors }}</strong></div>
          </div>
          <div class="result-flags">
            <el-tag size="small" :type="result?.resend_attempted ? 'success' : 'info'">
              {{ result?.resend_attempted ? (result?.resend_succeeded ? '已执行一次重发' : '已尝试重发') : '未触发重发' }}
            </el-tag>
            <el-tag v-if="diagnostics.detail_refresh_pending" size="small" type="warning">
              待刷新详情 {{ diagnostics.detail_refresh_pending }} 条
            </el-tag>
          </div>
        </div>
      </WorkspacePanel>
    </div>
  </div>
</template>

<style scoped>
.url-test-page { width: 100%; height: 100%; min-width: 0; min-height: 0; }
.url-test-grid { display: grid; grid-template-columns: minmax(440px, .9fr) minmax(520px, 1.1fr); gap: 7px; height: 100%; min-height: 0; }
.url-test-grid :deep(.workspace-panel) { min-height: 0; }
.url-test-grid :deep(.workspace-panel.is-fill) { height: 100%; }
.field-footer { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 10px; color: #7b8798; font-size: 12px; }
.result-empty { display: grid; place-items: center; align-content: center; gap: 8px; height: 100%; min-height: 180px; color: #9aa6b7; font-size: 13px; }
.result-empty .el-icon { font-size: 28px; color: #a9c7eb; }
.result-content { display: flex; flex-direction: column; gap: 18px; height: 100%; min-height: 0; }
.result-banner { display: flex; align-items: flex-start; gap: 10px; padding: 12px; border: 1px solid #f3d7a2; border-radius: 5px; background: #fff9ed; color: #8b5a12; }
.result-banner.success { border-color: #b7e1c4; background: #f0fbf3; color: #237744; }
.result-banner > .el-icon { flex: 0 0 auto; margin-top: 1px; font-size: 20px; }
.result-banner div { display: flex; flex-direction: column; gap: 4px; min-width: 0; }
.result-banner strong { font-size: 14px; }
.result-banner span { color: inherit; font-size: 12px; word-break: break-word; }
.verification-code { display: flex; align-items: center; justify-content: space-between; gap: 16px; min-height: 70px; padding: 12px 16px; border: 1px solid #b7e1c4; border-radius: 5px; background: #f0fbf3; }
.verification-code span { color: #4d6c58; font-size: 12px; }
.verification-code strong { color: #1f7542; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 30px; line-height: 1; letter-spacing: 0; }
.result-metrics { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; }
.result-metrics div { display: flex; flex-direction: column; gap: 4px; padding: 10px; border: 1px solid var(--workspace-border); border-radius: 4px; background: #fbfdff; }
.result-metrics span { color: #78859a; font-size: 11px; }
.result-metrics strong { color: #263448; font-size: 17px; font-weight: 680; }
.result-flags { display: flex; flex-wrap: wrap; gap: 7px; }
</style>
