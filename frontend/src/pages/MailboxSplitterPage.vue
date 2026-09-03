<script setup lang="ts">
import { ElMessage, ElMessageBox } from 'element-plus'
import { CopyDocument, Delete, Download, Scissor } from '@element-plus/icons-vue'
import WorkspacePanel from '../components/WorkspacePanel.vue'
import { useMailboxSplitter } from '../composables/useMailboxSplitter'
import { mailboxSplitFilename } from '../utils/mailboxSplitter'

const { state, result, clear } = useMailboxSplitter()

async function copyText(value: string) {
  if (!value || !navigator.clipboard?.writeText) {
    ElMessage.error('当前环境不支持安全剪贴板写入')
    return
  }
  try {
    await navigator.clipboard.writeText(value)
    ElMessage.success('已复制')
  } catch {
    ElMessage.error('复制失败')
  }
}

function downloadText(value: string, filename: string) {
  if (!value) return
  const url = URL.createObjectURL(new Blob([value], { type: 'text/plain;charset=utf-8' }))
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

async function clearSource() {
  if (!state.source) return
  try {
    await ElMessageBox.confirm('清空后无法恢复当前页面内的原始数据和分割结果。', '清空原始数据', {
      type: 'warning',
      confirmButtonText: '确认清空',
      cancelButtonText: '取消',
    })
    clear()
  } catch {
    // Keep the current in-memory data when cancelled.
  }
}
</script>

<template>
  <div class="splitter-page">
    <WorkspacePanel class="source-panel" title="原始数据" :icon="Scissor" fill body-padding="none">
      <template #actions>
        <el-button :disabled="!state.source" @click="clearSource"><el-icon><Delete /></el-icon>清空</el-button>
      </template>
      <el-input
        v-model="state.source"
        class="source-input"
        type="textarea"
        resize="none"
        spellcheck="false"
        placeholder="粘贴邮箱数据，每个非空行视为一个账号"
      />
    </WorkspacePanel>

    <div class="split-controls">
      <label>切出数量</label>
      <el-input-number v-model="state.amount" :min="0" :step="1" step-strictly controls-position="right" />
      <div class="count-item"><span>原始</span><strong>{{ result.sourceCount }}</strong></div>
      <div class="count-item"><span>剩余</span><strong>{{ result.valid ? result.remainingCount : 0 }}</strong></div>
      <div class="count-item"><span>切出</span><strong>{{ result.valid ? result.splitCount : 0 }}</strong></div>
      <el-alert v-if="result.sourceCount && !result.valid" title="切出数量必须是 1 到原始总数之间的整数" type="warning" :closable="false" show-icon />
    </div>

    <div class="result-grid">
      <WorkspacePanel title="剩余数据" :icon="Scissor" fill body-padding="none">
        <template #actions>
          <el-button :disabled="!result.remainingText" @click="copyText(result.remainingText)"><el-icon><CopyDocument /></el-icon>复制</el-button>
          <el-button :disabled="!result.remainingText" @click="downloadText(result.remainingText, mailboxSplitFilename('remaining', result.remainingCount))"><el-icon><Download /></el-icon>下载 TXT</el-button>
        </template>
        <el-input :model-value="result.remainingText" class="result-input" type="textarea" resize="none" readonly spellcheck="false" />
      </WorkspacePanel>

      <WorkspacePanel title="分割数据" :icon="Scissor" fill body-padding="none">
        <template #actions>
          <el-button :disabled="!result.splitText" @click="copyText(result.splitText)"><el-icon><CopyDocument /></el-icon>复制</el-button>
          <el-button :disabled="!result.splitText" @click="downloadText(result.splitText, mailboxSplitFilename('split', result.splitCount))"><el-icon><Download /></el-icon>下载 TXT</el-button>
        </template>
        <el-input :model-value="result.splitText" class="result-input" type="textarea" resize="none" readonly spellcheck="false" />
      </WorkspacePanel>
    </div>
  </div>
</template>

<style scoped>
.splitter-page { display: grid; grid-template-rows: minmax(210px, 0.8fr) 54px minmax(260px, 1fr); gap: 6px; width: 100%; height: 100%; min-width: 0; min-height: 0; }
.source-panel { min-height: 0; }
.source-input,
.result-input { width: 100%; height: 100%; }
.source-input :deep(.el-textarea__inner),
.result-input :deep(.el-textarea__inner) { height: 100%; min-height: 100% !important; border: 0; border-radius: 0; box-shadow: none; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; line-height: 1.55; }
.result-input :deep(.el-textarea__inner) { background: #f8fafc; color: #334155; }
.split-controls { display: flex; align-items: center; gap: 10px; min-width: 0; padding: 7px 12px; border: 1px solid var(--workspace-border); background: #fff; }
.split-controls > label { color: #475569; font-size: 13px; font-weight: 650; white-space: nowrap; }
.split-controls .el-input-number { width: 130px; }
.count-item { display: flex; align-items: baseline; gap: 5px; min-width: 76px; padding-left: 10px; border-left: 1px solid var(--workspace-border); }
.count-item span { color: #8490a3; font-size: 12px; }
.count-item strong { color: #172033; font-size: 16px; }
.split-controls .el-alert { flex: 1; min-width: 0; padding: 5px 10px; }
.result-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 6px; min-width: 0; min-height: 0; }
</style>
