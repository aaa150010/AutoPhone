<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Coin, Document, Operation, Promotion, Setting, Upload, VideoPause, VideoPlay } from '@element-plus/icons-vue'
import RunStartDialog from '../components/RunStartDialog.vue'
import SettingsForm from '../components/SettingsForm.vue'
import WorkspacePanel from '../components/WorkspacePanel.vue'
import { useAppController } from '../composables/useAppController'
import { getState, getLocalConfig } from '../api/client'
import {
  mergeConfig,
  normalizeEmailNotificationDraft,
  normalizeOperationalSettings,
} from '../utils/appConfigNormalize'
import { syncLegacySmsFields } from '../utils/smsPools'
import { errorMessage } from '../utils/errorMessage'
import { formatDateTimeZh } from '../utils/datetime'

const emit = defineEmits<{ navigate: [string] }>()
const props = defineProps<{ initialAnchor?: string }>()
const controller = useAppController()
const startDialog = ref<InstanceType<typeof RunStartDialog>>()
const settingsForm = ref<InstanceType<typeof SettingsForm>>()
const configFileInput = ref<HTMLInputElement>()
const freeDirty = ref(false)
const savingAll = ref(false)
const discarding = ref(false)
const dirty = computed(() => controller.dirty.value || freeDirty.value)
const lastRunAt = computed(() => {
  const summary = controller.runtime.value.summary || {}
  const stamp = summary.finished_at || summary.last_activity_at || summary.started_at
  return Number(stamp) > 0 ? formatDateTimeZh(Number(stamp) * 1000) : '—'
})

function messageFor(error: unknown) {
  return errorMessage(error) || '操作失败'
}

function openImport() {
  configFileInput.value?.click()
}

async function importFile(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  try {
    await importConfig(JSON.parse(await file.text()))
  } catch (error) {
    ElMessage.error(errorMessage(error) || '配置文件不是有效 JSON')
  } finally {
    input.value = ''
  }
}

async function save() {
  savingAll.value = true
  try {
    await Promise.all([
      controller.save(),
      settingsForm.value?.saveFreeConfig(),
    ])
    ElMessage.success('配置已保存')
  } catch (error) {
    ElMessage.error(messageFor(error))
  } finally {
    savingAll.value = false
  }
}

/** Reload the persisted config from the server and overwrite the draft. */
async function discardChanges() {
  try {
    await ElMessageBox.confirm('将放弃当前未保存的修改，恢复为已保存的配置。', '取消修改', {
      type: 'warning',
      confirmButtonText: '放弃修改',
      cancelButtonText: '继续编辑',
    })
  } catch {
    return
  }
  discarding.value = true
  try {
    const [stateResult, localResult] = await Promise.all([getState(), getLocalConfig()])
    const merged = mergeConfig(controller.form, stateResult.state?.settings || {}, localResult.config || {})
    normalizeOperationalSettings(merged)
    syncLegacySmsFields(merged)
    merged.email_notification = normalizeEmailNotificationDraft(merged.email_notification)
    controller.updateForm(merged)
    ElMessage.success('已恢复为已保存的配置')
  } catch (error) {
    ElMessage.error(messageFor(error))
  } finally {
    discarding.value = false
  }
}

async function preflight() {
  try {
    await controller.preflight()
    ElMessage.success('真实链路预检通过')
  } catch (error) {
    ElMessage.error(messageFor(error))
  }
}

function openStartDialog() {
  startDialog.value?.open()
}

async function start(selection: { runMode: 'register' }) {
  try {
    const result = await controller.start(true, selection.runMode)
    if (!result) return
    ElMessage.success('任务已启动')
    emit('navigate', '/')
  } catch (error) {
    ElMessage.error(messageFor(error))
  }
}

async function stop() {
  try {
    await controller.stop()
    ElMessage.success('已发送停止请求')
  } catch (error) {
    ElMessage.error(messageFor(error))
  }
}

async function importConfig(config: unknown) {
  try {
    await controller.importConfig(config)
    ElMessage.success('配置已导入并应用')
  } catch (error) {
    ElMessage.error(messageFor(error))
  }
}

async function exportConfig() {
  try {
    await ElMessageBox.confirm(
      '导出文件包含 SMS Key、SMTP 授权码及其他可迁移密钥，请仅保存在可信设备。',
      '导出敏感配置',
      { type: 'warning', confirmButtonText: '确认导出', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  try {
    const result = await controller.exportConfig()
    const blob = new Blob([JSON.stringify(result.config || {}, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'gptphone-config.json'
    link.click()
    URL.revokeObjectURL(url)
    ElMessage.success('配置已导出')
  } catch (error) {
    ElMessage.error(messageFor(error))
  }
}

async function testNotification() {
  try {
    await controller.sendTestNotification()
    ElMessage.success('测试通知已发送')
  } catch (error) {
    ElMessage.error(messageFor(error))
  }
}

async function querySmsBalances() {
  try {
    const result = await controller.queryBalances()
    const statuses = result.sms_key_statuses || []
    const unavailable = statuses.filter(status => status.status !== 'usable').length
    if (unavailable) {
      ElMessage.warning(`余额查询完成：${statuses.length - unavailable} 个可用，${unavailable} 个异常`)
    } else {
      ElMessage.success(`余额查询完成，共 ${statuses.length} 个 Key`)
    }
  } catch (error) {
    ElMessage.error(messageFor(error))
  }
}

onMounted(async () => {
  try {
    await controller.ensureSecretsLoaded()
  } catch (error) {
    ElMessage.error(messageFor(error))
  }
})
</script>

<template>
  <div class="settings-page">
    <input ref="configFileInput" class="config-file-input" type="file" accept="application/json,.json" @change="importFile" />
    <header class="settings-topbar">
      <div class="topbar-heading">
        <el-breadcrumb separator="/" class="topbar-breadcrumb">
          <el-breadcrumb-item>系统设置</el-breadcrumb-item>
          <el-breadcrumb-item>运行配置</el-breadcrumb-item>
        </el-breadcrumb>
        <div class="topbar-title-row">
          <h1 class="topbar-title">接码机运行配置</h1>
          <el-tag v-if="dirty" type="warning" effect="light" size="small">有未保存更改</el-tag>
          <el-tag v-else type="success" effect="plain" size="small">已保存</el-tag>
        </div>
        <p class="topbar-hint">修改后点击右上角"保存配置"；基础、代理、并发与保护策略均在此维护。</p>
      </div>
      <div class="topbar-actions">
        <el-button size="small" :icon="Upload" :loading="controller.actions.importing" @click="openImport">导入配置</el-button>
        <el-button size="small" :icon="Document" :loading="controller.actions.exporting" @click="exportConfig">导出配置</el-button>
        <el-button v-if="dirty" size="small" :loading="discarding" @click="discardChanges">取消修改</el-button>
        <el-button size="small" type="primary" :icon="Setting" :loading="savingAll || controller.actions.saving" @click="save">保存配置</el-button>
      </div>
    </header>

    <div v-if="dirty" class="dirty-banner" role="status">
      <span>配置已修改但尚未保存，离开页面前请保存或取消修改。</span>
      <el-button size="small" text type="primary" :loading="discarding" @click="discardChanges">恢复已保存配置</el-button>
    </div>

    <div class="settings-grid">
      <WorkspacePanel title="配置参数" :icon="Setting" fill body-padding="none" class="settings-panel">
        <SettingsForm
          ref="settingsForm"
          :initial-anchor="props.initialAnchor"
          :model-value="controller.form"
          :sms-key-statuses="controller.smsKeyStatuses.value"
          :querying-sms-balances="controller.actions.queryingSmsBalances"
          :testing-notification="controller.actions.testingNotification"
          :notification-status="controller.runtime.value.notification"
          @update:model-value="controller.updateForm"
          @test-notification="testNotification"
          @query-sms-balances="querySmsBalances"
          @free-dirty-change="freeDirty = $event"
          @navigate="emit('navigate', $event)"
        />
      </WorkspacePanel>

      <div class="status-rail">
        <WorkspacePanel title="运行状态" :icon="Operation" body-padding="compact" class="status-card">
          <div class="run-snapshot">
            <div><span>邮箱可用</span><strong>{{ Number(controller.runtime.value.pool?.available || 0) }}</strong><small>个</small></div>
            <div><span>运行任务</span><strong>{{ Number(controller.runtime.value.summary?.active || 0) }}</strong><small>个</small></div>
            <div><span>最近运行</span><strong class="run-time">{{ lastRunAt }}</strong><small v-if="controller.running.value" class="running-mark">运行中</small></div>
          </div>
          <div class="primary-actions">
            <el-tooltip v-if="controller.dirty.value" content="存在未保存配置，保存后才能开始运行" placement="top" :show-after="250">
              <span><el-button size="small" type="primary" :icon="VideoPlay" disabled>开始运行</el-button></span>
            </el-tooltip>
            <el-button v-else size="small" type="primary" :icon="VideoPlay" :loading="controller.actions.starting" :disabled="controller.running.value || !controller.hasPool.value" @click="openStartDialog">开始运行</el-button>
            <el-button size="small" type="danger" plain :icon="VideoPause" :loading="controller.actions.stopping" :disabled="!controller.running.value" @click="stop">停止</el-button>
          </div>
          <p v-if="controller.dirty.value" class="primary-hint">存在未保存配置，保存后才能开始运行。</p>
        </WorkspacePanel>

        <WorkspacePanel title="诊断操作" :icon="Coin" body-padding="compact" class="status-card">
          <div class="diagnostic-actions">
            <el-button size="small" :icon="Promotion" :loading="controller.actions.preflighting" @click="preflight">真实链路预检</el-button>
            <el-button size="small" :icon="Coin" :loading="controller.actions.queryingSmsBalances" @click="querySmsBalances">查询 SMS 余额</el-button>
            <el-button size="small" :loading="controller.actions.testingNotification" @click="testNotification">发送测试通知</el-button>
          </div>
        </WorkspacePanel>
      </div>
    </div>
    <RunStartDialog
      ref="startDialog"
      :loading="controller.actions.starting"
      @confirm="start"
    />
  </div>
</template>

<style scoped>
.settings-page { position: relative; display: grid; grid-template-rows: auto auto minmax(0, 1fr); gap: var(--workspace-gap); width: 100%; height: 100%; min-width: 0; min-height: 0; }
.config-file-input { display: none; }
.settings-topbar {
  position: sticky;
  top: 0;
  z-index: 5;
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  padding: 10px 14px;
  border: 1px solid var(--workspace-border);
  border-radius: var(--workspace-radius);
  background: var(--workspace-surface);
  box-shadow: var(--workspace-shadow);
}
.topbar-heading { min-width: 0; }
.topbar-breadcrumb :deep(.el-breadcrumb__inner) { font-size: 11px; }
.topbar-title-row { display: flex; align-items: center; gap: 8px; margin-top: 2px; }
.topbar-title { margin: 0; color: var(--el-text-color-primary); font-size: 16px; line-height: 22px; font-weight: 720; }
.topbar-hint { margin: 2px 0 0; color: var(--el-text-color-secondary); font-size: 12px; line-height: 17px; }
.topbar-actions { display: flex; flex: 0 0 auto; align-items: center; gap: 2px; padding-top: 4px; }
.dirty-banner { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 7px 14px; border: 1px solid var(--el-color-warning-light-5); border-radius: var(--workspace-radius); background: var(--tone-warning-bg); color: var(--tone-warning-text); font-size: 12px; }
.settings-grid { display: grid; grid-template-columns: minmax(640px, 1fr) 300px; gap: var(--workspace-gap); min-height: 0; }
.settings-panel { min-height: 0; }
.status-rail { display: grid; grid-template-rows: auto auto; gap: var(--workspace-gap); align-content: start; min-width: 0; }
.status-card { position: sticky; top: calc(10px + 76px); }
.run-snapshot { display: grid; gap: 1px; margin-bottom: 10px; border: 1px solid var(--workspace-border); border-radius: var(--workspace-radius); overflow: hidden; }
.run-snapshot > div { display: flex; align-items: baseline; column-gap: 10px; min-height: 34px; padding: 4px 12px; background: var(--workspace-subtle); }
.run-snapshot span { min-width: 56px; color: var(--el-text-color-secondary); font-size: 12px; }
.run-snapshot strong { color: var(--el-text-color-primary); font-size: 15px; font-variant-numeric: tabular-nums; }
.run-snapshot strong.run-time { font-size: 12px; font-weight: 600; }
.run-snapshot small { color: var(--el-text-color-secondary); font-size: 11px; }
.run-snapshot small.running-mark { color: var(--el-color-success); font-weight: 650; }
.primary-actions { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
.primary-actions :deep(.el-button) { margin-left: 0; }
.primary-hint { margin: 8px 0 0; color: var(--el-color-warning); font-size: 11px; line-height: 16px; }
.diagnostic-actions { display: grid; gap: 8px; }
.diagnostic-actions :deep(.el-button) { margin-left: 0; justify-content: flex-start; }
</style>
