<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Operation, Setting } from '@element-plus/icons-vue'
import PageToolbar from '../components/PageToolbar.vue'
import RunOperationBar from '../components/RunOperationBar.vue'
import RunStartDialog from '../components/RunStartDialog.vue'
import SettingsForm from '../components/SettingsForm.vue'
import WorkspacePanel from '../components/WorkspacePanel.vue'
import { useAppController } from '../composables/useAppController'

const emit = defineEmits<{ navigate: [string] }>()
const props = defineProps<{ initialAnchor?: string }>()
const controller = useAppController()
const startDialog = ref<InstanceType<typeof RunStartDialog>>()
const settingsForm = ref<InstanceType<typeof SettingsForm>>()
const freeDirty = ref(false)
const savingAll = ref(false)
const dirty = computed(() => controller.dirty.value || freeDirty.value)

const statusLabel = computed(() => controller.running.value
  ? controller.runtime.value.stop_requested ? '正在停止' : '运行中'
  : '空闲')
const statusTone = computed(() => controller.running.value ? 'success' : 'info')
function messageFor(error: any) {
  return error?.message || String(error || '操作失败')
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

async function importConfig(config: any) {
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
    <PageToolbar title="运行配置" :status="statusLabel" :tone="statusTone">
      <el-tag v-if="dirty" type="warning" effect="light">有未保存修改</el-tag>
    </PageToolbar>

    <div class="settings-grid">
      <WorkspacePanel title="配置参数" :icon="Setting" fill body-padding="none">
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
        />
      </WorkspacePanel>

      <WorkspacePanel title="运行操作" :icon="Operation" body-padding="compact">
        <div class="run-snapshot">
          <div><span>邮箱可用</span><strong>{{ Number(controller.runtime.value.pool?.available || 0) }}</strong></div>
          <div><span>运行任务</span><strong>{{ controller.runtime.value.summary?.active || 0 }}</strong></div>
          <div><span>配置状态</span><strong :class="{ dirty }">{{ dirty ? '待保存' : '已保存' }}</strong></div>
        </div>
        <RunOperationBar
          :running="controller.running.value"
          :has-pool="controller.hasPool.value"
          :saving="savingAll || controller.actions.saving"
          :preflighting="controller.actions.preflighting"
          :starting="controller.actions.starting"
          :stopping="controller.actions.stopping"
          :importing="controller.actions.importing"
          :exporting="controller.actions.exporting"
          @import-config="importConfig"
          @export-config="exportConfig"
          @save="save"
          @preflight="preflight"
          @start="openStartDialog"
          @stop="stop"
        />
      </WorkspacePanel>
    </div>
    <RunStartDialog
      ref="startDialog"
      :loading="controller.actions.starting"
      @confirm="start"
    />
  </div>
</template>

<style scoped>
.settings-page { display: grid; grid-template-rows: 44px minmax(0, 1fr); gap: 6px; width: 100%; height: 100%; min-width: 0; min-height: 0; }
.settings-grid { display: grid; grid-template-columns: minmax(720px, 1fr) 380px; gap: 8px; min-width: 0; min-height: 0; }
.run-snapshot { display: grid; gap: 1px; margin-bottom: 10px; border: 1px solid var(--workspace-border); border-radius: var(--workspace-radius); overflow: hidden; }
.run-snapshot > div { display: grid; grid-template-columns: 80px minmax(0, 1fr); align-items: center; column-gap: 16px; min-height: 36px; padding: 0 12px; background: #f8fafc; }
.run-snapshot span { color: var(--el-text-color-secondary); font-size: 13px; }
.run-snapshot strong { justify-self: start; font-size: 13px; font-variant-numeric: tabular-nums; }
.run-snapshot strong.dirty { color: var(--el-color-warning); }
</style>
