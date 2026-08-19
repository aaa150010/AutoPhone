<script setup lang="ts">
import { computed, onMounted, onUnmounted, provide, ref, watch } from 'vue'
import { ElMessageBox } from 'element-plus'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import MailboxPage from '../pages/MailboxPage.vue'
import FreeMailboxPoolPage from '../pages/FreeMailboxPoolPage.vue'
import FreeRegistrationPage from '../pages/FreeRegistrationPage.vue'
import MailboxSplitterPage from '../pages/MailboxSplitterPage.vue'
import UrlMailboxTestPage from '../pages/UrlMailboxTestPage.vue'
import RunPage from '../pages/RunPage.vue'
import SettingsPage from '../pages/SettingsPage.vue'
import { appControllerKey, createAppController } from '../composables/useAppController'
import { buildOpenAIConnectivityView } from '../utils/openAIConnectivity'
import ReleaseNotesDialog from './ReleaseNotesDialog.vue'
import OpenAIConnectivityDiagnosticDialog from './OpenAIConnectivityDiagnosticDialog.vue'

const controller = createAppController()
provide(appControllerKey, controller)

const routes = new Set(['/', '/mailboxes', '/free-register', '/free-mailboxes', '/splitter', '/url-test', '/settings'])
const pathFromLocation = () => routes.has(window.location.pathname) ? window.location.pathname : '/'
const activePath = ref(pathFromLocation())
const diagnosticDialog = ref<InstanceType<typeof OpenAIConnectivityDiagnosticDialog>>()

const runStatus = computed(() => {
  const runtime = controller.runtime.value
  if (runtime.stop_requested) return runtime.running ? '正在停止' : '已停止'
  if (runtime.sms_safe_stop) return '异常停止'
  return runtime.running ? '运行中' : '空闲'
})
const statusClass = computed(() => controller.runtime.value.sms_safe_stop
  ? 'danger'
  : controller.runtime.value.stop_requested
    ? 'warning'
    : controller.running.value ? 'success' : 'idle')
const connectivityStatus = computed(() => buildOpenAIConnectivityView(controller.runtime.value))
async function confirmNavigation() {
  if (!controller.dirty.value) return true
  try {
    await ElMessageBox.confirm('运行配置尚未保存，离开后草稿仍会保留。', '未保存配置', {
      type: 'warning',
      confirmButtonText: '继续离开',
      cancelButtonText: '留在配置页',
    })
    return true
  } catch {
    return false
  }
}

async function navigate(path: string, fromHistory = false) {
  const target = routes.has(path) ? path : '/'
  if (target === activePath.value) return
  if (!await confirmNavigation()) {
    if (fromHistory) history.pushState({}, '', activePath.value)
    return
  }
  activePath.value = target
  if (!fromHistory) history.pushState({}, '', target)
}

function selectPage(path: string) {
  void navigate(path)
}

function handlePopState() {
  void navigate(pathFromLocation(), true)
}

function handleBeforeUnload(event: BeforeUnloadEvent) {
  if (!controller.dirty.value) return
  event.preventDefault()
  event.returnValue = ''
}

function openConnectivityDiagnostics(reason = '手动检查当前 OpenAI 授权链路') {
  controller.openConnectivityDiagnostics(reason)
}

watch(
  () => controller.connectivityDiagnosticRequest.value,
  (request) => {
    if (!request) return
    diagnosticDialog.value?.open(request.reason)
    controller.clearConnectivityDiagnosticRequest()
  },
)

onMounted(() => {
  void controller.startPolling()
  window.addEventListener('popstate', handlePopState)
  window.addEventListener('beforeunload', handleBeforeUnload)
})

onUnmounted(() => {
  controller.stopPolling()
  window.removeEventListener('popstate', handlePopState)
  window.removeEventListener('beforeunload', handleBeforeUnload)
})
</script>

<template>
  <el-config-provider :locale="zhCn">
    <el-container class="app-shell">
      <el-aside width="58px" class="app-sidebar">
        <div class="brand-block">
          <div class="brand-mark"><el-icon><Cpu /></el-icon></div>
          <div class="brand-copy"><strong>自动接码机</strong><span>GPT Phone</span></div>
        </div>

        <el-menu :default-active="activePath" :collapse="true" :collapse-transition="false" @select="selectPage">
          <el-tooltip content="运行中心" placement="right"><el-menu-item index="/"><el-icon><Monitor /></el-icon><span>运行中心</span></el-menu-item></el-tooltip>
          <el-tooltip content="邮箱管理" placement="right"><el-menu-item index="/mailboxes"><el-icon><MessageBox /></el-icon><span>邮箱管理</span></el-menu-item></el-tooltip>
          <el-tooltip content="Free 注册中心" placement="right"><el-menu-item index="/free-register"><el-icon><Setting /></el-icon><span>Free 注册中心</span></el-menu-item></el-tooltip>
          <el-tooltip content="Free 邮箱管理" placement="right"><el-menu-item index="/free-mailboxes"><el-icon><Tickets /></el-icon><span>Free 邮箱管理</span></el-menu-item></el-tooltip>
          <el-tooltip content="邮箱分割" placement="right"><el-menu-item index="/splitter"><el-icon><Scissor /></el-icon><span>邮箱分割</span></el-menu-item></el-tooltip>
          <el-tooltip content="URL测试" placement="right"><el-menu-item index="/url-test"><el-icon><Link /></el-icon><span>URL测试</span></el-menu-item></el-tooltip>
          <el-tooltip content="运行配置" placement="right"><el-menu-item index="/settings"><el-icon><Setting /></el-icon><span>运行配置</span></el-menu-item></el-tooltip>
        </el-menu>

        <div class="global-status">
          <el-tooltip :content="`运行状态：${runStatus}`" placement="right"><button class="status-button" :class="statusClass" type="button" aria-label="运行状态"><span class="status-dot" /></button></el-tooltip>
          <el-tooltip :content="`${connectivityStatus.sidebarLabel}：${connectivityStatus.sidebarDetail}`" placement="right"><button class="status-button connectivity-button" :class="`is-${connectivityStatus.tone}`" type="button" aria-label="OpenAI 链路诊断" @click="openConnectivityDiagnostics()"><el-icon><Connection /></el-icon></button></el-tooltip>
          <el-tooltip v-if="controller.runtime.value.notification?.status" :content="controller.runtime.value.notification.status === 'sent' ? '通知已发送' : controller.runtime.value.notification.status === 'failed' ? '通知发送失败' : '通知等待发送'" placement="right"><button class="status-button notification-button" type="button" aria-label="通知状态"><el-icon><Bell /></el-icon></button></el-tooltip>
        </div>
      </el-aside>

      <el-main>
        <div v-if="!controller.initialized.value" class="shell-loading"><el-icon class="is-loading"><Loading /></el-icon></div>
        <RunPage v-else-if="activePath === '/'" @navigate="navigate" />
        <MailboxPage v-else-if="activePath === '/mailboxes'" />
        <FreeRegistrationPage v-else-if="activePath === '/free-register'" @navigate="navigate" />
        <FreeMailboxPoolPage v-else-if="activePath === '/free-mailboxes'" />
        <MailboxSplitterPage v-else-if="activePath === '/splitter'" />
        <UrlMailboxTestPage v-else-if="activePath === '/url-test'" />
        <SettingsPage v-else @navigate="navigate" />
      </el-main>
    </el-container>
    <ReleaseNotesDialog />
    <OpenAIConnectivityDiagnosticDialog ref="diagnosticDialog" @open-settings="void navigate('/settings')" />
  </el-config-provider>
</template>

<style scoped>
.app-shell { width: 100%; min-width: 1280px; height: 100vh; overflow: hidden; background: var(--workspace-page); }
.app-sidebar { display: flex; flex-direction: column; height: 100%; overflow: hidden; border-right: 1px solid #d8e1eb; background: #f8fafc; }
.brand-block { display: grid; place-items: center; height: 58px; padding: 0 8px; border-bottom: 1px solid #d8e1eb; }
.brand-mark { display: grid; place-items: center; flex: 0 0 32px; width: 32px; height: 32px; border-radius: 6px; background: #2563eb; color: #fff; font-size: 18px; }
.brand-copy { display: none; }
.brand-copy strong { color: #172033; font-size: 14px; line-height: 20px; font-weight: 720; white-space: nowrap; }
.brand-copy span { color: #8792a4; font-size: 10px; line-height: 14px; text-transform: uppercase; }
.el-menu { flex: 1; width: 58px; padding: 8px 6px; border-right: 0; background: transparent; }
.el-menu-item { width: 46px; height: 42px; margin-bottom: 4px; padding: 0 !important; justify-content: center; border-radius: 5px; color: #64748b; font-size: 13px; }
.el-menu-item .el-icon { font-size: 18px; }
.el-menu-item.is-active { background: #e7eef8; color: #315f99; font-weight: 650; }
.global-status { display: flex; flex-direction: column; align-items: center; gap: 7px; margin: 8px 6px; padding: 10px 0; border-top: 1px solid #d8e1eb; }
.status-button { display: grid; place-items: center; width: 32px; height: 32px; padding: 0; border: 0; border-radius: 5px; background: transparent; color: #64748b; cursor: pointer; }
.status-button:hover { background: #e7eef8; color: #315f99; }
.connectivity-button .el-icon, .notification-button .el-icon { font-size: 17px; }
.connectivity-button.is-success { color: #168363; }
.connectivity-button.is-warning { color: #bc761c; }
.connectivity-button.is-danger { color: #c44754; }
.status-dot { width: 7px; height: 7px; border-radius: 50%; background: #94a3b8; }
.status-button.success .status-dot { background: #16a34a; box-shadow: 0 0 0 3px #dcfce7; }
.status-button.warning .status-dot { background: #d97706; box-shadow: 0 0 0 3px #fef3c7; }
.status-button.danger .status-dot { background: #dc2626; box-shadow: 0 0 0 3px #fee2e2; }
.el-main { height: 100%; min-width: 0; padding: 5px; overflow: hidden; }
.shell-loading { display: grid; place-items: center; width: 100%; height: 100%; color: var(--el-color-primary); font-size: 22px; }
</style>
