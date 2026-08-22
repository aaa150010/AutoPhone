<script setup lang="ts">
import { computed, onMounted, onUnmounted, provide, ref, watch } from 'vue'
import { ElMessageBox } from 'element-plus'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import { Bell, Connection, Expand, Fold, Link, Loading, MessageBox, Monitor, Scissor, Setting, Tickets, Tools, Wallet } from '@element-plus/icons-vue'
import MailboxPage from '../pages/MailboxPage.vue'
import FreeMailboxPoolPage from '../pages/FreeMailboxPoolPage.vue'
import FreeRegistrationPage from '../pages/FreeRegistrationPage.vue'
import MailboxSplitterPage from '../pages/MailboxSplitterPage.vue'
import UrlMailboxTestPage from '../pages/UrlMailboxTestPage.vue'
import RunPage from '../pages/RunPage.vue'
import SettingsPage from '../pages/SettingsPage.vue'
import PaymentToolsPage from '../pages/PaymentToolsPage.vue'
import NetworkToolsPage from '../pages/NetworkToolsPage.vue'
import { appControllerKey, createAppController } from '../composables/useAppController'
import { buildOpenAIConnectivityView } from '../utils/openAIConnectivity'
import ReleaseNotesDialog from './ReleaseNotesDialog.vue'
import OpenAIConnectivityDiagnosticDialog from './OpenAIConnectivityDiagnosticDialog.vue'

const controller = createAppController()
provide(appControllerKey, controller)

const routes = new Set(['/', '/mailboxes', '/free-register', '/free-mailboxes', '/splitter', '/url-test', '/settings', '/payment-tools', '/network-tools'])
const pathFromLocation = () => `${routes.has(window.location.pathname) ? window.location.pathname : '/'}${window.location.search}${window.location.hash}`
const activePath = ref(routes.has(window.location.pathname) ? window.location.pathname : '/')
const settingsAnchor = ref(new URLSearchParams(window.location.search).get('section') || window.location.hash.replace(/^#/, ''))
const sidebarCollapsed = ref(window.localStorage.getItem('gptphone.sidebar.collapsed') === '1')
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
  const parsed = new URL(path, window.location.origin)
  const target = routes.has(parsed.pathname) ? parsed.pathname : '/'
  const anchor = parsed.searchParams.get('section') || parsed.hash.replace(/^#/, '')
  if (target === activePath.value && anchor === settingsAnchor.value) return
  if (!await confirmNavigation()) {
    if (fromHistory) history.pushState({}, '', activePath.value)
    return
  }
  activePath.value = target
  settingsAnchor.value = anchor
  if (!fromHistory) history.pushState({}, '', anchor && target === '/settings' ? `${target}#${encodeURIComponent(anchor)}` : target)
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

function toggleSidebar() {
  sidebarCollapsed.value = !sidebarCollapsed.value
  window.localStorage.setItem('gptphone.sidebar.collapsed', sidebarCollapsed.value ? '1' : '0')
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
      <el-aside :width="sidebarCollapsed ? '54px' : '188px'" class="app-sidebar" :class="{ 'is-collapsed': sidebarCollapsed }">
        <div class="brand-block">
          <div class="brand-mark"><img src="/assets/gpt-register-center-v1633.svg" alt="" /></div>
          <div class="brand-copy"><strong>GPT 注册中心</strong><span>FREE + SMS</span></div>
          <el-tooltip :content="sidebarCollapsed ? '展开菜单' : '收缩菜单'" placement="right"><el-button class="sidebar-toggle" link :icon="sidebarCollapsed ? Expand : Fold" aria-label="收缩或展开左侧菜单" @click="toggleSidebar" /></el-tooltip>
        </div>

        <el-menu :default-active="activePath" :default-openeds="sidebarCollapsed ? [] : ['sms-workspace', 'free-workspace', 'tool-workspace', 'system-settings']" :collapse="sidebarCollapsed" :collapse-transition="false" @select="selectPage">
          <el-sub-menu index="sms-workspace">
            <template #title><el-icon><MessageBox /></el-icon><span>接码工作台</span></template>
            <el-menu-item index="/"><el-icon><Monitor /></el-icon><span>接码运行中心</span></el-menu-item>
            <el-menu-item index="/mailboxes"><el-icon><Tickets /></el-icon><span>接码邮箱管理</span></el-menu-item>
            <el-menu-item index="/splitter"><el-icon><Scissor /></el-icon><span>邮箱拆分工具</span></el-menu-item>
            <el-menu-item index="/url-test"><el-icon><Link /></el-icon><span>邮箱 URL 测试</span></el-menu-item>
          </el-sub-menu>
          <el-sub-menu index="free-workspace">
            <template #title><el-icon><Setting /></el-icon><span>Free 注册</span></template>
            <el-menu-item index="/free-register"><el-icon><Monitor /></el-icon><span>Free 注册运行</span></el-menu-item>
            <el-menu-item index="/free-mailboxes"><el-icon><Tickets /></el-icon><span>Free 邮箱管理</span></el-menu-item>
          </el-sub-menu>
          <el-sub-menu index="tool-workspace">
            <template #title><el-icon><Tools /></el-icon><span>支付与网络工具</span></template>
            <el-menu-item index="/payment-tools"><el-icon><Wallet /></el-icon><span>支付链接工作台</span></el-menu-item>
            <el-menu-item index="/network-tools"><el-icon><Connection /></el-icon><span>代理与网络工具</span></el-menu-item>
          </el-sub-menu>
          <el-sub-menu index="system-settings">
            <template #title><el-icon><Setting /></el-icon><span>系统设置</span></template>
            <el-menu-item index="/settings"><el-icon><Setting /></el-icon><span>运行配置</span></el-menu-item>
          </el-sub-menu>
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
        <PaymentToolsPage v-else-if="activePath === '/payment-tools'" />
        <NetworkToolsPage v-else-if="activePath === '/network-tools'" />
        <SettingsPage v-else :initial-anchor="settingsAnchor" @navigate="navigate" />
      </el-main>
    </el-container>
    <ReleaseNotesDialog />
    <OpenAIConnectivityDiagnosticDialog ref="diagnosticDialog" @open-settings="void navigate('/settings')" />
  </el-config-provider>
</template>

<style scoped>
.app-shell { width: 100%; min-width: 1280px; height: 100vh; overflow: hidden; background: var(--workspace-page); }
.app-sidebar { display: flex; flex-direction: column; height: 100%; overflow: hidden; border-right: 1px solid #d8e1eb; background: #f8fafc; transition: width 160ms ease; }
.brand-block { display: flex; align-items: center; gap: 9px; height: 58px; padding: 0 10px; border-bottom: 1px solid #d8e1eb; }
.brand-mark { display: grid; place-items: center; flex: 0 0 32px; width: 32px; height: 32px; overflow: hidden; border-radius: 6px; background: #0f172a; }
.brand-mark img { display: block; width: 32px; height: 32px; }
.brand-copy { display: grid; min-width: 0; margin-right: auto; }
.brand-copy strong { color: #172033; font-size: 14px; line-height: 20px; font-weight: 720; white-space: nowrap; }
.brand-copy span { color: #8792a4; font-size: 10px; line-height: 14px; text-transform: uppercase; }
.sidebar-toggle { flex: 0 0 30px; width: 30px; height: 30px; padding: 0; color: #64748b; }
.sidebar-toggle:hover { color: #315f99; background: #e7eef8; }
.el-menu { flex: 1; width: 100%; padding: 8px 6px; overflow-y: auto; border-right: 0; background: transparent; }
.el-menu :deep(.el-sub-menu__title) { height: 38px; padding: 0 10px !important; color: #44556d; font-size: 12px; font-weight: 700; }
.el-menu :deep(.el-sub-menu .el-menu) { padding: 2px 0 5px 10px; overflow: visible; }
.el-menu :deep(.el-sub-menu .el-menu-item) { height: 36px; margin-bottom: 2px; font-size: 12px; }
.el-menu-item { width: calc(100% - 0px); height: 42px; margin-bottom: 4px; padding: 0 12px !important; justify-content: flex-start; border-radius: 5px; color: #64748b; font-size: 13px; }
.el-menu-item .el-icon { font-size: 18px; }
.el-menu-item.is-active { background: #e7eef8; color: #315f99; font-weight: 650; }
.global-status { display: flex; flex-direction: column; align-items: flex-start; gap: 7px; margin: 8px 10px; padding: 10px 0; border-top: 1px solid #d8e1eb; }
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
.app-sidebar.is-collapsed .brand-block { justify-content: center; padding: 0 8px; }
.app-sidebar.is-collapsed .brand-copy { display: none; }
.app-sidebar.is-collapsed .brand-mark { display: none; }
.app-sidebar.is-collapsed .sidebar-toggle { flex-basis: 32px; width: 32px; }
.app-sidebar.is-collapsed .el-menu { width: 54px; }
.app-sidebar.is-collapsed .el-menu-item { width: 42px; padding: 0 !important; justify-content: center; }
.app-sidebar.is-collapsed .el-menu :deep(.el-sub-menu__title) { width: 42px; padding: 0 !important; justify-content: center; }
.app-sidebar.is-collapsed .global-status { align-items: center; margin: 8px 6px; }
.el-main { height: 100%; min-width: 0; padding: 5px; overflow: hidden; }
.shell-loading { display: grid; place-items: center; width: 100%; height: 100%; color: var(--el-color-primary); font-size: 22px; }
</style>
