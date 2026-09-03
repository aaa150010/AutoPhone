<script setup lang="ts">
import { computed, onMounted, onUnmounted, provide, ref, watch } from 'vue'
import { ElMessageBox } from 'element-plus'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import { Document, Expand, Fold, Link, MessageBox, Monitor, Scissor, Setting, ShoppingCart, Tickets, Wallet } from '@element-plus/icons-vue'
import MailboxPage from '../pages/MailboxPage.vue'
import FreeMailboxPoolPage from '../pages/FreeMailboxPoolPage.vue'
import FreeRegistrationPage from '../pages/FreeRegistrationPage.vue'
import MailboxSplitterPage from '../pages/MailboxSplitterPage.vue'
import UrlMailboxTestPage from '../pages/UrlMailboxTestPage.vue'
import RunPage from '../pages/RunPage.vue'
import SettingsPage from '../pages/SettingsPage.vue'
import LogCenterPage from '../pages/LogCenterPage.vue'
import MailboxParserSamplesPage from '../pages/MailboxParserSamplesPage.vue'
import RemailPurchasePage from '../pages/RemailPurchasePage.vue'
import RemailOrdersPage from '../pages/RemailOrdersPage.vue'
import { appControllerKey, createAppController } from '../composables/useAppController'
import OpenAIConnectivityDiagnosticDialog from './OpenAIConnectivityDiagnosticDialog.vue'

const controller = createAppController()
provide(appControllerKey, controller)

const routes = new Set(['/', '/mailboxes', '/free-register', '/free-mailboxes', '/splitter', '/url-test', '/settings', '/logs', '/mailbox-parser-samples', '/remail/purchase', '/remail/orders'])
const pathFromLocation = () => `${routes.has(window.location.pathname) ? window.location.pathname : '/'}${window.location.search}${window.location.hash}`
const activePath = ref(routes.has(window.location.pathname) ? window.location.pathname : '/')
const currentLocation = ref(pathFromLocation())
const settingsAnchor = ref(new URLSearchParams(window.location.search).get('section') || window.location.hash.replace(/^#/, ''))
const sidebarCollapsed = ref(window.localStorage.getItem('gptphone.sidebar.collapsed') === '1')
const diagnosticDialog = ref<InstanceType<typeof OpenAIConnectivityDiagnosticDialog>>()

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
  const targetLocation = `${target}${parsed.search}${parsed.hash}`
  if (targetLocation === currentLocation.value) return
  if (!await confirmNavigation()) {
    if (fromHistory) history.pushState({}, '', currentLocation.value)
    return
  }
  activePath.value = target
  settingsAnchor.value = anchor
  currentLocation.value = targetLocation
  if (!fromHistory) history.pushState({}, '', targetLocation)
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

        <el-menu :default-active="activePath" :default-openeds="sidebarCollapsed ? [] : ['sms-workspace', 'free-workspace', 'remail-workspace', 'diagnostic-workspace', 'system-settings']" :collapse="sidebarCollapsed" :collapse-transition="false" @select="selectPage">
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
          <el-sub-menu index="remail-workspace">
            <template #title><el-icon><Wallet /></el-icon><span>Remail 管理</span></template>
            <el-menu-item index="/remail/purchase"><el-icon><ShoppingCart /></el-icon><span>Remail 购买</span></el-menu-item>
            <el-menu-item index="/remail/orders"><el-icon><Document /></el-icon><span>Remail 订单查询</span></el-menu-item>
          </el-sub-menu>
          <el-sub-menu index="diagnostic-workspace">
            <template #title><el-icon><Document /></el-icon><span>诊断与审计</span></template>
            <el-menu-item index="/logs"><el-icon><Document /></el-icon><span>日志中心</span></el-menu-item>
            <el-menu-item index="/mailbox-parser-samples"><el-icon><Document /></el-icon><span>邮箱解析样本</span></el-menu-item>
          </el-sub-menu>
          <el-sub-menu index="system-settings">
            <template #title><el-icon><Setting /></el-icon><span>系统设置</span></template>
            <el-menu-item index="/settings"><el-icon><Setting /></el-icon><span>运行配置</span></el-menu-item>
          </el-sub-menu>
        </el-menu>

      </el-aside>

      <el-main>
        <RunPage v-if="activePath === '/'" @navigate="navigate" />
        <MailboxPage v-else-if="activePath === '/mailboxes'" />
        <FreeRegistrationPage v-else-if="activePath === '/free-register'" @navigate="navigate" />
        <FreeMailboxPoolPage v-else-if="activePath === '/free-mailboxes'" />
        <MailboxSplitterPage v-else-if="activePath === '/splitter'" />
        <UrlMailboxTestPage v-else-if="activePath === '/url-test'" />
        <LogCenterPage v-else-if="activePath === '/logs'" :location-key="currentLocation" />
        <MailboxParserSamplesPage v-else-if="activePath === '/mailbox-parser-samples'" />
        <RemailPurchasePage v-else-if="activePath === '/remail/purchase'" />
        <RemailOrdersPage v-else-if="activePath === '/remail/orders'" />
        <SettingsPage v-else :initial-anchor="settingsAnchor" @navigate="navigate" />
      </el-main>
    </el-container>
    <OpenAIConnectivityDiagnosticDialog ref="diagnosticDialog" @open-settings="void navigate('/settings')" />
  </el-config-provider>
</template>

<style scoped>
.app-shell { width: 100%; min-width: 1280px; height: 100vh; overflow: hidden; background: var(--workspace-page); }
.app-sidebar { display: flex; flex-direction: column; height: 100%; overflow: hidden; border-right: 1px solid var(--workspace-border); background: #fff; transition: width 160ms ease; }
.brand-block { display: flex; align-items: center; gap: 9px; height: 62px; padding: 0 12px; border-bottom: 1px solid var(--workspace-border); }
.brand-mark { display: grid; place-items: center; flex: 0 0 32px; width: 32px; height: 32px; overflow: hidden; border-radius: 6px; background: #0f172a; }
.brand-mark img { display: block; width: 32px; height: 32px; }
.brand-copy { display: grid; min-width: 0; margin-right: auto; }
.brand-copy strong { color: #202938; font-size: 14px; line-height: 20px; font-weight: 720; white-space: nowrap; }
.brand-copy span { color: #8792a4; font-size: 10px; line-height: 14px; text-transform: uppercase; }
.sidebar-toggle { flex: 0 0 30px; width: 30px; height: 30px; padding: 0; color: #64748b; }
.sidebar-toggle:hover { color: var(--workspace-accent); background: var(--workspace-accent-soft); }
.el-menu { flex: 1; width: 100%; padding: 8px 6px; overflow-y: auto; border-right: 0; background: transparent; }
.el-menu :deep(.el-sub-menu__title) { height: 38px; padding: 0 10px !important; color: #687587; font-size: 12px; font-weight: 700; }
.el-menu :deep(.el-sub-menu .el-menu) { padding: 2px 0 5px 10px; overflow: visible; }
.el-menu :deep(.el-sub-menu .el-menu-item) { height: 36px; margin-bottom: 2px; font-size: 12px; }
.el-menu-item { width: calc(100% - 0px); height: 40px; margin-bottom: 3px; padding: 0 12px !important; justify-content: flex-start; border-radius: 7px; color: #687587; font-size: 13px; }
.el-menu-item .el-icon { font-size: 18px; }
.el-menu-item.is-active { background: var(--workspace-accent-soft); color: #dc5b18; font-weight: 700; }
.el-menu-item.is-active .el-icon { color: var(--workspace-accent); }
.app-sidebar.is-collapsed .brand-block { justify-content: center; padding: 0 8px; }
.app-sidebar.is-collapsed .brand-copy { display: none; }
.app-sidebar.is-collapsed .brand-mark { display: none; }
.app-sidebar.is-collapsed .sidebar-toggle { flex-basis: 32px; width: 32px; }
.app-sidebar.is-collapsed .el-menu { width: 54px; }
.app-sidebar.is-collapsed .el-menu-item { width: 42px; padding: 0 !important; justify-content: center; }
.app-sidebar.is-collapsed .el-menu :deep(.el-sub-menu__title) { width: 42px; padding: 0 !important; justify-content: center; }
.el-main { height: 100%; min-width: 0; padding: 10px 12px 12px; overflow: hidden; }
.shell-loading { display: grid; place-items: center; width: 100%; height: 100%; color: var(--el-color-primary); font-size: 22px; }
</style>
