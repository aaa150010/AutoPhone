<script setup lang="ts">
import { computed, onMounted, onUnmounted, provide, ref } from 'vue'
import { ElMessageBox } from 'element-plus'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import AccountManagementPage from '../pages/AccountManagementPage.vue'
import MailboxPage from '../pages/MailboxPage.vue'
import MailboxSplitterPage from '../pages/MailboxSplitterPage.vue'
import UrlMailboxTestPage from '../pages/UrlMailboxTestPage.vue'
import RunPage from '../pages/RunPage.vue'
import SettingsPage from '../pages/SettingsPage.vue'
import { appControllerKey, createAppController } from '../composables/useAppController'
import OpenAIConnectivitySidebarStatus from './OpenAIConnectivitySidebarStatus.vue'
import ReleaseNotesDialog from './ReleaseNotesDialog.vue'

const controller = createAppController()
provide(appControllerKey, controller)

const routes = new Set(['/', '/mailboxes', '/splitter', '/url-test', '/accounts', '/settings'])
const pathFromLocation = () => routes.has(window.location.pathname) ? window.location.pathname : '/'
const activePath = ref(pathFromLocation())

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
      <el-aside width="156px" class="app-sidebar">
        <div class="brand-block">
          <div class="brand-mark"><el-icon><Cpu /></el-icon></div>
          <div class="brand-copy"><strong>自动接码机</strong><span>GPT Phone</span></div>
        </div>

        <el-menu :default-active="activePath" :collapse-transition="false" @select="selectPage">
          <el-menu-item index="/"><el-icon><Monitor /></el-icon><span>运行中心</span></el-menu-item>
          <el-menu-item index="/mailboxes"><el-icon><MessageBox /></el-icon><span>邮箱管理</span></el-menu-item>
          <el-menu-item index="/splitter"><el-icon><Scissor /></el-icon><span>邮箱分割</span></el-menu-item>
          <el-menu-item index="/url-test"><el-icon><Link /></el-icon><span>URL测试</span></el-menu-item>
          <el-menu-item index="/accounts"><el-icon><UserFilled /></el-icon><span>账号管理</span></el-menu-item>
          <el-menu-item index="/settings"><el-icon><Setting /></el-icon><span>运行配置</span></el-menu-item>
        </el-menu>

        <div class="global-status">
          <div class="status-heading"><span class="status-dot" :class="statusClass" /><strong>{{ runStatus }}</strong></div>
          <OpenAIConnectivitySidebarStatus :runtime="controller.runtime.value" />
          <div v-if="controller.runtime.value.notification?.status" class="notification-state">
            <el-icon><Bell /></el-icon>
            <span>{{ controller.runtime.value.notification.status === 'sent' ? '通知已发送' : controller.runtime.value.notification.status === 'failed' ? '通知发送失败' : '通知等待发送' }}</span>
          </div>
        </div>
      </el-aside>

      <el-main>
        <div v-if="!controller.initialized.value" class="shell-loading"><el-icon class="is-loading"><Loading /></el-icon></div>
        <RunPage v-else-if="activePath === '/'" @navigate="navigate" />
        <MailboxPage v-else-if="activePath === '/mailboxes'" />
        <MailboxSplitterPage v-else-if="activePath === '/splitter'" />
        <UrlMailboxTestPage v-else-if="activePath === '/url-test'" />
        <AccountManagementPage v-else-if="activePath === '/accounts'" />
        <SettingsPage v-else @navigate="navigate" />
      </el-main>
    </el-container>
    <ReleaseNotesDialog />
  </el-config-provider>
</template>

<style scoped>
.app-shell { width: 100%; min-width: 1280px; height: 100vh; overflow: hidden; background: var(--workspace-page); }
.app-sidebar { display: flex; flex-direction: column; height: 100%; overflow: hidden; border-right: 1px solid var(--workspace-border); background: #fff; }
.brand-block { display: flex; align-items: center; gap: 9px; height: 64px; padding: 0 14px; border-bottom: 1px solid var(--workspace-border); }
.brand-mark { display: grid; place-items: center; flex: 0 0 32px; width: 32px; height: 32px; border-radius: 6px; background: #2563eb; color: #fff; font-size: 18px; }
.brand-copy { display: flex; flex-direction: column; min-width: 0; }
.brand-copy strong { color: #172033; font-size: 14px; line-height: 20px; font-weight: 720; white-space: nowrap; }
.brand-copy span { color: #8792a4; font-size: 10px; line-height: 14px; text-transform: uppercase; }
.el-menu { flex: 1; padding: 8px 6px; border-right: 0; }
.el-menu-item { height: 42px; margin-bottom: 4px; padding: 0 10px !important; border-radius: 5px; color: #596579; font-size: 13px; }
.el-menu-item .el-icon { font-size: 18px; }
.el-menu-item.is-active { background: #eef5ff; color: #2563eb; font-weight: 650; }
.global-status { margin: 8px; padding: 10px 9px; border-top: 1px solid var(--workspace-border); }
.status-heading,
.notification-state { display: flex; align-items: center; }
.status-heading { gap: 7px; }
.status-heading strong { font-size: 13px; }
.status-dot { width: 7px; height: 7px; border-radius: 50%; background: #94a3b8; }
.status-dot.success { background: #16a34a; box-shadow: 0 0 0 3px #dcfce7; }
.status-dot.warning { background: #d97706; box-shadow: 0 0 0 3px #fef3c7; }
.status-dot.danger { background: #dc2626; box-shadow: 0 0 0 3px #fee2e2; }
.notification-state { gap: 5px; margin-top: 7px; color: #7b8798; font-size: 10px; }
.el-main { height: 100%; min-width: 0; padding: 5px; overflow: hidden; }
.shell-loading { display: grid; place-items: center; width: 100%; height: 100%; color: var(--el-color-primary); font-size: 22px; }
</style>
