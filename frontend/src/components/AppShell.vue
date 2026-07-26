<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import RunPage from '../pages/RunPage.vue'
import MailboxPage from '../pages/MailboxPage.vue'

function pageFromLocation() {
  return window.location.pathname === '/mailboxes' ? 'mailboxes' : 'run'
}

const page = ref(pageFromLocation())

function selectPage(key: string) {
  page.value = key
  history.pushState({}, '', key === 'mailboxes' ? '/mailboxes' : '/')
}

function syncLocation() {
  page.value = pageFromLocation()
}

onMounted(() => window.addEventListener('popstate', syncLocation))
onUnmounted(() => window.removeEventListener('popstate', syncLocation))
</script>

<template>
  <el-config-provider size="small" :locale="zhCn">
    <el-container class="app-shell">
      <el-aside width="136px">
        <el-menu :default-active="page" :collapse-transition="false" @select="selectPage">
          <el-menu-item index="run"><el-icon><Monitor /></el-icon><span>运行控制</span></el-menu-item>
          <el-menu-item index="mailboxes"><el-icon><MessageBox /></el-icon><span>邮箱管理</span></el-menu-item>
        </el-menu>
      </el-aside>
      <el-main>
        <RunPage v-if="page === 'run'" />
        <MailboxPage v-else />
      </el-main>
    </el-container>
  </el-config-provider>
</template>

<style scoped>
.app-shell { width: 100%; height: 100vh; overflow: hidden; background: #f5f7fb; }
.el-aside { height: 100%; background: #fff; border-right: 1px solid var(--el-border-color-light); overflow: hidden; }
.el-menu { border-right: 0; }
.el-main { height: 100%; min-width: 0; padding: 5px; overflow: hidden; }
@media (max-width: 700px) {
  .el-aside { width: 56px !important; }
  .el-menu-item { padding: 0 18px !important; }
  .el-menu-item span { display: none; }
}
</style>
