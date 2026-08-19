<script setup lang="ts">
import { nextTick, onMounted, ref, watch } from 'vue'
import RuntimeSettingsSection from './RuntimeSettingsSection.vue'
import SmsSettingsSection from './SmsSettingsSection.vue'
import IntegrationSettingsSection from './IntegrationSettingsSection.vue'
import EmailNotificationSettingsSection from './EmailNotificationSettingsSection.vue'
import FreeRegisterSettingsSection from './FreeRegisterSettingsSection.vue'
import type { SmsKeyStatus, NotificationRuntimeStatus } from '../types/api'

interface SettingsNavNode {
  key: string
  label: string
  anchor: string
  children?: SettingsNavNode[]
}

const props = defineProps<{
  modelValue: any
  smsKeyStatuses?: SmsKeyStatus[]
  queryingSmsBalances?: boolean
  testingNotification?: boolean
  notificationStatus?: NotificationRuntimeStatus
  initialAnchor?: string
}>()
const emit = defineEmits<{ 'update:modelValue': [any]; testNotification: []; querySmsBalances: [] }>()

const scrollRegion = ref<HTMLElement>()
const activeKey = ref('runtime')
const navProps = { label: 'label', children: 'children' }
const navigation: SettingsNavNode[] = [
  {
    key: 'runtime',
    label: '接码机运行配置',
    anchor: 'runtime',
    children: [
      { key: 'runtime-scale', label: '任务规模与并发', anchor: 'runtime' },
      { key: 'runtime-network', label: '代理与链路', anchor: 'runtime' },
      { key: 'runtime-protection', label: '性能保护', anchor: 'runtime' },
    ],
  },
  {
    key: 'free-register',
    label: 'Free 注册运行配置',
    anchor: 'free-register',
    children: [
      { key: 'free-scale', label: '目标数与并发', anchor: 'free-register' },
      { key: 'free-driver', label: '注册链路', anchor: 'free-register' },
      { key: 'free-roxy', label: 'RoxyBrowser 与人工节奏', anchor: 'free-register' },
      { key: 'free-proxy', label: '独立代理池预检', anchor: 'free-register' },
    ],
  },
  {
    key: 'sms',
    label: 'SMS 接码',
    anchor: 'sms',
    children: [
      { key: 'sms-policy', label: '接码策略', anchor: 'sms' },
      { key: 'sms-providers', label: '平台 Key', anchor: 'sms' },
    ],
  },
  {
    key: 'integration',
    label: '平台集成',
    anchor: 'integration',
    children: [
      { key: 'sub2', label: 'SUB2 API', anchor: 'sub2' },
      { key: 'online-mailbox', label: '在线邮箱', anchor: 'online-mailbox' },
    ],
  },
  {
    key: 'notification',
    label: '通知设置',
    anchor: 'notification',
  },
]

function scrollToAnchor(anchor: string) {
  const targetNode = navigation.find(node => node.anchor === anchor || node.key === anchor)
  activeKey.value = targetNode?.key || anchor || 'runtime'
  nextTick(() => {
    const target = scrollRegion.value?.querySelector<HTMLElement>(`[data-settings-anchor="${anchor}"]`)
    target?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  })
}

function jumpTo(node: SettingsNavNode) {
  scrollToAnchor(node.anchor || node.key)
}

onMounted(() => {
  if (props.initialAnchor) scrollToAnchor(props.initialAnchor)
})

watch(() => props.initialAnchor, (anchor) => {
  if (anchor) scrollToAnchor(anchor)
})
</script>

<template>
  <div class="settings-form">
    <aside class="settings-nav" aria-label="运行配置快捷导航">
      <div class="nav-title">快捷导航</div>
      <el-tree
        :data="navigation"
        :props="navProps"
        node-key="key"
        default-expand-all
        highlight-current
        :current-node-key="activeKey"
        @node-click="jumpTo"
      />
    </aside>

    <div ref="scrollRegion" class="settings-scroll">
      <el-form label-position="top" class="settings-fields">
        <section data-settings-anchor="runtime" class="settings-anchor">
          <RuntimeSettingsSection
            :model-value="modelValue"
            @update:model-value="emit('update:modelValue', $event)"
          />
        </section>
        <section data-settings-anchor="free-register" class="settings-anchor">
          <FreeRegisterSettingsSection />
        </section>
        <section data-settings-anchor="sms" class="settings-anchor">
          <SmsSettingsSection
            :model-value="modelValue"
            :statuses="smsKeyStatuses"
            :querying-balances="queryingSmsBalances"
            @update:model-value="emit('update:modelValue', $event)"
            @query-balances="emit('querySmsBalances')"
          />
        </section>
        <section data-settings-anchor="integration" class="settings-anchor">
          <IntegrationSettingsSection
            :model-value="modelValue"
            @update:model-value="emit('update:modelValue', $event)"
          />
        </section>
        <section data-settings-anchor="notification" class="settings-anchor">
          <EmailNotificationSettingsSection
            :model-value="modelValue"
            :testing="testingNotification"
            :status="notificationStatus"
            @update:model-value="emit('update:modelValue', $event)"
            @test="emit('testNotification')"
          />
        </section>
      </el-form>
    </div>
  </div>
</template>

<style scoped>
.settings-form {
  display: grid;
  grid-template-columns: 178px minmax(0, 1fr);
  width: 100%;
  height: 100%;
  min-width: 0;
  min-height: 0;
  background: var(--workspace-surface);
}
.settings-nav {
  min-width: 0;
  min-height: 0;
  padding: 12px 8px 12px 10px;
  border-right: 1px solid var(--workspace-border);
  background: #f7f9fc;
  overflow: auto;
}
.nav-title {
  margin: 0 8px 8px;
  color: var(--el-text-color-secondary);
  font-size: 12px;
  font-weight: 650;
}
.settings-nav :deep(.el-tree) { background: transparent; color: var(--el-text-color-regular); }
.settings-nav :deep(.el-tree-node__content) { height: 32px; border-radius: 4px; }
.settings-nav :deep(.el-tree-node__label) { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12px; }
.settings-nav :deep(.el-tree-node.is-current > .el-tree-node__content) { color: var(--el-color-primary); background: #eaf3ff; }
.settings-scroll {
  min-width: 0;
  min-height: 0;
  overflow: auto;
  scrollbar-width: thin;
  scrollbar-color: #75a9d8 #edf3f8;
}
.settings-scroll::-webkit-scrollbar { width: 7px; }
.settings-scroll::-webkit-scrollbar-thumb { border-radius: 4px; background: #75a9d8; }
.settings-scroll::-webkit-scrollbar-track { background: #edf3f8; }
.settings-fields { box-sizing: border-box; width: 100%; padding: 12px 16px 20px; }
.settings-anchor + .settings-anchor { margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--workspace-border); }
</style>
