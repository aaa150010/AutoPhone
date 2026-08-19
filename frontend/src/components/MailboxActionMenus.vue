<script setup lang="ts">
import { computed } from 'vue'
import {
  ArrowDown,
  Box,
  CircleCloseFilled,
  Delete,
  Download,
  Loading,
  MoreFilled,
  RefreshLeft,
  RefreshRight,
  Tools,
  UploadFilled,
} from '@element-plus/icons-vue'

const props = defineProps<{
  reloginDisabled: boolean
  restoreDisabled: boolean
  draftDisabled: boolean
  unavailableDisabled: boolean
  exportDisabled: boolean
  sourceExportDisabled: boolean
  websiteDisabled: boolean
  deleteDisabled: boolean
  reloginLoading?: boolean
  exportLoading?: boolean
  sourceExportLoading?: boolean
  websiteLoading?: boolean
  unavailableLoading?: boolean
  draftLoading?: boolean
}>()

const emit = defineEmits<{
  (event: 'relogin'): void
  (event: 'restore'): void
  (event: 'draft'): void
  (event: 'unavailable'): void
  (event: 'export'): void
  (event: 'source-export'): void
  (event: 'website'): void
  (event: 'delete'): void
}>()

const accountDisabled = computed(() => (
  props.reloginDisabled && props.restoreDisabled && props.draftDisabled && props.unavailableDisabled
))
const transferDisabled = computed(() => (
  props.exportDisabled && props.sourceExportDisabled && props.websiteDisabled
))
const accountLoading = computed(() => Boolean(
  props.reloginLoading || props.draftLoading || props.unavailableLoading,
))
const transferLoading = computed(() => Boolean(
  props.exportLoading || props.sourceExportLoading || props.websiteLoading,
))

function handleAccountCommand(command: string) {
  if (command === 'relogin' && !props.reloginDisabled) emit('relogin')
  if (command === 'restore' && !props.restoreDisabled) emit('restore')
  if (command === 'draft' && !props.draftDisabled) emit('draft')
  if (command === 'unavailable' && !props.unavailableDisabled) emit('unavailable')
}

function handleTransferCommand(command: string) {
  if (command === 'export' && !props.exportDisabled) emit('export')
  if (command === 'source-export' && !props.sourceExportDisabled) emit('source-export')
  if (command === 'website' && !props.websiteDisabled) emit('website')
}

function handleMoreCommand(command: string) {
  if (command === 'delete' && !props.deleteDisabled) emit('delete')
}
</script>

<template>
  <div class="mailbox-action-menus">
    <el-dropdown
      trigger="click"
      :disabled="accountDisabled"
      @command="handleAccountCommand"
    >
      <el-button :disabled="accountDisabled">
        <el-icon v-if="accountLoading" class="is-loading"><Loading /></el-icon>
        <el-icon v-else><Tools /></el-icon>
        账号维护
        <el-icon class="menu-chevron"><ArrowDown /></el-icon>
      </el-button>
      <template #dropdown>
        <el-dropdown-menu>
          <el-dropdown-item command="relogin" :disabled="reloginDisabled || reloginLoading">
            <el-icon :class="{ 'is-loading': reloginLoading }">
              <Loading v-if="reloginLoading" />
              <RefreshRight v-else />
            </el-icon>
            重登并更新 SUB2
          </el-dropdown-item>
          <el-dropdown-item command="restore" :disabled="restoreDisabled">
            <el-icon><RefreshLeft /></el-icon>
            恢复可用
          </el-dropdown-item>
          <el-dropdown-item command="draft" :disabled="draftDisabled || draftLoading">
            <el-icon :class="{ 'is-loading': draftLoading }">
              <Loading v-if="draftLoading" />
              <Box v-else />
            </el-icon>
            放入草稿箱
          </el-dropdown-item>
          <el-dropdown-item command="unavailable" :disabled="unavailableDisabled || unavailableLoading">
            <el-icon :class="{ 'is-loading': unavailableLoading }">
              <Loading v-if="unavailableLoading" />
              <CircleCloseFilled v-else />
            </el-icon>
            设置为不可用
          </el-dropdown-item>
        </el-dropdown-menu>
      </template>
    </el-dropdown>

    <el-dropdown
      trigger="click"
      :disabled="transferDisabled"
      @command="handleTransferCommand"
    >
      <el-button :disabled="transferDisabled">
        <el-icon v-if="transferLoading" class="is-loading"><Loading /></el-icon>
        <el-icon v-else><UploadFilled /></el-icon>
        导出与邮箱
        <el-icon class="menu-chevron"><ArrowDown /></el-icon>
      </el-button>
      <template #dropdown>
        <el-dropdown-menu>
          <el-dropdown-item command="export" :disabled="exportDisabled || exportLoading">
            <el-icon :class="{ 'is-loading': exportLoading }">
              <Loading v-if="exportLoading" />
              <Download v-else />
            </el-icon>
            导出 SUB2API
          </el-dropdown-item>
          <el-dropdown-item command="source-export" :disabled="sourceExportDisabled || sourceExportLoading">
            <el-icon :class="{ 'is-loading': sourceExportLoading }">
              <Loading v-if="sourceExportLoading" />
              <Download v-else />
            </el-icon>
            导出原始格式
          </el-dropdown-item>
          <el-dropdown-item command="website" :disabled="websiteDisabled || websiteLoading">
            <el-icon :class="{ 'is-loading': websiteLoading }">
              <Loading v-if="websiteLoading" />
              <UploadFilled v-else />
            </el-icon>
            导入网站邮箱
          </el-dropdown-item>
        </el-dropdown-menu>
      </template>
    </el-dropdown>

    <el-dropdown
      trigger="click"
      @command="handleMoreCommand"
    >
      <el-button>
        <el-icon><MoreFilled /></el-icon>
        更多操作
        <el-icon class="menu-chevron"><ArrowDown /></el-icon>
      </el-button>
      <template #dropdown>
        <el-dropdown-menu>
          <el-dropdown-item command="delete" :disabled="deleteDisabled">
            <el-icon class="danger-icon"><Delete /></el-icon>
            <span class="danger-label">删除</span>
          </el-dropdown-item>
        </el-dropdown-menu>
      </template>
    </el-dropdown>
  </div>
</template>

<style scoped>
.mailbox-action-menus {
  display: flex;
  align-items: center;
  gap: 7px;
  min-width: 0;
}

.mailbox-action-menus .el-button {
  margin-left: 0;
  white-space: nowrap;
}

.menu-chevron {
  margin-left: 2px;
  font-size: 11px;
}

.danger-icon,
.danger-label {
  color: var(--el-color-danger);
}
</style>
