<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { Delete, Plus } from '@element-plus/icons-vue'
import { ElMessageBox } from 'element-plus'
import type { SmsKeyStatus } from '../types/api'

const props = defineProps<{
  modelValue: string[]
  statuses?: SmsKeyStatus[]
  title?: string
}>()

const emit = defineEmits<{ 'update:modelValue': [string[]] }>()

let nextRowId = 1
const rowIds = ref<number[]>([])

const rows = computed(() => {
  const values = Array.isArray(props.modelValue) ? props.modelValue : []
  return values.length ? values : ['']
})

watch(
  () => rows.value.length,
  (length) => {
    const next = rowIds.value.slice(0, length)
    while (next.length < length) next.push(nextRowId++)
    rowIds.value = next
  },
  { immediate: true },
)

function updateRow(index: number, value: string) {
  const next = [...rows.value]
  next[index] = value
  emit('update:modelValue', next)
}

function addRow() {
  rowIds.value = [...rowIds.value, nextRowId++]
  emit('update:modelValue', [...rows.value, ''])
}

async function removeRow(index: number) {
  if (rows.value.length === 1) {
    if (rows.value[index]) {
      try {
        await ElMessageBox.confirm(
          '确定清空 SMS API Key？清空后需要保存配置才会生效。',
          '清空 SMS API Key',
          {
            type: 'warning',
            confirmButtonText: '清空',
            cancelButtonText: '取消',
          },
        )
      } catch {
        return
      }
    }
    emit('update:modelValue', [''])
    return
  }
  rowIds.value = rowIds.value.filter((_rowId, rowIndex) => rowIndex !== index)
  emit('update:modelValue', rows.value.filter((_value, rowIndex) => rowIndex !== index))
}

function statusAt(index: number) {
  return props.statuses?.find(item => Number(item.index) === index + 1)
}

function statusLabel(status?: SmsKeyStatus) {
  if (!status) return '未查询'
  if (status.status === 'usable') return `可用 $${Number(status.balance_usd || 0).toFixed(2)}`
  if (status.status === 'insufficient_balance') return `余额不足 $${Number(status.balance_usd || 0).toFixed(2)}`
  if (status.status === 'invalid') return 'Key 无效'
  if (status.status === 'rate_limited') return '请求限流'
  if (status.status === 'network_error') return '网络异常'
  return status.message || '未查询'
}

function statusType(status?: SmsKeyStatus) {
  if (status?.status === 'usable') return 'success'
  if (['insufficient_balance', 'invalid', 'error'].includes(status?.status || '')) return 'danger'
  if (status?.status === 'rate_limited' || status?.status === 'network_error') return 'warning'
  return 'info'
}
</script>

<template>
  <div class="sms-key-editor">
    <div class="editor-title">
      <span>{{ title || 'API Key' }}</span>
      <el-tooltip content="新增 SMS API Key" placement="top">
        <el-button text circle aria-label="新增 SMS API Key" @click="addRow">
          <el-icon><Plus /></el-icon>
        </el-button>
      </el-tooltip>
    </div>
    <div class="key-rows">
      <div v-for="(key, index) in rows" :key="rowIds[index]" class="key-row">
        <el-input
          :model-value="key"
          type="password"
          show-password
          autocomplete="new-password"
          :placeholder="`SMS API Key ${index + 1}`"
          @update:model-value="updateRow(index, $event)"
        />
        <el-tag class="key-status" :type="statusType(statusAt(index))">
          {{ statusLabel(statusAt(index)) }}
        </el-tag>
        <el-tooltip :content="rows.length === 1 ? '清空 SMS API Key' : '删除 SMS API Key'" placement="top">
          <el-button text circle :aria-label="rows.length === 1 ? '清空 SMS API Key' : '删除 SMS API Key'" @click="removeRow(index)">
            <el-icon><Delete /></el-icon>
          </el-button>
        </el-tooltip>
      </div>
    </div>
  </div>
</template>

<style scoped>
.sms-key-editor { margin-bottom: 12px; }
.editor-title { display: flex; align-items: center; gap: 4px; min-height: 32px; margin-bottom: 6px; color: var(--el-text-color-regular); font-size: 12px; }
.editor-title :deep(.el-button) { width: 32px; height: 32px; padding: 0; }
.key-rows { display: grid; gap: 8px; }
.key-row { display: grid; grid-template-columns: minmax(0, 1fr) 116px 32px; align-items: center; gap: 8px; min-height: 32px; }
.key-status { width: 116px; justify-content: center; overflow: hidden; }
.key-status :deep(.el-tag__content) { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.key-row > :deep(.el-button) { width: 32px; height: 32px; padding: 0; }
</style>
