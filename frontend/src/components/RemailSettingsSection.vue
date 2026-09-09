<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { errorMessage } from '../utils/errorMessage'
import { copyTextRequired } from '../utils/clipboard'
import { ElMessage, ElMessageBox } from 'element-plus'
import { CircleCheck, CopyDocument, Refresh, View } from '@element-plus/icons-vue'
import { getRemailConfig, revealRemailKey, saveRemailConfig, type FreeConfig } from '../api/client'

const emit = defineEmits<{ dirtyChange: [boolean] }>()
const config = reactive<NonNullable<FreeConfig['remail']>>({ enabled: false, base_url: 'https://remail.aishop6.com', api_key: '', project_id: '', supply_policy: 'private_first', request_timeout_seconds: 20, catalog_cache_seconds: 60, order_sync_enabled: false, order_sync_interval_minutes: 30, auto_import_new_purchase_orders: false })
const loading = ref(false)
const saving = ref(false)
const dirty = ref(false)
const revealing = ref(false)
const keyVisible = ref(false)
/** Real key fetched on demand; non-empty means the field currently shows the fetched key. */
const revealedKey = ref('')
/** True while the loaded key is masked server-side (i.e. a key exists but was not sent). */
const keyIsMasked = computed(() => config.api_key === '********')
function markDirty() { if (!dirty.value) { dirty.value = true; emit('dirtyChange', true) } }
async function load() { loading.value = true; try { Object.assign(config, (await getRemailConfig()).config || {}); revealedKey.value = ''; keyVisible.value = false; dirty.value = false; emit('dirtyChange', false) } catch (error) { ElMessage.error(errorMessage(error) || 'Remail 配置读取失败') } finally { loading.value = false } }
async function save() { saving.value = true; try { Object.assign(config, (await saveRemailConfig({ ...config })).config || {}); revealedKey.value = ''; keyVisible.value = false; dirty.value = false; emit('dirtyChange', false); ElMessage.success('Remail 配置已保存') } catch (error) { ElMessage.error(errorMessage(error) || 'Remail 配置保存失败') } finally { saving.value = false } }
function onKeyInput() { if (revealedKey.value) revealedKey.value = ''; markDirty() }
async function fetchKey(): Promise<string> {
  revealing.value = true
  try {
    const result = await revealRemailKey()
    if (!result.has_key) ElMessage.warning('当前未配置 Remail API Key')
    return result.api_key
  } catch (error) {
    ElMessage.error(errorMessage(error) || '读取 Remail API Key 失败')
    return ''
  } finally {
    revealing.value = false
  }
}
async function confirmViewKey(): Promise<boolean> {
  try { await ElMessageBox.confirm('Remail API Key 仅用于本机设置页查看与复制，请勿泄露。确认查看？', '查看 API Key', { type: 'warning', confirmButtonText: '查看', cancelButtonText: '取消' }); return true } catch { return false }
}
/** Swap the masked placeholder for the fetched real key before showing it. */
function showFetchedKey(key: string) { revealedKey.value = key; config.api_key = key; keyVisible.value = true }
async function toggleKeyVisible() {
  if (keyVisible.value) {
    keyVisible.value = false
    if (revealedKey.value) { config.api_key = '********'; revealedKey.value = '' }
    return
  }
  if (keyIsMasked.value) {
    if (!(await confirmViewKey())) return
    const key = await fetchKey()
    if (!key) return
    showFetchedKey(key)
    return
  }
  keyVisible.value = true
}
async function copyKey() {
  if (keyIsMasked.value) {
    if (!(await confirmViewKey())) return
    const key = await fetchKey()
    if (!key) return
    showFetchedKey(key)
    await copyTextRequired(key, 'API Key 已复制')
    return
  }
  await copyTextRequired(config.api_key, 'API Key 已复制')
}
defineExpose({ save })
onMounted(load)
</script>

<template>
  <div class="remail-settings-section">
    <div class="section-heading-row"><div><h2 class="section-title">Remail 运行配置</h2><p class="section-hint">配置 Remail API、供应策略和订单同步。运行任务期间不能修改。</p></div><el-button size="small" :icon="Refresh" :loading="loading" @click="load" aria-label="刷新">刷新</el-button></div>
    <el-form label-position="top" class="config-grid" @change="markDirty">
      <el-form-item label="启用 Remail"><el-switch v-model="config.enabled" @change="markDirty" /></el-form-item>
      <el-form-item label="API Key">
        <el-input v-model="config.api_key" size="small" :type="keyVisible ? 'text' : 'password'" placeholder="rk-..." @input="onKeyInput">
          <template #suffix>
            <el-tooltip content="查看原文" :show-after="250" placement="top"><el-button class="key-action" :icon="View" link size="small" :loading="revealing" :aria-label="keyVisible ? '隐藏 API Key' : '查看 API Key 原文'" @click="toggleKeyVisible" /></el-tooltip>
            <el-tooltip content="复制原文" :show-after="250" placement="top"><el-button class="key-action" :icon="CopyDocument" link size="small" :disabled="!config.api_key" aria-label="复制 API Key 原文" @click="copyKey" /></el-tooltip>
          </template>
        </el-input>
      </el-form-item>
      <el-form-item label="API 地址"><el-input v-model="config.base_url" size="small" @input="markDirty" /></el-form-item>
      <el-form-item label="项目 ID"><el-input v-model="config.project_id" size="small" @input="markDirty" /></el-form-item>
      <el-form-item label="供应策略"><el-select v-model="config.supply_policy" size="small" @change="markDirty"><el-option label="私有优先" value="private_first" /><el-option label="仅公开供应" value="public_only" /></el-select></el-form-item>
      <el-form-item label="请求超时（秒）"><el-input-number v-model="config.request_timeout_seconds" size="small" :min="3" :max="120" @change="markDirty" /></el-form-item>
      <el-form-item label="目录缓存（秒）"><el-input-number v-model="config.catalog_cache_seconds" size="small" :min="0" :max="3600" @change="markDirty" /></el-form-item>
      <el-form-item label="订单自动同步间隔（分钟）"><el-input-number v-model="config.order_sync_interval_minutes" size="small" :min="1" :max="1440" @change="markDirty" /></el-form-item>
      <el-form-item label="订单同步"><el-switch v-model="config.order_sync_enabled" @change="markDirty" /></el-form-item>
      <el-form-item label="新订单自动导入 Free 池"><el-switch v-model="config.auto_import_new_purchase_orders" @change="markDirty" /></el-form-item>
    </el-form>
    <div class="settings-actions"><el-button type="primary" size="small" :icon="CircleCheck" :loading="saving" @click="save" aria-label="保存 Remail 配置">保存 Remail 配置</el-button></div>
  </div>
</template>

<style scoped>
.section-heading-row { display:flex; align-items:center; gap:10px; }.section-heading-row > div:first-child { margin-right:auto; }.section-title { margin:0; font-size:14px; }.section-hint { margin:3px 0 0; color:var(--el-text-color-secondary); font-size:12px; }.config-grid { display:grid; grid-template-columns:repeat(4,minmax(150px,220px)); gap:0 10px; margin-top:10px; align-items:start; }.config-grid :deep(.el-input),.config-grid :deep(.el-select),.config-grid :deep(.el-input-number){width:100%;max-width:220px;}.config-grid :deep(.el-input__wrapper),.config-grid :deep(.el-select__wrapper),.config-grid :deep(.el-input-number){min-height:28px;height:28px;}.settings-actions { display:flex; justify-content:flex-end; margin-top:6px; padding-top:10px; border-top:1px solid var(--workspace-border); }
.key-action { padding: 0 1px; }
.key-action + .key-action { margin-left: 2px; }
@media (max-width: 1100px) { .config-grid { grid-template-columns:repeat(3,minmax(150px,220px)); } }
@media (max-width: 760px) { .config-grid { grid-template-columns:repeat(2,minmax(140px,1fr)); } .config-grid :deep(.el-input),.config-grid :deep(.el-select),.config-grid :deep(.el-input-number) { max-width:none; } }
</style>
