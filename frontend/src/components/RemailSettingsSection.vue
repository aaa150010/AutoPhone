<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { CircleCheck, Refresh } from '@element-plus/icons-vue'
import { getRemailConfig, saveRemailConfig, type FreeConfig } from '../api/client'

const emit = defineEmits<{ dirtyChange: [boolean] }>()
const config = reactive<NonNullable<FreeConfig['remail']>>({ enabled: false, base_url: 'https://remail.aishop6.com', api_key: '', project_id: '', supply_policy: 'private_first', request_timeout_seconds: 20, catalog_cache_seconds: 60, order_sync_enabled: false, order_sync_interval_minutes: 30, auto_import_new_purchase_orders: false })
const loading = ref(false)
const saving = ref(false)
const dirty = ref(false)
function markDirty() { if (!dirty.value) { dirty.value = true; emit('dirtyChange', true) } }
async function load() { loading.value = true; try { Object.assign(config, (await getRemailConfig()).config || {}); dirty.value = false; emit('dirtyChange', false) } catch (error: any) { ElMessage.error(error?.message || 'Remail 配置读取失败') } finally { loading.value = false } }
async function save() { saving.value = true; try { Object.assign(config, (await saveRemailConfig({ ...config })).config || {}); dirty.value = false; emit('dirtyChange', false); ElMessage.success('Remail 配置已保存') } catch (error: any) { ElMessage.error(error?.message || 'Remail 配置保存失败') } finally { saving.value = false } }
defineExpose({ save })
onMounted(load)
</script>

<template>
  <div class="remail-settings-section">
    <div class="section-heading-row"><div><h2 class="section-title">Remail 运行配置</h2><p class="section-hint">配置 Remail API、供应策略和订单同步。运行任务期间不能修改。</p></div><el-button size="small" :icon="Refresh" :loading="loading" @click="load">刷新</el-button></div>
    <el-form label-position="top" class="config-grid" @change="markDirty">
      <el-form-item label="启用 Remail"><el-switch v-model="config.enabled" @change="markDirty" /></el-form-item>
      <el-form-item label="API Key"><el-input v-model="config.api_key" type="password" show-password placeholder="rk-..." @input="markDirty" /></el-form-item>
      <el-form-item label="API 地址"><el-input v-model="config.base_url" @input="markDirty" /></el-form-item>
      <el-form-item label="项目 ID"><el-input v-model="config.project_id" @input="markDirty" /></el-form-item>
      <el-form-item label="供应策略"><el-select v-model="config.supply_policy" @change="markDirty"><el-option label="私有优先" value="private_first" /><el-option label="仅公开供应" value="public_only" /></el-select></el-form-item>
      <el-form-item label="请求超时（秒）"><el-input-number v-model="config.request_timeout_seconds" :min="3" :max="120" @change="markDirty" /></el-form-item>
      <el-form-item label="目录缓存（秒）"><el-input-number v-model="config.catalog_cache_seconds" :min="0" :max="3600" @change="markDirty" /></el-form-item>
      <el-form-item label="订单自动同步间隔（分钟）"><el-input-number v-model="config.order_sync_interval_minutes" :min="1" :max="1440" @change="markDirty" /></el-form-item>
      <el-form-item label="订单同步"><el-switch v-model="config.order_sync_enabled" @change="markDirty" /></el-form-item>
      <el-form-item label="新订单自动导入 Free 池"><el-switch v-model="config.auto_import_new_purchase_orders" @change="markDirty" /></el-form-item>
    </el-form>
    <div class="settings-actions"><el-button type="primary" size="small" :icon="CircleCheck" :loading="saving" @click="save">保存 Remail 配置</el-button></div>
  </div>
</template>

<style scoped>
.section-heading-row { display:flex; align-items:center; gap:10px; }.section-heading-row > div:first-child { margin-right:auto; }.section-title { margin:0; font-size:14px; }.section-hint { margin:3px 0 0; color:var(--el-text-color-secondary); font-size:12px; }.config-grid { display:grid; grid-template-columns:repeat(3,minmax(180px,1fr)); gap:0 14px; margin-top:14px; }.config-grid :deep(.el-select),.config-grid :deep(.el-input-number){width:100%;}.settings-actions { display:flex; justify-content:flex-end; margin-top:8px; padding-top:12px; border-top:1px solid var(--workspace-border); }
</style>
