<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { CircleCheck, Connection, Refresh } from '@element-plus/icons-vue'
import { getFreeConfig, getFreeRoxyWorkspaces, importFreeProxies, preflightFree, preflightFreeProxies, saveFreeConfig, type FreeConfig, type FreeState } from '../api/client'

const defaultConfig: FreeConfig = {
  driver: 'protocol', target_count: 0, concurrency: 3, email_code_timeout: 90, auto_set_2fa: true,
  proxy_probe_url: 'https://api.ipify.org', protocol: { node_runner: '', sentinel_timeout: 90 },
  roxybrowser: {
    api_base: 'http://127.0.0.1:50000', api_key: '', workspace_id: '', project_id: '',
    workspace_list_path: '/browser/workspace', create_path: '/browser/create', open_path: '/browser/open',
    close_path: '/browser/close', delete_path: '/browser/delete', headless: false, keep_browser_open: false,
    one_profile_per_account: true, delete_profile_after_run: true, random_os: true, os_choices: ['Windows', 'macOS'],
    random_profile_name: true, profile_name_prefix: 'rb', proxy_check_channel: 'IPRust.io', selenium_timeout: 90,
    api_retries: 3, api_retry_delay: 2, humanize_delay: true, humanize_factor: 1,
    humanize_browser_actions: true, post_registration_dwell_min: 18, post_registration_dwell_max: 45,
  },
}

const config = reactive<FreeConfig>(structuredClone(defaultConfig))
const state = ref<FreeState>({ running: false, tasks: [], summary: {}, pool: {} })
const proxyText = ref('')
const proxyCheckRows = ref<Array<{ index: number; masked: string; fingerprint: string; exit_ip: string }>>([])
const workspaces = ref<Array<{ workspace_id: string; workspace_name: string; project_id: string; project_name: string; label: string }>>([])
const busy = ref<'load' | 'save' | 'preflight' | 'proxy' | 'proxy-preflight' | 'workspace' | ''>('')
const running = computed(() => Boolean(state.value.running))
const roxy = computed(() => config.roxybrowser)

function mergeConfig(value: any) {
  if (!value || typeof value !== 'object') return
  Object.assign(config, value)
  Object.assign(config.protocol, value.protocol || {})
  Object.assign(config.roxybrowser, value.roxybrowser || {})
}

async function load() {
  busy.value = 'load'
  try {
    const result = await getFreeConfig()
    mergeConfig(result.config)
    state.value = result.state || state.value
  } catch (error: any) {
    ElMessage.error(error?.message || 'Free 配置加载失败')
  } finally {
    busy.value = ''
  }
}

async function save() {
  busy.value = 'save'
  try {
    const result = await saveFreeConfig(config)
    mergeConfig(result.config)
    state.value = result.state || state.value
    ElMessage.success('Free 注册配置已保存')
  } catch (error: any) {
    ElMessage.error(error?.message || 'Free 配置保存失败')
  } finally {
    busy.value = ''
  }
}

async function preflight() {
  busy.value = 'preflight'
  try {
    const result = await preflightFree({ ...config, proxy_content: proxyText.value })
    mergeConfig(result.config)
    state.value = result.state || state.value
    ElMessage.success(`Free 预检通过：${Number(result.result?.target_count || 0)} 个账号，${Number(result.result?.proxies || 0)} 个固定代理`)
  } catch (error: any) {
    ElMessage.error(error?.message || 'Free 注册预检失败')
  } finally {
    busy.value = ''
  }
}

async function importProxyPool() {
  if (!proxyText.value.trim()) {
    ElMessage.warning('请先粘贴 Free 代理')
    return
  }
  busy.value = 'proxy'
  try {
    const result = await importFreeProxies(proxyText.value)
    ElMessage.success(`已保存 ${Number(result.imported || 0)} 个 Free 代理`)
    proxyText.value = ''
  } catch (error: any) {
    ElMessage.error(error?.message || 'Free 代理池保存失败')
  } finally {
    busy.value = ''
  }
}

async function preflightProxyPool() {
  busy.value = 'proxy-preflight'
  try {
    const result = await preflightFreeProxies(proxyText.value, config.proxy_probe_url)
    proxyCheckRows.value = result.result?.rows || []
    ElMessage.success(`代理出口 IP 检测通过：${Number(result.result?.proxies || 0)} 个，${Number(result.result?.exit_ips || 0)} 个唯一出口 IP`)
  } catch (error: any) {
    proxyCheckRows.value = []
    ElMessage.error(error?.message || 'Free 代理出口 IP 检测失败')
  } finally {
    busy.value = ''
  }
}

async function loadWorkspaces() {
  busy.value = 'workspace'
  try {
    workspaces.value = (await getFreeRoxyWorkspaces()).items || []
    ElMessage.success(`已读取 ${workspaces.value.length} 个 RoxyBrowser 工作区`)
  } catch (error: any) {
    ElMessage.error(error?.message || 'RoxyBrowser 工作区读取失败')
  } finally {
    busy.value = ''
  }
}

function applyWorkspace(value: string) {
  const item = workspaces.value.find(row => row.label === value)
  if (!item) return
  config.roxybrowser.workspace_id = item.workspace_id
  config.roxybrowser.project_id = item.project_id
}

onMounted(load)
</script>

<template>
  <div class="free-settings-section">
    <div class="section-heading-row">
      <div>
        <h2 class="section-title">Free 注册运行配置</h2>
        <p class="section-hint">与接码机的目标数、并发、邮箱池、代理池和运行状态完全隔离。</p>
      </div>
      <el-tag v-if="running" type="success" effect="light">Free 注册运行中</el-tag>
      <el-tag v-else type="info" effect="plain">独立 Free 链路</el-tag>
    </div>

    <el-form-item label="注册链路">
      <el-radio-group v-model="config.driver" :disabled="running || busy === 'load'" class="driver-options">
        <el-radio value="protocol" border><strong>全协议</strong><small>OAuth、邮箱 OTP 和套餐检查</small></el-radio>
        <el-radio value="roxybrowser" border><strong>RoxyBrowser</strong><small>独立 Profile、固定代理和 Selenium 页面注册</small></el-radio>
      </el-radio-group>
    </el-form-item>

    <el-row :gutter="10">
      <el-col :span="8"><el-form-item label="Free 目标数量（0=全部可用）"><el-input-number v-model="config.target_count" :min="0" :max="10000" controls-position="right" :disabled="running" /></el-form-item></el-col>
      <el-col :span="8"><el-form-item label="Free 并发数（1-5）"><el-input-number v-model="config.concurrency" :min="1" :max="5" controls-position="right" :disabled="running" /></el-form-item></el-col>
      <el-col :span="8"><el-form-item label="邮箱 OTP 超时（秒）"><el-input-number v-model="config.email_code_timeout" :min="10" :max="600" controls-position="right" :disabled="running" /></el-form-item></el-col>
    </el-row>
    <el-form-item label="出口 IP 探测地址"><el-input v-model="config.proxy_probe_url" :disabled="running" placeholder="https://api.ipify.org" /></el-form-item>
    <el-form-item><el-checkbox v-model="config.auto_set_2fa" :disabled="running">注册完成后自动设置动态口令（额外等待一封 OTP）</el-checkbox></el-form-item>

    <div v-if="config.driver === 'protocol'" class="subsection">
      <h3>全协议专属配置</h3>
      <el-row :gutter="10">
        <el-col :span="16"><el-form-item label="Node / Sentinel Runner"><el-input v-model="config.protocol.node_runner" placeholder="留空使用运行时默认配置" :disabled="running" /></el-form-item></el-col>
        <el-col :span="8"><el-form-item label="Sentinel 超时（秒）"><el-input-number v-model="config.protocol.sentinel_timeout" :min="10" :max="300" controls-position="right" :disabled="running" /></el-form-item></el-col>
      </el-row>
    </div>

    <div v-else class="subsection">
      <div class="section-heading-row"><h3>RoxyBrowser 专属配置</h3><el-button size="small" :icon="Connection" :loading="busy === 'workspace'" :disabled="running" @click="loadWorkspaces">读取工作区</el-button></div>
      <el-row :gutter="10">
        <el-col :span="12"><el-form-item label="API 地址"><el-input v-model="roxy.api_base" :disabled="running" /></el-form-item></el-col>
        <el-col :span="12"><el-form-item label="API Key"><el-input v-model="roxy.api_key" type="password" show-password placeholder="留空或保持已保存密钥" :disabled="running" /></el-form-item></el-col>
      </el-row>
      <el-form-item label="工作区 / 项目"><el-select :model-value="workspaces.find(row => row.workspace_id === roxy.workspace_id && row.project_id === roxy.project_id)?.label || ''" clearable filterable placeholder="读取后选择" :disabled="running" @change="applyWorkspace"><el-option v-for="item in workspaces" :key="`${item.workspace_id}/${item.project_id}`" :label="item.label" :value="item.label" /></el-select></el-form-item>
      <el-row :gutter="10">
        <el-col :span="12"><el-form-item label="Workspace ID"><el-input v-model="roxy.workspace_id" :disabled="running" /></el-form-item></el-col>
        <el-col :span="12"><el-form-item label="Project ID"><el-input v-model="roxy.project_id" :disabled="running" /></el-form-item></el-col>
      </el-row>
      <el-row :gutter="10">
        <el-col :span="8"><el-form-item label="Selenium 超时（秒）"><el-input-number v-model="roxy.selenium_timeout" :min="10" :max="300" controls-position="right" :disabled="running" /></el-form-item></el-col>
        <el-col :span="8"><el-form-item label="API 重试次数"><el-input-number v-model="roxy.api_retries" :min="1" :max="5" controls-position="right" :disabled="running" /></el-form-item></el-col>
        <el-col :span="8"><el-form-item label="API 重试间隔（秒）"><el-input-number v-model="roxy.api_retry_delay" :min="0.25" :max="15" :step="0.25" controls-position="right" :disabled="running" /></el-form-item></el-col>
      </el-row>
      <div class="humanize-heading"><h4>人工节奏与浏览器动作</h4><el-tag size="small" type="success" effect="plain">默认开启</el-tag></div>
      <el-row :gutter="10">
        <el-col :span="8"><el-form-item label="人工节奏倍率"><el-input-number v-model="roxy.humanize_factor" :min="0.1" :max="5" :step="0.1" controls-position="right" :disabled="running" /></el-form-item></el-col>
        <el-col :span="8"><el-form-item label="注册后停留最短（秒）"><el-input-number v-model="roxy.post_registration_dwell_min" :min="0" :max="300" controls-position="right" :disabled="running" /></el-form-item></el-col>
        <el-col :span="8"><el-form-item label="注册后停留最长（秒）"><el-input-number v-model="roxy.post_registration_dwell_max" :min="0" :max="600" controls-position="right" :disabled="running" /></el-form-item></el-col>
      </el-row>
      <div class="check-row"><el-checkbox v-model="roxy.humanize_delay" :disabled="running">启用人工节奏</el-checkbox><el-checkbox v-model="roxy.humanize_browser_actions" :disabled="running">随机页面动作</el-checkbox><el-checkbox v-model="roxy.random_os" :disabled="running">随机系统</el-checkbox><el-checkbox v-model="roxy.random_profile_name" :disabled="running">随机 Profile 名称</el-checkbox></div>
      <el-row v-if="roxy.random_os" :gutter="10"><el-col :span="12"><el-form-item label="随机系统范围"><el-checkbox-group v-model="roxy.os_choices" :disabled="running"><el-checkbox label="Windows" /><el-checkbox label="macOS" /><el-checkbox label="Linux" /></el-checkbox-group></el-form-item></el-col><el-col :span="12"><el-form-item label="Profile 名称前缀"><el-input v-model="roxy.profile_name_prefix" :disabled="running" /></el-form-item></el-col></el-row>
      <div class="check-row"><el-checkbox v-model="roxy.one_profile_per_account" :disabled="running">一号一 Profile</el-checkbox><el-checkbox v-model="roxy.delete_profile_after_run" :disabled="running">运行结束删除 Profile</el-checkbox><el-checkbox v-model="roxy.headless" :disabled="running">无头模式</el-checkbox><el-checkbox v-model="roxy.keep_browser_open" :disabled="running">保留浏览器（调试）</el-checkbox></div>
      <el-row :gutter="10"><el-col :span="12"><el-form-item label="代理检查渠道"><el-input v-model="roxy.proxy_check_channel" :disabled="running" /></el-form-item></el-col><el-col :span="12"><el-form-item label="API 默认端口"><el-input model-value="50000" readonly /></el-form-item></el-col></el-row>
    </div>

    <div class="subsection proxy-section">
      <div class="section-heading-row"><div><h3>Free 独立代理池</h3><p class="section-hint">粘贴后可先检测每条代理的出口 IP、重复 IP 和代理协议，再保存到 Free 池。</p></div><span class="muted">已保存 {{ Number(state.pool?.proxies || 0) }} 个</span></div>
      <el-input v-model="proxyText" type="textarea" :rows="5" :disabled="running" placeholder="每行一个代理 URL 或 主机:端口:用户名:密码" autocomplete="off" />
      <div class="inline-actions"><el-button size="small" :icon="CircleCheck" :loading="busy === 'proxy-preflight'" :disabled="running || !proxyText.trim()" @click="preflightProxyPool">检测出口 IP</el-button><el-button size="small" type="primary" :loading="busy === 'proxy'" :disabled="running || !proxyText.trim()" @click="importProxyPool">保存代理池</el-button><span class="muted">不会消耗邮箱，也不会启动注册</span></div>
      <el-table v-if="proxyCheckRows.length" :data="proxyCheckRows" size="small" height="150" class="proxy-check-table"><el-table-column prop="index" label="#" width="52" /><el-table-column prop="masked" label="代理掩码" min-width="220" /><el-table-column prop="exit_ip" label="出口 IP" min-width="150" /><el-table-column prop="fingerprint" label="指纹" min-width="120" /></el-table>
    </div>

    <div class="settings-actions"><el-button size="small" :loading="busy === 'save'" :disabled="running || busy === 'load'" @click="save">保存 Free 配置</el-button><el-button size="small" :icon="CircleCheck" :loading="busy === 'preflight'" :disabled="running" @click="preflight">注册预检</el-button><el-button size="small" :icon="Refresh" :loading="busy === 'load'" :disabled="running" @click="load">刷新 Free 配置</el-button></div>
  </div>
</template>

<style scoped>
.free-settings-section { min-width: 0; }
.section-heading-row { display: flex; align-items: center; gap: 10px; min-width: 0; }
.section-heading-row > div:first-child { min-width: 0; margin-right: auto; }
.section-title { margin: 0; font-size: 14px; line-height: 20px; font-weight: 680; }
.section-hint, .muted { margin: 2px 0 0; color: var(--el-text-color-secondary); font-size: 12px; line-height: 18px; }
.driver-options { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); width: 100%; gap: 8px; }
.driver-options :deep(.el-radio) { display: grid; gap: 3px; min-height: 58px; height: auto; margin: 0; align-content: center; }
.driver-options strong { font-size: 13px; }
.driver-options small { color: var(--el-text-color-secondary); font-size: 11px; }
.subsection { margin-top: 10px; padding-top: 12px; border-top: 1px solid var(--workspace-border); }
.subsection h3 { margin: 0 0 9px; font-size: 13px; line-height: 20px; }
.subsection h4 { margin: 0; font-size: 12px; font-weight: 650; }
.humanize-heading { display: flex; align-items: center; gap: 7px; margin: 2px 0 8px; }
.check-row { display: flex; flex-wrap: wrap; gap: 4px 16px; margin: 0 0 8px; }
.check-row :deep(.el-checkbox) { margin-right: 0; }
.inline-actions, .settings-actions { display: flex; align-items: center; gap: 8px; margin-top: 8px; }
.settings-actions { justify-content: flex-end; margin-top: 16px; padding-top: 12px; border-top: 1px solid var(--workspace-border); }
.proxy-check-table { margin-top: 8px; }
.free-settings-section :deep(.el-input-number), .free-settings-section :deep(.el-select) { width: 100%; }
.free-settings-section :deep(.el-form-item) { margin-bottom: 10px; }
</style>
