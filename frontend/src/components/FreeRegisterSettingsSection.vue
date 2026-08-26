<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { CircleCheck, Connection, Refresh } from '@element-plus/icons-vue'
import { getFreeConfig, getFreeProxies, getFreeRoxyWorkspaces, preflightFree, preflightFreeProxies, saveFreeConfig, type FreeConfig, type FreeState, type FreeProxyRow } from '../api/client'
import FieldHelpLabel from './FieldHelpLabel.vue'

const emit = defineEmits<{ dirtyChange: [boolean] }>()

const defaultConfig: FreeConfig = {
  driver: 'protocol', flow_profile: 'reference_20260823', proxy_allocation_mode: 'healthy_random', target_count: 1, concurrency: 3, email_code_timeout: 90, auto_set_2fa: true,
  mailbox_network_mode: 'local_proxy', mailbox_proxy_url: 'http://127.0.0.1:7897',
  mailbox_request_retries: 3, mailbox_retry_backoff_seconds: 1,
  proxy_probe_url: 'https://chatgpt.com/', proxy_socks5_dns_mode: 'auto', proxy_tls_verify: true, proxy_tls_compat_fallback: true, protocol: { node_runner: '', sentinel_version: '20260219f9f6', sentinel_timeout: 90, network_timeout: 20, network_preflight_retries: 3, security_challenge_wait_seconds: 60, anonymous_warmup: true, authenticated_warmup: true },
  proxy_default_scheme: 'http', proxy_failure_threshold: 2, proxy_quarantine_seconds: 600, proxy_health_probe_ttl_seconds: 300, proxy_retry_count: 1,
  roxy_circuit_failure_threshold: 3, roxy_circuit_recovery_seconds: 30,
  roxybrowser: {
    api_base: 'http://127.0.0.1:50000', api_key: '', workspace_id: '', project_id: '',
    workspace_list_path: '/browser/workspace', create_path: '/browser/create', open_path: '/browser/open',
    close_path: '/browser/close', delete_path: '/browser/delete', headless: true, force_open: false, keep_browser_open: false,
    one_profile_per_account: true, delete_profile_after_run: true, random_os: true, os_choices: ['Windows', 'macOS'],
    random_profile_name: true, profile_name_prefix: 'rb', selenium_timeout: 90,
    api_retries: 3, api_retry_delay: 2, humanize_delay: true, humanize_factor: 1,
    humanize_browser_actions: true, existing_account_login: true, post_registration_dwell_min: 18, post_registration_dwell_max: 45,
  },
  camoufox: {
    headless: true, pool_size: 2, max_contexts_per_browser: 3, context_start_interval_ms: 175,
    startup_concurrency: 4, block_images: true, registration_timeout_seconds: 600,
    context_close_timeout_seconds: 15, browser_recycle_timeout_seconds: 45,
    browser_recycle_drain_timeout_seconds: 20, max_registrations_per_browser: 12,
    browser_launch_attempts: 3, existing_account_login: true,
  },
}

const config = reactive<FreeConfig>(structuredClone(defaultConfig))
const state = ref<FreeState>({ running: false, tasks: [], summary: {}, pool: {} })
const proxyText = ref('')
const proxyScheme = ref('http')
const proxySourceLabel = ref('')
const layeredProbe = ref(true)
const proxyCheckRows = ref<Array<{ index: number; masked: string; fingerprint: string; scheme?: string; available?: boolean; http_status?: number | null; local_to_proxy_ms?: number | null; proxy_to_target_ms?: number | null; failure_node?: string; failure_reason?: string }>>([])
const proxyRows = ref<FreeProxyRow[]>([])
const workspaces = ref<Array<{ workspace_id: string; workspace_name: string; project_id: string; project_name: string; label: string }>>([])
const busy = ref<'load' | 'save' | 'preflight' | 'proxy-preflight' | 'workspace' | ''>('')
const loaded = ref(false)
const savedSignature = ref('')
const running = computed(() => Boolean(state.value.running))
const pendingRoxyCleanup = computed(() => Math.max(0, Number(state.value.roxy_cleanup?.pending || 0)))
const roxy = computed(() => config.roxybrowser)

function mergeConfig(value: any) {
  if (!value || typeof value !== 'object') return
  Object.assign(config, value)
  Object.assign(config.protocol, value.protocol || {})
  Object.assign(config.roxybrowser, value.roxybrowser || {})
  Object.assign(config.camoufox, value.camoufox || {})
  config.proxy_allocation_mode = 'healthy_random'
  config.target_count = Math.min(200, Math.max(1, Number(config.target_count) || 1))
  config.concurrency = Math.min(16, Math.max(1, Number(config.concurrency) || 1))
}

const proxyStatusLabel = (status: string) => ({ unknown: '未检测', available: '可用', quarantined: '已隔离' }[status] || status || '-')

function draftSignature() {
  return JSON.stringify({
    config,
    proxy_content: proxyText.value,
    proxy_scheme: proxyScheme.value,
    proxy_source_label: proxySourceLabel.value,
  })
}

function markSaved() {
  savedSignature.value = draftSignature()
  emit('dirtyChange', false)
}

watch([config, proxyText, proxyScheme], () => {
  if (loaded.value) emit('dirtyChange', draftSignature() !== savedSignature.value)
}, { deep: true })

async function loadProxies() {
  try {
    const result = await getFreeProxies()
    applyPublicProxies(result.proxies)
  } catch (error: any) {
    ElMessage.error(error?.message || 'Free 代理池加载失败')
  }
}

async function load() {
  busy.value = 'load'
  try {
    const result = await getFreeConfig()
    mergeConfig(result.config)
    state.value = result.state || state.value
    await loadProxies()
    loaded.value = true
    markSaved()
  } catch (error: any) {
    ElMessage.error(error?.message || 'Free 配置加载失败')
  } finally {
    busy.value = ''
  }
}

async function save() {
  if (!loaded.value) throw new Error('Free 配置仍在加载，请稍后再保存')
  busy.value = 'save'
  try {
    const result = await saveFreeConfig({
      ...config,
      proxy_content: proxyText.value,
      proxy_scheme: proxyScheme.value,
      proxy_source_label: proxySourceLabel.value,
    })
    mergeConfig(result.config)
    state.value = result.state || state.value
    const refreshed = applyPublicProxies(result.proxies)
    if (proxyText.value.trim()) proxyText.value = ''
    if (!refreshed) await loadProxies()
    markSaved()
    return result
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
    ElMessage.success(`Free 预检通过：${Number(result.result?.target_count || 0)} 个账号，${Number(result.result?.proxies || 0)} 个代理`)
  } catch (error: any) {
    ElMessage.error(error?.message || 'Free 注册预检失败')
  } finally {
    busy.value = ''
  }
}

async function preflightProxyPool() {
  busy.value = 'proxy-preflight'
  try {
    const result = await preflightFreeProxies(proxyText.value, config.proxy_probe_url, { driver: config.driver, scheme: proxyScheme.value, proxy_socks5_dns_mode: config.proxy_socks5_dns_mode, proxy_tls_verify: config.proxy_tls_verify, proxy_tls_compat_fallback: config.proxy_tls_compat_fallback, layered_probe: layeredProbe.value })
    proxyCheckRows.value = result.result?.rows || []
    const checkedRows = proxyCheckRows.value
    const available = checkedRows.filter(row => row.available).length
    const failed = checkedRows.length - available
    if (failed) ElMessage.warning(`代理连通性检测完成：可用 ${available} 个，失败 ${failed} 个`)
    else ElMessage.success(`代理连通性检测通过：${available} 个`)
  } catch (error: any) {
    proxyCheckRows.value = []
    ElMessage.error(error?.message || 'Free 代理连通性检测失败')
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
  const item = workspaces.value.find(row => workspaceValue(row) === value)
  if (!item) return
  config.roxybrowser.workspace_id = item.workspace_id
  config.roxybrowser.project_id = item.project_id
}

function workspaceValue(row: { workspace_id: string; project_id: string }) {
  return `${row.workspace_id}/${row.project_id}`
}

function applyPublicProxies(value: any) {
  if (!value || typeof value !== 'object') return false
  proxyRows.value = Array.isArray(value.rows) ? value.rows : []
  if (Number.isFinite(Number(value.count))) {
    state.value = {
      ...state.value,
      pool: { ...(state.value.pool || {}), proxies: Number(value.count) },
    }
  }
  return true
}

onMounted(load)

defineExpose({ save })
</script>

<template>
  <div class="free-settings-section">
    <div class="section-heading-row">
      <div>
        <h2 class="section-title">Free 注册运行配置</h2>
        <p class="section-hint">与接码机的目标数、并发、邮箱池、代理池和运行状态完全隔离。</p>
      </div>
      <el-tag v-if="running" type="success" effect="light">Free 注册运行中</el-tag>
      <el-tag v-else-if="pendingRoxyCleanup > 0" type="warning" effect="light">待清理 Profile {{ pendingRoxyCleanup }}</el-tag>
      <el-tag v-else type="info" effect="plain">独立 Free 链路</el-tag>
    </div>

    <el-form-item>
      <template #label><FieldHelpLabel label="注册链路" help="全协议直接调用认证接口；RoxyBrowser 使用独立 Profile；Camoufox 使用共享浏览器进程中的独立 context。三条链路共用同一个 URL 邮箱池和取件策略。" /></template>
      <el-radio-group v-model="config.driver" :disabled="running || busy === 'load'" class="driver-options">
        <el-radio value="protocol" border><strong>全协议</strong><small>OAuth、邮箱 OTP 和套餐检查</small></el-radio>
        <el-radio value="roxybrowser" border><strong>RoxyBrowser</strong><small>独立 Profile、任务代理和 Selenium 页面注册</small></el-radio>
        <el-radio value="camoufox" border><strong>Camoufox</strong><small>异步共享浏览器池、独立 context 和同源 Session</small></el-radio>
      </el-radio-group>
    </el-form-item>

    <div class="selection-summary shared-proxy-summary">
      <span>共享健康随机代理池</span>
      <b>{{ Number(state.pool?.proxies || 0) }}</b>
      <small>任务共享健康随机代理；连接观测变化不会阻断健康任务</small>
    </div>

    <el-row :gutter="10">
      <el-col :span="12"><el-form-item><template #label><FieldHelpLabel label="流程配置" help="默认使用参考项目 2026-08-23 的 RoxyBrowser 与全协议状态机；遇到兼容问题时可临时切回旧流程，便于回滚定位。" /></template><el-select v-model="config.flow_profile" :disabled="running"><el-option label="参考流程（推荐）" value="reference_20260823" /><el-option label="旧流程（回滚）" value="legacy" /></el-select></el-form-item></el-col>
      <el-col :span="12"><el-form-item><template #label><FieldHelpLabel label="代理分配方式" help="按 AutoRegister 使用健康代理随机分配，多个并发任务可以共享同一代理；不比较或锁定出口地址。" /></template><el-tag type="success" effect="plain">健康随机共享池</el-tag></el-form-item></el-col>
    </el-row>

    <el-row :gutter="10">
      <el-col :span="8"><el-form-item><template #label><FieldHelpLabel label="Free 注册数量（1-200）" help="本批最多启动的 Free 账号数。Free 注册中心启动条使用并保存同一个数值。" /></template><el-input-number v-model="config.target_count" class="free-scale-number" :min="1" :max="200" controls-position="right" :disabled="running" /></el-form-item></el-col>
      <el-col :span="8"><el-form-item><template #label><FieldHelpLabel label="Free 并发数（1-16）" help="配置允许同时运行的 Free 注册任务数；运行时可能因协议压力控制或 Roxy 熔断降低实际并发。" /></template><el-input-number v-model="config.concurrency" class="free-scale-number" :min="1" :max="16" controls-position="right" :disabled="running" /></el-form-item></el-col>
      <el-col :span="8"><el-form-item><template #label><FieldHelpLabel label="邮箱 OTP 超时（秒）" help="注册流程等待邮箱验证码的最长时间。启用自动动态口令后，第二封 OTP 也使用这项超时。" /></template><el-input-number v-model="config.email_code_timeout" :min="10" :max="600" controls-position="right" :disabled="running" /></el-form-item></el-col>
    </el-row>
    <el-form-item><template #label><FieldHelpLabel label="代理连通性目标地址" help="手动检测时通过每条待用代理访问该地址，只确认代理请求和 HTTP 响应是否建立；不会解析、保存或展示账号出口 IP。" /></template><el-input v-model="config.proxy_probe_url" :disabled="running" placeholder="https://chatgpt.com/" /></el-form-item>
    <div class="check-row proxy-tls-options"><el-checkbox v-model="config.proxy_tls_verify" :disabled="running"><FieldHelpLabel label="严格校验探测站证书" help="默认按标准 TLS 证书校验访问探测地址。关闭后只影响连通性探测，不会改代理协议、不会切换节点，也不会影响浏览器页面证书校验。" /></el-checkbox><el-checkbox v-model="config.proxy_tls_compat_fallback" :disabled="running || !config.proxy_tls_verify"><FieldHelpLabel label="TLS/CONNECT 兼容重试" help="严格校验遇到明确证书错误时，用同一代理和同一协议再试一次；协议不匹配不会走证书兼容重试。" /></el-checkbox></div>
    <el-form-item><template #label><FieldHelpLabel label="注册后安全设置" help="Free 注册固定启用 2FA。注册完成会再等待一封邮箱 OTP，执行 TOTP enrollment 和 activation 并保存动态口令密钥；失败时保留 Token，账号进入 2FA 待重试。" /></template><el-checkbox v-model="config.auto_set_2fa" disabled>注册完成后自动设置动态口令（必需）</el-checkbox></el-form-item>

    <div class="subsection mailbox-network-section">
      <div class="humanize-heading"><h3>邮箱 OTP 取件网络</h3><FieldHelpLabel label="网络隔离说明" help="这里只控制邮箱取件 URL 的网络，不会使用账号注册代理，也不会改变浏览器 Profile。" /><el-tag size="small" type="info" effect="plain">与注册代理分离</el-tag></div>
      <el-form-item>
        <template #label><FieldHelpLabel label="取件方式" help="本机代理适合通过 Clash Verge 访问邮箱服务，默认使用 127.0.0.1:7897；直连则完全不使用代理。两种方式都不会继承系统环境代理。" /></template>
        <el-radio-group v-model="config.mailbox_network_mode" :disabled="running">
          <el-radio value="local_proxy" border>本机代理</el-radio>
          <el-radio value="direct" border>直连</el-radio>
        </el-radio-group>
      </el-form-item>
      <el-row :gutter="10">
        <el-col :span="12"><el-form-item><template #label><FieldHelpLabel label="本机取件代理" help="Free 邮箱取件专用代理。默认是当前 Mac 的 Clash Verge HTTP 代理 http://127.0.0.1:7897；支持 HTTP、HTTPS、SOCKS5 和 SOCKS5H 完整地址。" /></template><el-input v-model="config.mailbox_proxy_url" :disabled="running || config.mailbox_network_mode === 'direct'" placeholder="http://127.0.0.1:7897" /></el-form-item></el-col>
        <el-col :span="6"><el-form-item><template #label><FieldHelpLabel label="网络额外重试次数" help="邮箱取件遇到 SSL、连接超时、429 或 5xx 时的额外重试次数。401、403、404 和响应格式错误不会盲目重试。" /></template><el-input-number v-model="config.mailbox_request_retries" :min="0" :max="5" controls-position="right" :disabled="running" /></el-form-item></el-col>
        <el-col :span="6"><el-form-item><template #label><FieldHelpLabel label="重试退避（秒）" help="两次邮箱取件网络请求之间的基础等待时间，后续尝试会按次数递增。" /></template><el-input-number v-model="config.mailbox_retry_backoff_seconds" :min="0" :max="15" :step="0.25" controls-position="right" :disabled="running" /></el-form-item></el-col>
      </el-row>
      <p class="section-hint">注册页面继续固定使用账号住宅代理；邮箱取件只使用这里保存的网络方式。</p>
    </div>

    <div class="subsection">
      <div class="humanize-heading"><h3>代理稳定性策略</h3><FieldHelpLabel label="规则说明" help="这些规则只作用于独立 Free 代理池：控制注册前可否更换备用代理、连续失败隔离，以及 RoxyBrowser 基础设施异常时停止新任务。" /></div>
      <el-row :gutter="10">
        <el-col :span="8"><el-form-item><template #label><FieldHelpLabel label="代理额外重试次数" help="进入注册页面前，原代理连接失败后允许的额外重试次数；进入注册页面后不因观测地址变化更换代理。" /></template><el-input-number v-model="config.proxy_retry_count" :min="0" :max="5" controls-position="right" :disabled="running" /></el-form-item></el-col>
        <el-col :span="8"><el-form-item><template #label><FieldHelpLabel label="连续失败隔离阈值" help="同一代理连续失败达到此次数后进入隔离，当前批次不再分配它。成功探测会清零连续失败次数。" /></template><el-input-number v-model="config.proxy_failure_threshold" :min="1" :max="10" controls-position="right" :disabled="running" /></el-form-item></el-col>
        <el-col :span="8"><el-form-item><template #label><FieldHelpLabel label="代理隔离时间（秒）" help="代理达到失败阈值后的暂停使用时间。到期后可重新参与检测和任务分配。" /></template><el-input-number v-model="config.proxy_quarantine_seconds" :min="30" :max="86400" controls-position="right" :disabled="running" /></el-form-item></el-col>
      </el-row>
      <el-row :gutter="10">
        <el-col :span="12"><el-form-item><template #label><FieldHelpLabel label="Roxy 熔断失败阈值" help="Roxy API、工作区、Profile 打开或 Selenium 连接等基础设施错误连续达到此次数后，暂停启动新的 Roxy 任务。页面业务错误不会触发。" /></template><el-input-number v-model="config.roxy_circuit_failure_threshold" :min="1" :max="10" controls-position="right" :disabled="running" /></el-form-item></el-col>
        <el-col :span="12"><el-form-item><template #label><FieldHelpLabel label="Roxy 熔断恢复等待（秒）" help="Roxy 批次打开熔断后等待的恢复时间。熔断只影响当前 Free RoxyBrowser 批次，不影响全协议和普通接码任务。" /></template><el-input-number v-model="config.roxy_circuit_recovery_seconds" :min="0" :max="3600" controls-position="right" :disabled="running" /></el-form-item></el-col>
      </el-row>
      <el-row :gutter="10">
        <el-col :span="12"><el-form-item><template #label><FieldHelpLabel label="健康探测有效期（秒）" help="代理最近一次成功探测在这段时间内直接复用；超过后仅在绑定前执行一次有界连通性探测。设为 0 可关闭自动刷新，保留手动代理检测。" /></template><el-input-number v-model="config.proxy_health_probe_ttl_seconds" :min="0" :max="86400" controls-position="right" :disabled="running" /></el-form-item></el-col>
      </el-row>
    </div>

    <div v-if="config.driver === 'protocol'" class="subsection">
      <h3>全协议专属配置</h3>
      <el-row :gutter="10">
        <el-col :span="16"><el-form-item><template #label><FieldHelpLabel label="Node / Sentinel Runner" help="全协议链路使用的本地 Node/Sentinel 执行器。留空时沿用运行时默认路径，RoxyBrowser 链路不会读取这项。" /></template><el-input v-model="config.protocol.node_runner" placeholder="留空使用运行时默认配置" :disabled="running" /></el-form-item></el-col>
        <el-col :span="8"><el-form-item><template #label><FieldHelpLabel label="Sentinel 超时（秒）" help="全协议链路等待 Sentinel 初始化和响应的最长时间，超时后任务在对应节点失败。" /></template><el-input-number v-model="config.protocol.sentinel_timeout" :min="10" :max="300" controls-position="right" :disabled="running" /></el-form-item></el-col>
      </el-row>
      <el-row :gutter="10">
        <el-col :span="6"><el-form-item><template #label><FieldHelpLabel label="网络预检重试" help="ChatGPT、Auth 和 Sentinel 预检的额外尝试次数；每次仍使用同一任务代理。" /></template><el-input-number v-model="config.protocol.network_preflight_retries" :min="1" :max="5" controls-position="right" :disabled="running" /></el-form-item></el-col>
        <el-col :span="6"><el-form-item><template #label><FieldHelpLabel label="网络超时（秒）" help="全协议预检和匿名预热的单次网络请求超时。" /></template><el-input-number v-model="config.protocol.network_timeout" :min="5" :max="60" controls-position="right" :disabled="running" /></el-form-item></el-col>
        <el-col :span="6"><el-form-item><template #label><FieldHelpLabel label="安全挑战等待（秒）" help="同一会话和代理等待 Cloudflare/安全挑战自然解除的最长时间；不会自动绕过或切换代理。" /></template><el-input-number v-model="config.protocol.security_challenge_wait_seconds" :min="0" :max="60" controls-position="right" :disabled="running" /></el-form-item></el-col>
      </el-row>
      <div class="check-row"><el-checkbox v-model="config.protocol.anonymous_warmup" :disabled="running">匿名态预热</el-checkbox><el-checkbox v-model="config.protocol.authenticated_warmup" :disabled="running">认证态预热</el-checkbox></div>
    </div>
    <div v-if="config.driver === 'camoufox'" class="subsection">
      <h3>Camoufox 浏览器池</h3>
      <el-row :gutter="10">
        <el-col :span="6"><el-form-item label="模式"><el-switch v-model="config.camoufox.headless" active-text="无头" inactive-text="有头" :disabled="running" /></el-form-item></el-col>
        <el-col :span="6"><el-form-item label="浏览器进程"><el-input-number v-model="config.camoufox.pool_size" :min="1" :max="16" controls-position="right" :disabled="running" /></el-form-item></el-col>
        <el-col :span="6"><el-form-item label="每进程 context"><el-input-number v-model="config.camoufox.max_contexts_per_browser" :min="1" :max="32" controls-position="right" :disabled="running" /></el-form-item></el-col>
        <el-col :span="6"><el-form-item label="注册超时"><el-input-number v-model="config.camoufox.registration_timeout_seconds" :min="60" :max="3600" controls-position="right" :disabled="running" /></el-form-item></el-col>
      </el-row>
      <el-row :gutter="10">
        <el-col :span="8"><el-form-item label="context 关闭超时"><el-input-number v-model="config.camoufox.context_close_timeout_seconds" :min="1" :max="120" controls-position="right" :disabled="running" /></el-form-item></el-col>
        <el-col :span="8"><el-form-item label="进程回收超时"><el-input-number v-model="config.camoufox.browser_recycle_timeout_seconds" :min="5" :max="300" controls-position="right" :disabled="running" /></el-form-item></el-col>
        <el-col :span="8"><el-form-item label="单进程最大注册数"><el-input-number v-model="config.camoufox.max_registrations_per_browser" :min="1" :max="1000" controls-position="right" :disabled="running" /></el-form-item></el-col>
      </el-row>
      <div class="check-row"><el-checkbox v-model="config.camoufox.block_images" :disabled="running">无头模式阻止图片加载</el-checkbox><el-checkbox v-model="config.camoufox.existing_account_login" :disabled="running">允许已有账号邮箱验证码登录</el-checkbox></div>
      <p class="section-hint">Camoufox 是可选依赖；未安装时预检会明确提示，不影响全协议和 RoxyBrowser。</p>
    </div>

    <div v-if="config.driver === 'roxybrowser'" class="subsection">
      <div class="section-heading-row"><h3>RoxyBrowser 专属配置</h3><el-button size="small" :icon="Connection" :loading="busy === 'workspace'" :disabled="running" @click="loadWorkspaces">读取工作区</el-button></div>
      <el-row :gutter="10">
        <el-col :span="12"><el-form-item><template #label><FieldHelpLabel label="API 地址" help="本机 RoxyBrowser API 服务地址，默认端口 50000。这里只连接本机控制接口，不是代理地址。" /></template><el-input v-model="roxy.api_base" :disabled="running" /></el-form-item></el-col>
        <el-col :span="12"><el-form-item><template #label><FieldHelpLabel label="API Key" help="RoxyBrowser 本地 API 的访问密钥。保存后只显示掩码，不会出现在列表或日志中。" /></template><el-input v-model="roxy.api_key" type="password" show-password placeholder="留空或保持已保存密钥" :disabled="running" /></el-form-item></el-col>
      </el-row>
      <el-form-item><template #label><FieldHelpLabel label="工作区 / 项目" help="临时注册 Profile 将创建在这里。先读取工作区再选择，系统会同步填入下方 Workspace ID 和 Project ID。保存时使用稳定的 ID，不依赖显示名称。" /></template><el-select :model-value="workspaces.find(row => row.workspace_id === roxy.workspace_id && row.project_id === roxy.project_id) ? workspaceValue({ workspace_id: roxy.workspace_id, project_id: roxy.project_id }) : ''" clearable filterable placeholder="读取后选择" :disabled="running" @change="applyWorkspace"><el-option v-for="item in workspaces" :key="workspaceValue(item)" :label="item.label" :value="workspaceValue(item)" /></el-select></el-form-item>
      <el-row :gutter="10">
        <el-col :span="12"><el-form-item><template #label><FieldHelpLabel label="Workspace ID" help="RoxyBrowser 工作区标识。通常由“读取工作区”自动填写，也可以按本地 API 返回值手动输入。" /></template><el-input v-model="roxy.workspace_id" :disabled="running" /></el-form-item></el-col>
        <el-col :span="12"><el-form-item><template #label><FieldHelpLabel label="Project ID" help="工作区下的项目标识；本地 RoxyBrowser API 不要求项目时可以留空。" /></template><el-input v-model="roxy.project_id" :disabled="running" /></el-form-item></el-col>
      </el-row>
      <el-row :gutter="10">
        <el-col :span="8"><el-form-item><template #label><FieldHelpLabel label="Selenium 超时（秒）" help="等待 RoxyBrowser 窗口打开、连接以及关键页面元素出现的超时上限。" /></template><el-input-number v-model="roxy.selenium_timeout" :min="10" :max="300" controls-position="right" :disabled="running" /></el-form-item></el-col>
        <el-col :span="8"><el-form-item><template #label><FieldHelpLabel label="API 重试次数" help="RoxyBrowser 本地 API 遇到可重试的连接或服务错误时，最多请求的次数。Profile 创建不会盲目重复创建。" /></template><el-input-number v-model="roxy.api_retries" :min="1" :max="5" controls-position="right" :disabled="running" /></el-form-item></el-col>
        <el-col :span="8"><el-form-item><template #label><FieldHelpLabel label="API 重试间隔（秒）" help="RoxyBrowser API 两次重试之间的基础等待时间，后续尝试会按次数延长。" /></template><el-input-number v-model="roxy.api_retry_delay" :min="0.25" :max="15" :step="0.25" controls-position="right" :disabled="running" /></el-form-item></el-col>
      </el-row>
      <div class="humanize-heading"><h4>人工节奏与浏览器动作</h4><FieldHelpLabel label="说明" help="为并发任务加入错峰、随机输入和点击间隔，减少固定节拍导致的页面竞态。它只改善稳定性，不保证第三方平台接受注册。" /><el-tag size="small" type="success" effect="plain">默认开启</el-tag></div>
      <el-row :gutter="10">
        <el-col :span="8"><el-form-item><template #label><FieldHelpLabel label="人工节奏倍率" help="统一放大或缩小随机点击、输入和页面等待时间。1.0 使用默认节奏；数值越大整体越慢。" /></template><el-input-number v-model="roxy.humanize_factor" :min="0.1" :max="5" :step="0.1" controls-position="right" :disabled="running" /></el-form-item></el-col>
        <el-col :span="8"><el-form-item><template #label><FieldHelpLabel label="注册后停留最短（秒）" help="注册、套餐查询和可选 2FA 完成后，关闭临时 Profile 前随机停留的最短时间。" /></template><el-input-number v-model="roxy.post_registration_dwell_min" :min="0" :max="300" controls-position="right" :disabled="running" /></el-form-item></el-col>
        <el-col :span="8"><el-form-item><template #label><FieldHelpLabel label="注册后停留最长（秒）" help="注册完成后的随机停留上限，实际时间会在最短值与最长值之间选择。" /></template><el-input-number v-model="roxy.post_registration_dwell_max" :min="0" :max="600" controls-position="right" :disabled="running" /></el-form-item></el-col>
      </el-row>
      <div class="check-row"><el-checkbox v-model="roxy.humanize_delay" :disabled="running">启用人工节奏</el-checkbox><el-checkbox v-model="roxy.humanize_browser_actions" :disabled="running">随机页面动作</el-checkbox><el-checkbox v-model="roxy.random_os" :disabled="running">随机系统</el-checkbox><el-checkbox v-model="roxy.random_profile_name" :disabled="running">随机 Profile 名称</el-checkbox></div>
      <el-form-item>
        <template #label><FieldHelpLabel label="已有账号登录兜底" help="当注册邮箱被认证页识别为已有账号并进入登录密码页时，自动点击“使用一次性验证码”，继续用该任务绑定的邮箱和代理登录。成功后只保存 Token、套餐和 2FA，不会把统一注册密码误存为已有账号密码。" /></template>
        <el-checkbox v-model="roxy.existing_account_login" :disabled="running">已有账号自动切换邮箱验证码登录</el-checkbox>
      </el-form-item>
      <el-row v-if="roxy.random_os" :gutter="10"><el-col :span="12"><el-form-item><template #label><FieldHelpLabel label="随机系统范围" help="创建每个临时 Profile 时从勾选项中随机选择浏览器指纹系统，不改变本机操作系统。" /></template><el-checkbox-group v-model="roxy.os_choices" :disabled="running"><el-checkbox label="Windows" /><el-checkbox label="macOS" /><el-checkbox label="Linux" /></el-checkbox-group></el-form-item></el-col><el-col :span="12"><el-form-item><template #label><FieldHelpLabel label="Profile 名称前缀" help="临时 RoxyBrowser Profile 名称的固定前缀，后面会追加时间和随机标记，便于识别本程序创建的窗口。" /></template><el-input v-model="roxy.profile_name_prefix" :disabled="running" /></el-form-item></el-col></el-row>
      <div class="humanize-heading"><FieldHelpLabel label="Profile 生命周期" help="默认每个账号创建一个临时 Profile，并在完成或失败后关闭和删除。保留浏览器仅用于诊断，会跳过正常清理；无头模式默认开启，浏览器在后台运行，不显示可见窗口。" /></div>
      <div class="check-row"><el-checkbox v-model="roxy.one_profile_per_account" :disabled="running">一号一 Profile</el-checkbox><el-checkbox v-model="roxy.delete_profile_after_run" :disabled="running">运行结束删除 Profile</el-checkbox><el-checkbox v-model="roxy.headless" :disabled="running">无头模式（默认开启）</el-checkbox><el-checkbox v-model="roxy.keep_browser_open" :disabled="running">保留浏览器（调试）</el-checkbox></div>
      <el-row :gutter="10"><el-col :span="12"><el-form-item><template #label><FieldHelpLabel label="API 默认端口" help="RoxyBrowser 本地 API 的默认监听端口，固定显示 50000；实际访问地址以上方 API 地址为准。" /></template><el-input model-value="50000" readonly /></el-form-item></el-col></el-row>
    </div>

    <div class="subsection proxy-section">
      <div class="section-heading-row"><div><h3>Free 独立代理池</h3><p class="section-hint">粘贴后可先检测每条代理的连通性和声明协议，再保存到 Free 池。</p></div><span class="muted">已保存 {{ Number(state.pool?.proxies || 0) }} 个</span></div>
      <div class="proxy-import-meta">
        <div class="proxy-import-field"><FieldHelpLabel label="无协议默认协议" help="支持 scheme://用户名:密码@主机:端口、主机:端口:用户名:密码、用户名:密码@主机:端口、主机:端口@用户名:密码；裸格式按当前下拉协议解析，显式协议始终优先。" /><el-select v-model="proxyScheme" placeholder="无协议时默认协议"><el-option label="HTTP" value="http" /><el-option label="HTTPS" value="https" /><el-option label="SOCKS4" value="socks4" /><el-option label="SOCKS5" value="socks5" /><el-option label="SOCKS5H" value="socks5h" /></el-select></div>
        <div class="proxy-import-field"><FieldHelpLabel label="SOCKS5 DNS" help="只影响 SOCKS5 代理的域名解析位置，不改变保存的协议标签。自动模式检测到 Clash Fake-IP 时使用代理端解析，普通网络保留本机解析。" /><el-select v-model="config.proxy_socks5_dns_mode" :disabled="running"><el-option label="自动适配" value="auto" /><el-option label="本机解析" value="local" /><el-option label="代理端解析" value="remote" /><el-option label="严格声明" value="declared" /></el-select></div>
        <div class="proxy-import-field"><FieldHelpLabel label="代理来源（可选）" help="仅用于报表和供应商对比，例如 1024、cliproxy；不会参与代理分配，也不会写入代理凭据。" /><el-input v-model="proxySourceLabel" maxlength="40" show-word-limit placeholder="例如 1024 / cliproxy" /></div>
      </div>
      <el-input v-model="proxyText" type="textarea" :rows="5" :disabled="running" placeholder="每行一个代理，支持 URL、host:port:user:pass 和两种 @ 格式" autocomplete="off" />
      <div class="inline-actions"><el-button size="small" :icon="CircleCheck" :loading="busy === 'proxy-preflight'" :disabled="running || !proxyText.trim()" @click="preflightProxyPool">检测代理连通性</el-button><el-checkbox v-model="layeredProbe" :disabled="running">分层诊断</el-checkbox><span class="muted">分层诊断会额外记录 TCP、HTTPS 和 ChatGPT 登录页耗时，不保存响应正文。</span></div>
      <template v-if="proxyCheckRows.length"><div class="proxy-table-heading"><FieldHelpLabel label="本次检测结果" help="仅展示声明协议、脱敏地址、响应状态和耗时；检测不解析、保存或比较出口 IP。" /></div><el-table :data="proxyCheckRows" size="small" height="180" class="proxy-check-table"><el-table-column type="index" label="序号" width="58" align="center" fixed="left" /><el-table-column prop="masked" label="代理掩码" min-width="220" /><el-table-column prop="scheme" label="协议" width="85" /><el-table-column label="状态" width="75"><template #default="{ row }"><el-tag size="small" :type="row.available ? 'success' : 'danger'">{{ row.available ? '可用' : '失败' }}</el-tag></template></el-table-column><el-table-column prop="http_status" label="HTTP" width="70" /><el-table-column label="耗时" width="170"><template #default="{ row }"><span v-if="row.layered_probe">TCP {{ row.layered_probe.tcp_connect_ms ?? '-' }} ms · HTTPS {{ row.layered_probe.https_request_ms ?? '-' }} ms · 登录 {{ row.layered_probe.chatgpt_request_ms ?? '-' }} ms</span><span v-else>{{ row.proxy_to_target_ms != null ? `${row.proxy_to_target_ms} ms` : '-' }}</span></template></el-table-column><el-table-column prop="failure_node" label="故障节点" min-width="150" /><el-table-column prop="fingerprint" label="指纹" min-width="120" /></el-table></template>
      <template v-if="proxyRows.length"><div class="proxy-table-heading"><FieldHelpLabel label="代理明细" help="已保存共享 Free 代理池的逐条记录。用于查看来源、声明/有效协议、健康状态、成功率和延迟；认证信息始终隐藏。" /></div><el-table :data="proxyRows" size="small" height="180" class="proxy-check-table"><el-table-column type="index" label="序号" width="58" align="center" fixed="left" /><el-table-column prop="source_label" label="来源" width="100" show-overflow-tooltip /><el-table-column label="协议" width="125"><template #default="{ row }">{{ row.declared_scheme || row.scheme || '-' }}<small class="table-subline">有效 {{ row.effective_scheme || row.scheme || '-' }}</small></template></el-table-column><el-table-column prop="masked" label="代理" min-width="210" show-overflow-tooltip /><el-table-column width="85"><template #header><FieldHelpLabel label="状态" help="未检测表示尚无成功探测；可用表示最近探测成功；已隔离表示连续失败达到阈值，隔离期内不会分配。" /></template><template #default="{ row }">{{ proxyStatusLabel(row.status) }}</template></el-table-column><el-table-column label="成功率" width="90"><template #default="{ row }">{{ row.probe_success_rate == null ? '-' : `${(Number(row.probe_success_rate) * 100).toFixed(1)}%` }}</template></el-table-column><el-table-column label="p50 / p95" width="105"><template #default="{ row }">{{ row.p50_latency_ms == null ? '-' : `${row.p50_latency_ms} / ${row.p95_latency_ms ?? '-'} ms` }}</template></el-table-column><el-table-column prop="last_probe_mode" label="探测模式" width="90"><template #default="{ row }">{{ row.last_probe_mode === 'compat' ? '兼容重试' : row.last_probe_mode === 'strict' ? '严格校验' : '-' }}</template></el-table-column><el-table-column prop="consecutive_failures" label="连续失败" width="85" /></el-table></template>
    </div>

    <div class="settings-actions"><el-button size="small" :icon="CircleCheck" :loading="busy === 'preflight'" :disabled="running" @click="preflight">注册预检</el-button><el-button size="small" :icon="Refresh" :loading="busy === 'load'" :disabled="running" @click="load">刷新 Free 配置</el-button></div>
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
.proxy-selection-grid { display: grid; grid-template-columns: minmax(220px, 1fr) minmax(260px, 1fr) 150px; gap: 10px; align-items: end; margin-bottom: 4px; }
.selection-summary { display: flex; flex-direction: column; min-height: 58px; justify-content: center; padding: 8px 12px; border: 1px solid var(--workspace-border); color: var(--el-text-color-secondary); }
.selection-summary b { color: var(--el-text-color-primary); font-size: 19px; line-height: 22px; }
.selection-summary small { font-size: 11px; }
.subsection { margin-top: 10px; padding-top: 12px; border-top: 1px solid var(--workspace-border); }
.subsection h3 { margin: 0 0 9px; font-size: 13px; line-height: 20px; }
.subsection h4 { margin: 0; font-size: 12px; font-weight: 650; }
.humanize-heading { display: flex; align-items: center; gap: 7px; margin: 2px 0 8px; }
.check-row { display: flex; flex-wrap: wrap; gap: 4px 16px; margin: 0 0 8px; }
.check-row :deep(.el-checkbox) { margin-right: 0; }
.inline-actions, .settings-actions { display: flex; align-items: center; gap: 8px; margin-top: 8px; }
.settings-actions { justify-content: flex-end; margin-top: 16px; padding-top: 12px; border-top: 1px solid var(--workspace-border); }
.proxy-check-table { margin-top: 8px; }
.proxy-import-meta { display: grid; grid-template-columns: 180px minmax(180px, 1fr) minmax(180px, 1fr); gap: 8px; margin-bottom: 8px; }
.proxy-import-field { display: grid; gap: 5px; min-width: 0; }
.proxy-table-heading { display: flex; align-items: center; margin: 12px 0 -2px; color: var(--el-text-color-regular); font-size: 12px; font-weight: 650; }
.table-subline { display: block; color: var(--el-text-color-secondary); font-size: 10px; line-height: 14px; }
.free-settings-section :deep(.el-input-number), .free-settings-section :deep(.el-select) { width: 100%; }
.free-settings-section :deep(.free-scale-number) { width: 132px; max-width: 100%; }
.free-settings-section :deep(.el-form-item) { margin-bottom: 10px; }
</style>
