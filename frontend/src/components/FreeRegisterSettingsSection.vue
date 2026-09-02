<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { CircleCheck, CopyDocument, Refresh, View } from '@element-plus/icons-vue'
import { getFreeConfig, getFreeProxies, preflightFree, preflightFreeProxies, saveFreeConfig, type FreeConfig, type FreeState, type FreeProxyPreflightRow, type FreeProxyRow } from '../api/client'
import type { TaskFailure } from '../types/api'
import FieldHelpLabel from './FieldHelpLabel.vue'

const emit = defineEmits<{ dirtyChange: [boolean]; navigate: [string] }>()

const defaultConfig: FreeConfig = {
  driver: 'protocol', flow_profile: 'reference_20260823', proxy_allocation_mode: 'healthy_random', target_count: 1, concurrency: 3, email_code_timeout: 90, account_password: 'Aa150010150010', auto_set_password: false, auto_set_2fa: true,
  mailbox_network_mode: 'local_proxy', mailbox_proxy_url: 'http://127.0.0.1:7897',
  mailbox_request_retries: 3, mailbox_retry_backoff_seconds: 1,
  proxy_probe_url: 'https://chatgpt.com/', proxy_socks5_dns_mode: 'remote', proxy_tls_verify: true, proxy_tls_compat_fallback: true, protocol: { node_runner: '', sentinel_version: '20260219f9f6', sentinel_timeout: 90, network_timeout: 20, network_preflight_retries: 3, security_challenge_wait_seconds: 60, anonymous_warmup: true, authenticated_warmup: true },
  proxy_default_scheme: 'socks5', proxy_failure_threshold: 2, proxy_quarantine_seconds: 600, proxy_health_probe_ttl_seconds: 300, proxy_retry_count: 1,
  camoufox: {
    debug_mode: true, headless: true, pool_size: 2, max_contexts_per_browser: 3, context_start_interval_ms: 175,
    startup_concurrency: 4, block_images: true, registration_timeout_seconds: 600,
    context_close_timeout_seconds: 15, browser_recycle_timeout_seconds: 45,
    browser_recycle_drain_timeout_seconds: 20, max_registrations_per_browser: 12,
    browser_launch_attempts: 3, existing_account_login: true,
  },
  remail: { enabled: false, base_url: 'https://remail.aishop6.com', api_key: '', project_id: '', supply_policy: 'private_first', request_timeout_seconds: 20, catalog_cache_seconds: 60, order_sync_enabled: false, order_sync_interval_minutes: 30, auto_import_new_purchase_orders: false },
}

const config = reactive<FreeConfig>(structuredClone(defaultConfig))
const state = ref<FreeState>({ running: false, tasks: [], summary: {}, pool: {} })
const proxyText = ref('')
const proxyScheme = ref(defaultConfig.proxy_default_scheme)
const proxySourceLabel = ref('')
const layeredProbe = ref(false)
const proxyCheckRows = ref<FreeProxyPreflightRow[]>([])
const proxyCheckIncidentId = ref('')
const proxyCheckFailure = ref<TaskFailure | null>(null)
const proxyRows = ref<FreeProxyRow[]>([])
const busy = ref<'load' | 'save' | 'preflight' | 'proxy-preflight' | ''>('')
const loaded = ref(false)
const savedSignature = ref('')
const running = computed(() => Boolean(state.value.running))
const camoufoxEffectiveHeadless = computed(() => Boolean(config.camoufox.debug_mode) ? false : Boolean(config.camoufox.headless))
const savedProxyAvailable = computed(() => proxyRows.value.filter(row => row.status === 'available').length)
const savedProxyQuarantined = computed(() => proxyRows.value.filter(row => row.status === 'quarantined').length)
const proxyCheckSummary = computed(() => {
  const total = proxyCheckRows.value.length
  if (!total) return ''
  const available = proxyCheckRows.value.filter(row => row.available).length
  return `最近检测 ${total} 个：可用 ${available} · 失败 ${total - available}`
})

function mergeConfig(value: any) {
  if (!value || typeof value !== 'object') return
  Object.assign(config, value)
  // Strip removed legacy fields from old responses before they can be
  // persisted again by the save payload.
  const draft = config as Record<string, unknown>
  delete draft.roxybrowser
  delete draft.roxy_circuit_failure_threshold
  delete draft.roxy_circuit_recovery_seconds
  delete draft.roxy_api_key
  delete draft.roxy_workspace_id
  const proxySelection = draft.proxy_selection
  if (proxySelection && typeof proxySelection === 'object') {
    delete (proxySelection as Record<string, unknown>).roxybrowser
  }
  Object.assign(config.protocol, value.protocol || {})
  Object.assign(config.camoufox, value.camoufox || {})
  if (!['protocol', 'camoufox'].includes(String(config.driver || '').trim().toLowerCase())) {
    config.driver = 'protocol'
  }
  if (typeof config.proxy_default_scheme === 'string' && config.proxy_default_scheme.trim()) {
    proxyScheme.value = config.proxy_default_scheme.trim().toLowerCase()
  }
  config.proxy_allocation_mode = 'healthy_random'
  config.target_count = Math.min(200, Math.max(1, Number(config.target_count) || 1))
  config.concurrency = Math.min(16, Math.max(1, Number(config.concurrency) || 1))
}

function updateCamoufoxHeadless(value: boolean) {
  // Keep the user's preference in the persisted config. Debug mode exposes a
  // headed browser regardless of that preference and the control is disabled.
  if (!config.camoufox.debug_mode) config.camoufox.headless = Boolean(value)
}

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
    // The selector is the user-facing editor for the persisted default used
    // when importing protocol-less proxy rows. Keep the legacy proxy_scheme
    // request field as well for API compatibility.
    config.proxy_default_scheme = proxyScheme.value
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
    proxyCheckIncidentId.value = String(result.result?.incident_id || result.incident_id || '').trim()
    proxyCheckFailure.value = result.result?.failure || result.failure || null
    const checkedRows = proxyCheckRows.value
    const available = checkedRows.filter(row => row.available).length
    const failed = checkedRows.length - available
    if (!proxyText.value.trim()) await loadProxies()
    if (failed) ElMessage.warning(`代理连通性检测完成：可用 ${available} 个，失败 ${failed} 个`)
    else ElMessage.success(`代理连通性检测通过：${available} 个`)
  } catch (error: any) {
    proxyCheckRows.value = []
    const payload = error?.payload && typeof error.payload === 'object' ? error.payload : {}
    proxyCheckIncidentId.value = String(payload.incident_id || '').trim()
    proxyCheckFailure.value = payload.failure && typeof payload.failure === 'object' ? payload.failure : null
    ElMessage.error(error?.message || 'Free 代理连通性检测失败')
  } finally {
    busy.value = ''
  }
}

async function copyProxyCheckIncident() {
  if (!proxyCheckIncidentId.value) return
  if (!navigator.clipboard?.writeText) {
    ElMessage.warning('当前环境不支持复制')
    return
  }
  try {
    await navigator.clipboard.writeText(proxyCheckIncidentId.value)
    ElMessage.success('日志 ID 已复制')
  } catch {
    ElMessage.error('日志 ID 复制失败')
  }
}

function openProxyCheckIncident() {
  if (proxyCheckIncidentId.value) {
    emit('navigate', `/logs?incident_id=${encodeURIComponent(proxyCheckIncidentId.value)}`)
  }
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
      <el-tag v-else type="info" effect="plain">独立 Free 链路</el-tag>
    </div>

    <el-form-item>
      <template #label><FieldHelpLabel label="注册链路" help="全协议直接调用认证接口；Camoufox 使用共享浏览器进程中的独立 context。两条链路共用同一个 URL 邮箱池和取件策略。" /></template>
      <el-radio-group v-model="config.driver" :disabled="running || busy === 'load'" class="driver-options">
        <el-radio value="protocol" border><strong>全协议</strong><small>OAuth、邮箱 OTP 和套餐检查</small></el-radio>
        <el-radio value="camoufox" border><strong>Camoufox</strong><small>异步共享浏览器池、独立 context 和同源 Session</small></el-radio>
      </el-radio-group>
    </el-form-item>

    <div class="selection-summary shared-proxy-summary">
      <span>共享健康随机代理池</span>
      <b>{{ Number(state.pool?.proxies || 0) }}</b>
      <small>已保存 {{ savedProxyAvailable }} 个可用 · {{ savedProxyQuarantined }} 个隔离；任务共享健康随机代理</small>
    </div>

    <el-row :gutter="10">
      <el-col :span="12"><el-form-item><template #label><FieldHelpLabel label="流程配置" help="使用参考项目 2026-08-23 的协议和 Camoufox 状态机；遇到兼容问题时可临时切回旧流程，便于回滚定位。" /></template><el-select v-model="config.flow_profile" :disabled="running"><el-option label="参考流程（推荐）" value="reference_20260823" /><el-option label="旧流程（回滚）" value="legacy" /></el-select></el-form-item></el-col>
      <el-col :span="12"><el-form-item><template #label><FieldHelpLabel label="代理分配方式" help="按 AutoRegister 使用健康代理随机分配，多个并发任务可以共享同一代理；不比较或锁定出口地址。" /></template><el-tag type="success" effect="plain">健康随机共享池</el-tag></el-form-item></el-col>
    </el-row>

    <el-row :gutter="10">
      <el-col :span="8"><el-form-item><template #label><FieldHelpLabel label="Free 注册数量（1-200）" help="本批最多启动的 Free 账号数。Free 注册中心启动条使用并保存同一个数值。" /></template><el-input-number v-model="config.target_count" class="free-scale-number" :min="1" :max="200" controls-position="right" :disabled="running" /></el-form-item></el-col>
      <el-col :span="8"><el-form-item><template #label><FieldHelpLabel label="Free 并发数（1-16）" help="配置允许同时运行的 Free 注册任务数；运行时可能因协议压力控制降低实际并发。" /></template><el-input-number v-model="config.concurrency" class="free-scale-number" :min="1" :max="16" controls-position="right" :disabled="running" /></el-form-item></el-col>
      <el-col :span="8"><el-form-item><template #label><FieldHelpLabel label="邮箱 OTP 超时（秒）" help="注册流程等待邮箱验证码的最长时间。启用自动动态口令后，第二封 OTP 也使用这项超时。" /></template><el-input-number v-model="config.email_code_timeout" :min="10" :max="600" controls-position="right" :disabled="running" /></el-form-item></el-col>
    </el-row>
    <el-form-item><template #label><FieldHelpLabel label="代理连通性目标地址" help="手动检测时通过每条待用代理访问该地址，只确认代理请求和 HTTP 响应是否建立；不会解析、保存或展示账号出口 IP。" /></template><el-input v-model="config.proxy_probe_url" :disabled="running" placeholder="https://chatgpt.com/" /></el-form-item>
    <div class="check-row proxy-tls-options"><el-checkbox v-model="config.proxy_tls_verify" :disabled="running"><FieldHelpLabel label="严格校验探测站证书" help="默认按标准 TLS 证书校验访问探测地址。关闭后只影响连通性探测，不会改代理协议、不会切换节点，也不会影响浏览器页面证书校验。" /></el-checkbox><el-checkbox v-model="config.proxy_tls_compat_fallback" :disabled="running || !config.proxy_tls_verify"><FieldHelpLabel label="TLS/CONNECT 兼容重试" help="严格校验遇到明确证书错误时，用同一代理和同一协议再试一次；协议不匹配不会走证书兼容重试。" /></el-checkbox></div>
    <el-form-item><template #label><FieldHelpLabel label="注册账号密码" help="启用自动设置密码后，注册页和补设密码流程都会使用这里的值。默认是 Aa150010150010；已保存密码会以掩码显示，输入新值即可替换。" /></template><el-input v-model="config.account_password" type="password" show-password autocomplete="new-password" maxlength="256" :disabled="running" placeholder="Aa150010150010" /></el-form-item>
    <el-form-item><template #label><FieldHelpLabel label="注册后安全设置" help="密码和 2FA 可独立启用。每个启用的设置都会在对应分支单独重新获取一封邮箱 OTP；关闭后跳过该步骤。" /></template><div class="check-row security-options"><el-checkbox v-model="config.auto_set_password" :disabled="running">注册完成后自动设置密码</el-checkbox><el-checkbox v-model="config.auto_set_2fa" :disabled="running">注册完成后自动设置动态口令（2FA）</el-checkbox></div></el-form-item>

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
      <div class="humanize-heading"><h3>代理稳定性策略</h3><FieldHelpLabel label="规则说明" help="这些规则只作用于独立 Free 代理池：控制注册前可否更换备用代理和连续失败隔离。" /></div>
      <el-row :gutter="10">
        <el-col :span="8"><el-form-item><template #label><FieldHelpLabel label="代理额外重试次数" help="仅对邮箱提交前的连接失败和非挑战 401/403 访问拒绝切换健康代理；Cloudflare/Turnstile 安全挑战，以及邮箱提交、验证码或账号创建后的失败不会自动换代理或重放。" /></template><el-input-number v-model="config.proxy_retry_count" :min="0" :max="5" controls-position="right" :disabled="running" /></el-form-item></el-col>
        <el-col :span="8"><el-form-item><template #label><FieldHelpLabel label="连续失败隔离阈值" help="同一代理连续失败达到此次数后进入隔离，当前批次不再分配它。成功探测会清零连续失败次数。" /></template><el-input-number v-model="config.proxy_failure_threshold" :min="1" :max="10" controls-position="right" :disabled="running" /></el-form-item></el-col>
        <el-col :span="8"><el-form-item><template #label><FieldHelpLabel label="代理隔离时间（秒）" help="代理达到失败阈值后的暂停使用时间。到期后可重新参与检测和任务分配。" /></template><el-input-number v-model="config.proxy_quarantine_seconds" :min="30" :max="86400" controls-position="right" :disabled="running" /></el-form-item></el-col>
      </el-row>
      <el-row :gutter="10">
        <el-col :span="12"><el-form-item><template #label><FieldHelpLabel label="健康探测有效期（秒）" help="代理最近一次成功探测在这段时间内直接复用；超过后仅在绑定前执行一次有界连通性探测。设为 0 可关闭自动刷新，保留手动代理检测。" /></template><el-input-number v-model="config.proxy_health_probe_ttl_seconds" :min="0" :max="86400" controls-position="right" :disabled="running" /></el-form-item></el-col>
      </el-row>
    </div>

    <div v-if="config.driver === 'protocol'" class="subsection">
      <h3>全协议专属配置</h3>
      <el-row :gutter="10">
        <el-col :span="16"><el-form-item><template #label><FieldHelpLabel label="Node / Sentinel Runner" help="全协议链路使用的本地 Node/Sentinel 执行器。留空时沿用运行时默认路径。" /></template><el-input v-model="config.protocol.node_runner" placeholder="留空使用运行时默认配置" :disabled="running" /></el-form-item></el-col>
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
        <el-col :span="6"><el-form-item><template #label><FieldHelpLabel label="失败后保留窗口" help="默认开启调试模式：普通业务失败和 Cloudflare/Turnstile 挑战会保留当前窗口，并生成脱敏截图、DOM 和事件摘要；成功、超时、取消及浏览器进程断开会正常回收。" /></template><el-switch v-model="config.camoufox.debug_mode" active-text="开启" inactive-text="关闭" :disabled="running" /></el-form-item></el-col>
        <el-col :span="6"><el-form-item><template #label><FieldHelpLabel label="窗口模式" help="调试模式开启时必须使用有头模式才能查看失败页面；关闭调试模式后才可切换无头或有头。" /></template><el-switch :model-value="camoufoxEffectiveHeadless" active-text="无头" inactive-text="有头" :disabled="running || Boolean(config.camoufox.debug_mode)" @update:model-value="updateCamoufoxHeadless" /><small v-if="config.camoufox.debug_mode" class="field-note">调试模式实际运行：有头（关闭调试后恢复已保存偏好）</small></el-form-item></el-col>
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
      <p class="section-hint">Camoufox 是可选依赖；未安装时预检会明确提示，不影响全协议。调试窗口会占用现有 context 容量，完成排查后请在 Free 注册页手动关闭。</p>
    </div>

    <div class="subsection proxy-section">
      <div class="section-heading-row"><div><h3>Free 独立代理池</h3><p class="section-hint">粘贴后可检测代理池连通性，再保存到 Free 池。</p></div><span class="muted">已保存 {{ Number(state.pool?.proxies || 0) }} 个</span></div>
      <div class="proxy-import-meta">
        <div class="proxy-import-field"><FieldHelpLabel label="无协议默认协议" help="支持 scheme://用户名:密码@主机:端口、主机:端口:用户名:密码、用户名:密码@主机:端口、主机:端口@用户名:密码；裸格式按当前下拉协议解析，显式协议始终优先。" /><el-select v-model="proxyScheme" placeholder="无协议时默认协议"><el-option label="HTTP" value="http" /><el-option label="HTTPS" value="https" /><el-option label="SOCKS4" value="socks4" /><el-option label="SOCKS5" value="socks5" /><el-option label="SOCKS5H" value="socks5h" /></el-select></div>
        <div class="proxy-import-field"><FieldHelpLabel label="SOCKS5 DNS" help="只影响 SOCKS5 代理的域名解析位置，不改变保存的协议标签。默认使用代理端解析，避免本机 Fake-IP 或 DNS 污染导致连接失败；也可按需选择本机解析或严格声明。" /><el-select v-model="config.proxy_socks5_dns_mode" :disabled="running"><el-option label="自动适配" value="auto" /><el-option label="本机解析" value="local" /><el-option label="代理端解析" value="remote" /><el-option label="严格声明" value="declared" /></el-select></div>
        <div class="proxy-import-field"><FieldHelpLabel label="代理来源（可选）" help="仅用于报表和供应商对比，例如 1024、cliproxy；不会参与代理分配，也不会写入代理凭据。" /><el-input v-model="proxySourceLabel" maxlength="40" show-word-limit placeholder="例如 1024 / cliproxy" /></div>
      </div>
      <el-input v-model="proxyText" type="textarea" :rows="5" :disabled="running" placeholder="每行一个代理，支持 URL、host:port:user:pass 和两种 @ 格式" autocomplete="off" />
      <div class="inline-actions"><el-button size="small" :icon="CircleCheck" :loading="busy === 'proxy-preflight'" :disabled="running || (!proxyText.trim() && !proxyRows.length)" @click="preflightProxyPool">{{ proxyText.trim() ? '检测代理连通性' : '复检已保存代理' }}</el-button><el-checkbox v-model="layeredProbe" :disabled="running">分层诊断</el-checkbox><span class="muted">留空时复检已保存代理，成功会解除隔离；分层诊断会额外记录 TCP、HTTPS 和 ChatGPT 登录页耗时，不保存响应正文。</span></div>
      <div v-if="proxyCheckIncidentId" class="proxy-check-incident">
        <div><span>本次检测故障日志</span><code>{{ proxyCheckIncidentId }}</code><small>{{ proxyCheckFailure?.public_message || '部分代理检测失败，详细证据已写入日志中心。' }}</small></div>
        <el-button text size="small" :icon="CopyDocument" @click="copyProxyCheckIncident">复制日志 ID</el-button>
        <el-button text size="small" :icon="View" @click="openProxyCheckIncident">查看详情</el-button>
      </div>
      <div v-if="proxyCheckSummary" class="proxy-check-summary">{{ proxyCheckSummary }}</div>
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
.proxy-import-meta { display: grid; grid-template-columns: 180px minmax(180px, 1fr) minmax(180px, 1fr); gap: 8px; margin-bottom: 8px; }
.proxy-import-field { display: grid; gap: 5px; min-width: 0; }
.proxy-check-summary { margin-top: 8px; color: var(--el-text-color-secondary); font-size: 12px; line-height: 18px; }
.proxy-check-incident { display: flex; align-items: center; gap: 8px; min-width: 0; margin-top: 8px; padding: 7px 0; border-top: 1px solid var(--el-color-danger-light-7); border-bottom: 1px solid var(--el-color-danger-light-7); }
.proxy-check-incident > div { display: grid; grid-template-columns: auto auto; align-items: baseline; gap: 2px 8px; min-width: 0; margin-right: auto; overflow: hidden; }
.proxy-check-incident span { color: var(--el-color-danger); font-size: 12px; font-weight: 650; }
.proxy-check-incident code { color: var(--el-text-color-primary); font-size: 12px; }
.proxy-check-incident small { grid-column: 1 / -1; min-width: 0; overflow: hidden; color: var(--el-text-color-secondary); font-size: 11px; text-overflow: ellipsis; white-space: nowrap; }
.table-subline { display: block; color: var(--el-text-color-secondary); font-size: 10px; line-height: 14px; }
.free-settings-section :deep(.el-input-number), .free-settings-section :deep(.el-select) { width: 100%; }
.free-settings-section :deep(.free-scale-number) { width: 132px; max-width: 100%; }
.free-settings-section :deep(.el-form-item) { margin-bottom: 10px; }
</style>
