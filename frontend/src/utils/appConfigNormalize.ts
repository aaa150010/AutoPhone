/**
 * Operational config normalization helpers.
 *
 * Pure defaults, merge and draft-normalization logic extracted verbatim from
 * useAppController so the composable keeps only reactive wiring.
 */
import { normalizeSmsProviderPools, syncLegacySmsFields } from './smsPools'

export function defaultEmailNotification() {
  return {
    enabled: false,
    provider: 'qq',
    smtp_host: 'smtp.qq.com',
    smtp_port: 465,
    security: 'ssl',
    username: '',
    sender: '',
    password: '',
    recipients: [] as string[],
    stalled_minutes: 10,
    events: {
      batch_completed: true,
      unexpected_stop: true,
      stalled: true,
      sms_exhausted: true,
      sms_balance_low: true,
      openai_auth_connectivity: true,
      manual_stop: false,
    },
  }
}

export function defaultForm() {
  return {
    proxy: 'http://127.0.0.1:7897',
    proxy_scope: { sms: false, email: false, upload: false },
    target_count: '1',
    concurrency: '5',
    node_concurrency: '5',
    auto_email_login_concurrency: 5,
    phone_submission_concurrency: 2,
    node_timeout: 45,
    email_code_timeout: 60,
    auth_session_retries: 1,
    adaptive_task_concurrency: true,
    task_inflight_optimization: true,
    task_inflight_limit: 20,
    openai_connectivity_guard: true,
    phone_binding_compatibility: true,
    mailbox_result_index_cache: true,
    protocol_concurrency_ceiling: 12,
    sms_provider: 'smsbower',
    sms_min_price: '0.01',
    max_price: '0.15',
    sms_timeout: '30',
    phone_max_attempts: 45,
    phone_attempts_per_provider: 15,
    phone_session_cycle_seconds: 1800,
    sms_quality_optimization: true,
    sms_api_keys: [''],
    sms_provider_pools: normalizeSmsProviderPools(null),
    sub2api: {},
    online_mailbox: {
      base_url: 'https://lynote.xyz/token-tool',
      api_token: '',
    },
    email_notification: defaultEmailNotification(),
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function mergeConfig(...values: any[]) {
  const result: Record<string, unknown> = {}
  for (const value of values) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) continue
    for (const [key, item] of Object.entries(value)) {
      if (item && typeof item === 'object' && !Array.isArray(item)) {
        result[key] = mergeConfig(result[key], item)
      } else {
        result[key] = item
      }
    }
  }
  return result
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function normalizeEmailNotificationDraft(value: any) {
  return {
    ...mergeConfig(defaultEmailNotification(), value || {}),
    provider: 'qq',
    smtp_host: 'smtp.qq.com',
    smtp_port: 465,
    security: 'ssl',
  }
}

export function normalizeOperationalSettings(config: Record<string, any>) {
  config.phone_submission_concurrency = Math.max(1, Math.min(5, Number(config.phone_submission_concurrency) || 2))
  config.adaptive_task_concurrency = config.adaptive_task_concurrency !== false
  config.task_inflight_optimization = config.task_inflight_optimization !== false
  config.task_inflight_limit = Math.max(1, Math.min(20, Number(config.task_inflight_limit) || 20))
  config.openai_connectivity_guard = config.openai_connectivity_guard !== false
  config.phone_binding_compatibility = config.phone_binding_compatibility !== false
  config.mailbox_result_index_cache = config.mailbox_result_index_cache !== false
  config.protocol_concurrency_ceiling = Math.max(8, Math.min(15, Number(config.protocol_concurrency_ceiling) || 12))
  delete config.allow_free_plan_sms_binding
  delete config.allow_unknown_plan_sms_binding
  config.sms_quality_optimization = config.sms_quality_optimization !== false
  return config
}

export function stableValue(value: any): any {
  if (Array.isArray(value)) return value.map(stableValue)
  if (!value || typeof value !== 'object') return value
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, stableValue(value[key])]))
}

export function signature(value: any) {
  return JSON.stringify(stableValue(value))
}

export function normalizeImportedConfig(value: any) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('配置 JSON 必须是对象')
  }
  const config = mergeConfig(value)
  delete config.free_target_count
  delete config.free_concurrency
  delete config.free_proxy_probe_url
  delete config.free_proxy_pool_content
  delete config.free_register_password
  delete config.free_pool_content
  syncLegacySmsFields(config)
  normalizeOperationalSettings(config)
  config.email_notification = normalizeEmailNotificationDraft(config.email_notification)
  return config
}
