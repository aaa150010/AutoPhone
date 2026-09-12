/**
 * Single source for the Free registration config editor defaults and legacy
 * draft cleanup.
 *
 * Both FreeRegistrationPage.vue and FreeRegisterSettingsSection.vue derive
 * their editable draft from `defaultFreeConfig()`, keeping the two pages on
 * one field set. `stripLegacyFreeConfigDraft` removes removed roxybrowser
 * fields from pre-migration config drafts before they can be re-persisted.
 */

import type { FreeConfig } from '../types/free'

/** Build a fresh Free config editor draft with the full default field set. */
export function defaultFreeConfig(): FreeConfig {
  return {
    driver: 'protocol', flow_profile: 'reference_20260823', proxy_allocation_mode: 'healthy_random', target_count: 1, concurrency: 3, email_code_timeout: 90, account_password: 'Aa150010150010', auto_set_password: false, auto_set_2fa: true,
    mailbox_network_mode: 'local_proxy', mailbox_proxy_url: 'http://127.0.0.1:7897',
    mailbox_request_retries: 3, mailbox_retry_backoff_seconds: 1,
    proxy_probe_url: 'https://chatgpt.com/', proxy_socks5_dns_mode: 'remote', proxy_tls_verify: true, proxy_tls_compat_fallback: true, protocol: { node_runner: '', sentinel_version: '20260219f9f6', sentinel_timeout: 90, network_timeout: 20, network_preflight_retries: 3, security_challenge_wait_seconds: 60, anonymous_warmup: true, authenticated_warmup: true },
    proxy_default_scheme: 'socks5', proxy_failure_threshold: 2, proxy_quarantine_seconds: 600, proxy_health_probe_ttl_seconds: 300, proxy_retry_count: 1,
    proxy_tunnel_enabled: false, proxy_tunnel_gateway_host: '', proxy_tunnel_gateway_port: 0, proxy_tunnel_scheme: 'socks5', proxy_tunnel_username_template: '', proxy_tunnel_password: '', proxy_tunnel_sticky_minutes: 30,
    proxy_pool_target_size: 0, proxy_challenge_switch_limit: 3,
    camoufox: {
      debug_mode: true, headless: true, pool_size: 2, max_contexts_per_browser: 3, context_start_interval_ms: 175,
      startup_concurrency: 4, block_images: true, registration_timeout_seconds: 600,
      context_close_timeout_seconds: 15, browser_recycle_timeout_seconds: 45,
      browser_recycle_drain_timeout_seconds: 20, max_registrations_per_browser: 12,
      browser_launch_attempts: 3, existing_account_login: true,
    },
    remail: { enabled: false, base_url: 'https://remail.aishop6.com', api_key: '', project_id: '', supply_policy: 'private_first', request_timeout_seconds: 20, catalog_cache_seconds: 60, order_sync_enabled: false, order_sync_interval_minutes: 30, auto_import_new_purchase_orders: false },
  }
}

/** Delete removed legacy roxybrowser fields from a config draft in place. */
export function stripLegacyFreeConfigDraft(draft: FreeConfig): void {
  // Legacy keys no longer exist on FreeConfig, so the deletion pass goes
  // through a structural record view of the same object.
  const record: Record<string, unknown> = draft
  delete record.roxybrowser
  delete record.roxy_circuit_failure_threshold
  delete record.roxy_circuit_recovery_seconds
  delete record.roxy_api_key
  delete record.roxy_workspace_id
  const proxySelection = draft.proxy_selection as Record<string, unknown> | undefined
  if (proxySelection && typeof proxySelection === 'object') {
    delete proxySelection.roxybrowser
  }
}

/**
 * Merge one server Free config into a reactive draft, stripping legacy
 * fields and clamping the shared scalar bounds. Callers keep any
 * page-local extra wiring (quick-run bar, proxy scheme selector) around
 * this common core.
 */
export function mergeFreeConfigDraft(
  draft: FreeConfig,
  value: FreeConfig | undefined | null,
): void {
  if (!value || typeof value !== 'object') return
  Object.assign(draft, value)
  stripLegacyFreeConfigDraft(draft)
  Object.assign(draft.protocol, value.protocol || {})
  Object.assign(draft.camoufox, value.camoufox || {})
  // Old persisted configs may still report a removed driver. Keep the editor
  // valid while historical task rows retain their original read-only metadata.
  if (!['protocol', 'camoufox'].includes(String(draft.driver || '').trim().toLowerCase())) draft.driver = 'protocol'
  draft.target_count = Math.min(200, Math.max(1, Number(draft.target_count) || 1))
  draft.concurrency = Math.min(16, Math.max(1, Number(draft.concurrency) || 1))
  draft.proxy_tunnel_sticky_minutes = Math.min(120, Math.max(5, Number(draft.proxy_tunnel_sticky_minutes) || 30))
  draft.proxy_pool_target_size = Math.min(16, Math.max(0, Number(draft.proxy_pool_target_size) || 0))
  draft.proxy_challenge_switch_limit = Math.min(6, Math.max(0, Number(draft.proxy_challenge_switch_limit ?? 3)))
}
