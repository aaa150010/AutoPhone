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
export function stripLegacyFreeConfigDraft(draft: Record<string, unknown>): void {
  delete draft.roxybrowser
  delete draft.roxy_circuit_failure_threshold
  delete draft.roxy_circuit_recovery_seconds
  delete draft.roxy_api_key
  delete draft.roxy_workspace_id
  const proxySelection = draft.proxy_selection
  if (proxySelection && typeof proxySelection === 'object') {
    delete (proxySelection as Record<string, unknown>).roxybrowser
  }
}
