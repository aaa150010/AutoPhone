/** Free (protocol / Camoufox) chain and diagnostics API types.

Moved from ``api/client.ts`` so the request layer keeps only functions while
every type stays importable from one place.  ``client.ts`` re-exports all of
these names, so existing ``from '../api/client'`` imports keep working; new
code can import from ``types/free`` directly.
*/

import type { JsonRecord, ManualVerificationRequest, TaskFailure, TaskProgress, TaskTiming } from './api'

export interface FreeConfig {
  version?: number
  driver: 'protocol' | 'camoufox'
  flow_profile?: 'reference_20260823' | 'legacy' | string
  proxy_allocation_mode?: 'healthy_random' | string
  target_count: number
  concurrency: number
  email_code_timeout: number
  mailbox_network_mode: 'local_proxy' | 'direct'
  mailbox_proxy_url: string
  mailbox_request_retries: number
  mailbox_retry_backoff_seconds: number
  /** Registration password; the Free config endpoint masks this as `********`. */
  account_password: string
  auto_set_password: boolean
  auto_set_2fa: boolean
  twofa_auto_retry_attempts?: number
  proxy_probe_url: string
  proxy_default_scheme?: 'http' | 'https' | 'socks4' | 'socks5' | 'socks5h' | string
  proxy_socks5_dns_mode?: 'auto' | 'declared' | 'local' | 'remote' | string
  proxy_tls_verify?: boolean
  proxy_tls_compat_fallback?: boolean
  proxy_failure_threshold?: number
  proxy_quarantine_seconds?: number
  proxy_health_probe_ttl_seconds?: number
  proxy_retry_count?: number
  /** @deprecated retained only for loading pre-v6 config responses. */
  proxy_selection?: {
    protocol?: { country?: string; group?: string }
    camoufox?: { country?: string; group?: string }
  }
  protocol: {
    node_runner: string
    sentinel_version?: string
    sentinel_timeout: number
    network_timeout?: number
    network_preflight_retries?: number
    security_challenge_wait_seconds?: number
    anonymous_warmup?: boolean
    authenticated_warmup?: boolean
  }
  camoufox: {
    debug_mode?: boolean
    headless: boolean
    pool_size: number
    max_contexts_per_browser: number
    context_start_interval_ms: number
    startup_concurrency: number
    block_images: boolean
    registration_timeout_seconds: number
    context_close_timeout_seconds: number
    browser_recycle_timeout_seconds: number
    browser_recycle_drain_timeout_seconds: number
    max_registrations_per_browser: number
    browser_launch_attempts: number
    existing_account_login: boolean
  }
  remail?: {
    enabled: boolean
    base_url: string
    api_key: string
    project_id: string
    supply_policy: 'private_first' | 'public_only' | string
    request_timeout_seconds: number
    catalog_cache_seconds: number
    order_sync_enabled: boolean
    order_sync_interval_minutes: number
    auto_import_new_purchase_orders: boolean
  }
  /** Server payloads may still carry removed legacy keys (e.g. roxybrowser
   * fields) that the editor strips before re-saving. */
  [legacyKey: string]: unknown
}

export interface FreeState {
  runtime_version?: string
  otp_parser_revision?: string
  running: boolean
  batch_id?: string
  driver?: 'protocol' | 'camoufox' | string
  tasks?: FreeTaskRow[]
  pool?: { total?: number; available?: number; proxies?: number }
  scheduler?: { concurrency?: number; active_slots?: number; queued_slots?: number }
  camoufox_debug?: FreeCamoufoxDebugState
  summary?: { total?: number; active?: number; success?: number; failed?: number; stopped?: number }
}

export interface FreeCamoufoxDebugSession {
  session_id: string
  task_id?: string
  node_code?: string
  node_label?: string
  error_code?: string
  page_type?: string
  safe_page?: string
  proxy_fingerprint?: string
  artifact_id?: string
  incident_id?: string
  created_at?: number | string
}

export interface FreeCamoufoxDebugState {
  enabled?: boolean
  headless?: boolean
  capacity?: number
  used?: number
  available?: number
  open_contexts?: number
  closing_contexts?: number
  closing_sessions?: string[]
  browser_count?: number
  pool_count?: number
  sessions?: FreeCamoufoxDebugSession[]
}

export interface FreeProxyRow {
  proxy_id: string
  index?: number
  masked: string
  fingerprint: string
  scheme: string
  country: string
  group: string
  enabled: boolean
  status: string
  lease_until?: number | null
  last_checked_at?: number | null
  last_probe_mode?: 'strict' | 'compat' | string
  last_probe_ok?: boolean | null
  source_label?: string
  effective_scheme?: string
  declared_scheme?: string
  probe_attempts?: number
  probe_successes?: number
  probe_success_rate?: number | null
  p50_latency_ms?: number | null
  p95_latency_ms?: number | null
  last_chatgpt_login_checked_at?: number | null
  last_chatgpt_login_status?: number
  last_chatgpt_login_probe_mode?: 'strict' | 'compat' | string
  latency_ms?: number | null
  consecutive_failures?: number
}

export interface FreeProxyPool {
  count: number
  allocation_mode?: string
  content?: string
  rows: FreeProxyRow[]
  groups?: FreeProxySummary[]
  countries?: FreeProxySummary[]
}

export interface FreeProxySummary {
  country: string
  group?: string
  total: number
  enabled: number
  available: number
  leased?: number
  quarantined: number
  schemes?: string[]
}

export type FreeConfigSavePayload = Partial<FreeConfig> & {
  proxy_content?: string
  proxy_scheme?: string
  proxy_source_label?: string
}

export interface FreeCamoufoxDebugCloseResult {
  ok: true
  session_id?: string
  closed_pools?: number
  closed_contexts?: number
  closed_sessions?: number
  retained_contexts?: number
  remaining_contexts?: number
  remaining_sessions?: number
  state: FreeState
  camoufox_debug?: FreeCamoufoxDebugState
}

export interface DiagnosticIncident {
  incident_id: string
  created_at?: string
  updated_at?: string
  chain?: string
  workflow?: string
  driver?: string
  run_id?: string
  batch_id?: string
  task_id?: string
  subject_kind?: string
  subject_ref?: string
  subject_display?: string
  outcome?: string
  status?: string
  first_node_code?: string
  first_node_label?: string
  first_error_code?: string
  retryable?: boolean | number
  failure?: JsonRecord
  event_count?: number
  integrity_status?: string
  match_basis?: string[]
  time_distance_seconds?: number | null
  events?: DiagnosticEvent[]
}

export interface DiagnosticEvent {
  event_id: string
  incident_id?: string
  occurred_at?: string
  received_at?: string
  chain?: string
  workflow?: string
  driver?: string
  task_id?: string
  batch_id?: string
  stage_group?: string
  node_code?: string
  node_label?: string
  sequence?: number
  attempt?: number
  attempt_group?: string
  outcome?: string
  parent_event_id?: string
  root_cause_event_id?: string
  elapsed_ms?: number | null
  failure?: JsonRecord
  transport?: JsonRecord
  message?: string
  redaction_applied?: boolean
}

export interface FreeMailboxRow {
  created_at?: number | string
  row_id: string
  line_no: number
  email: string
  email_masked?: string
  source?: string
  mailbox_url?: string
  has_mailbox_url?: boolean
  subject_ref_fingerprint?: string
  status: string
  cooldown_until?: number | null
  cooldown_remaining?: number
  stage?: string
  driver?: 'protocol' | 'camoufox' | string
  proxy_masked?: string
  proxy_fingerprint?: string
  proxy_scheme?: string
  proxy_country?: string
  proxy_group?: string
  plan_type?: string
  subscription_plan?: string
  plan_check_status?: string
  plan_check_task_id?: string
  plan_source?: string
  plan_retry_after_until?: number | null
  plus_trial_eligible?: boolean
  live_check_status?: 'queued' | 'running' | 'live' | 'deactivated' | 'token_expired' | 'free_live_proxy_blocked' | 'free_live_session_rejected' | 'free_live_rate_limited' | 'free_live_upstream_error' | 'free_live_network_error' | 'free_live_password_required' | 'failed' | string
  live_check_mode?: 'fast' | 'deep' | string
  live_check_task_id?: string
  live_checked_at?: number | string
  live_check_token_refreshed?: boolean
  live_check_http_status?: number | null
  live_check_failure?: TaskFailure | null
  twofa_status?: string
  twofa_error?: string
  has_access_token?: boolean
  has_password?: boolean
  has_totp?: boolean
  has_credential?: boolean
  credential_line?: string
  task_id?: string
  retry_resolved?: boolean | string
  error?: string
  failure?: TaskFailure | null
  profile_summary?: string
  account_flow?: string
  has_active_subscription?: boolean
  eligible_campaign_id?: string
  plan_checked_at?: number | string
  plan_error_code?: string
  plan_http_status?: number | null
  rebind_email?: string
  rebind_email_masked?: string
  rebind_task_id?: string
  rebind_status?: string
  rebind_plan_type?: string
  rebind_plus_trial_eligible?: boolean
  display_index?: number
  progress?: Record<string, unknown> | null
}

export interface FreeTaskRow {
  task_id?: string
  incident_id?: string
  slot_id?: string
  batch_id?: string
  batch_started_at?: number
  run_mode?: string
  driver?: 'protocol' | 'camoufox' | string
  row_id?: string
  stage?: string
  stage_label?: string
  proxy_fingerprint?: string
  proxy_id?: string
  proxy_masked?: string
  proxy_scheme?: string
  proxy_effective_scheme?: string
  proxy_attempts?: Array<Record<string, unknown>>
  proxy_country?: string
  proxy_group?: string
  retry_of?: string
  retry_task_id?: string
  retry_status?: string
  retry_attempt?: number
  retry_resolved?: boolean | string
  retry_updated_at?: number
  ordinal?: number
  slot_index?: number
  concurrency_limit?: number
  status?: string
  cleanup_status?: string
  created_at?: number
  updated_at?: number
  email?: string
  email_masked?: string
  account?: string
  subject_ref_fingerprint?: string
  has_mailbox_url?: boolean
  mailbox_verification?: {
    phase: 'automatic' | 'manual' | string
    stage?: string
    opened_at?: number
    deadline_at?: number
  } | null
  manual_verification?: ManualVerificationRequest | null
  progress?: TaskProgress | null
  timing?: TaskTiming | null
  result?: {
    account_flow?: string
    plan_type?: string
    subscription_plan?: string
    eligible_campaign_id?: string
    plan_check_task_id?: string
    plan_error_code?: string
    plan_check_status?: string
    password_status?: string
    twofa_status?: string
    twofa_error?: string
    plus_trial_eligible?: boolean
    has_active_subscription?: boolean
    password_set_after_registration?: boolean
    has_access_token?: boolean
    has_password?: boolean
    has_totp?: boolean
    has_credential?: boolean
    totp_secret?: string | null
    plan_checked_at?: number | null
    plan_retry_after_until?: number | null
    plan_http_status?: number | null
    driver?: string
    expected_exit_ip?: string
    sms_cost_usd?: number | null
    sms_cost_cny?: number | null
    sms_exchange_rate?: number | null
    sms_exchange_date?: string
    timing?: TaskTiming
    run_mode?: string
    batch_id?: string
    batch_started_at?: number
  }
  error?: string
  failure?: TaskFailure | null
}

export interface RemailProjectProduct {
  id?: number | string
  type?: string
  suffix?: string
  suffixes?: Array<{ suffix?: string; purchaseAvailable?: number | string; totalAvailable?: number | string }>
  purchaseEnabled?: boolean
  purchaseAvailable?: number | string
  totalAvailable?: number | string
  purchasePrice?: number | string
  priceMultiplier?: number | string
}

export interface RemailProject {
  id?: number | string
  name?: string
  products?: RemailProjectProduct[]
}

export interface RemailWallet {
  consumerBalance?: number | string
  balance?: number | string
  amount?: number | string
}

export interface RemailOrder {
  order_no: string
  status: string
  delivery_email_masked?: string
  imported: boolean
  hidden?: boolean
  pool_row_id?: string
  payload?: JsonRecord
  created_at?: string
  updated_at?: string
}

export interface FreeLiveCheckState {
  running: boolean
  workers: number
  queue_limit: number
  active: number
  jobs: Array<{
    task_id: string
    row_id: string
    email: string
    email_masked?: string
    subject_ref_fingerprint?: string
    mode: 'fast' | 'deep' | string
    status: string
    stage?: string
    stage_label?: string
    checked_at?: number
    failure?: FreeMailboxRow['live_check_failure']
  }>
}

export interface FreePlanCheckState {
  running: boolean
  workers: number
  queue_limit: number
  active: number
  jobs: Array<{
    task_id: string
    row_id: string
    email: string
    email_masked?: string
    subject_ref_fingerprint?: string
    status: string
    created_at?: number
    updated_at?: number
    checked_at?: number
    retry_after_until?: number
    http_status?: number
    source?: string
    failure?: TaskFailure | null
  }>
}

export interface FreeProxyPreflightRow {
  index: number
  masked: string
  fingerprint: string
  scheme?: string
  declared_scheme?: string
  effective_scheme?: string
  available?: boolean
  http_status?: number | null
  provider_status?: number | null
  provider_code?: string
  local_to_proxy_ms?: number | null
  proxy_to_target_ms?: number | null
  failure_node?: string
  failure_reason?: string
  failure?: TaskFailure | null
  incident_id?: string
  layered_probe?: JsonRecord
}

export interface FreeProxyPreflightResult {
  proxies: number
  rows: FreeProxyPreflightRow[]
  target_count?: number
  mailboxes?: number
  driver?: string
  failure_count?: number
  health_write_failures?: number
  incident_id?: string
  failure?: TaskFailure | null
}
