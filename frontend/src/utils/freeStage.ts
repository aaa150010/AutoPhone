const FREE_STAGE_LABELS: Record<string, string> = {
  oauth_create_node: '初始化 Node/Sentinel',
  free_protocol_preflight: '协议网络预检',
  free_protocol_warmup: '匿名态 ChatGPT 预热',
  free_authenticated_warmup: '认证态 ChatGPT 预热',
  free_protocol_fingerprint: '协议设备与出口画像',
  free_proxy_geo: '出口地区画像',
  free_proxy_binding: '绑定 Free 注册代理',
  free_proxy_preflight: 'Free 代理预检',
  free_proxy_health: '检查 Free 代理健康度',
  free_proxy_lease: '分配 Free 注册代理',
  free_proxy_release: '释放 Free 注册代理',
  proxy_protocol_mismatch: '代理协议不匹配',
  proxy_auth_rejected: '代理认证失败',
  proxy_dns_failed: '代理 DNS 解析失败',
  proxy_connect_timeout: '代理连接超时',
  proxy_connection_reset: '代理连接被重置',
  proxy_tls_certificate_error: '代理证书校验失败',
  proxy_connect_failed: '代理连接失败',
  free_existing_login: '已有 Free 账号登录',
  free_existing_login_password: '验证已有 Free 账号密码',
  free_existing_login_otp: '已有 Free 账号邮箱验证',
  free_mailbox_lease: '分配 Free 邮箱',
  free_mailbox_release: '释放 Free 邮箱',
  free_camoufox_dependency: '检查 Camoufox 依赖',
  free_camoufox_launch: '启动 Camoufox 浏览器池',
  camoufox_pool_shutdown_pending: '等待 Camoufox 浏览器池关闭',
  free_camoufox_signup: 'Camoufox 页面注册',
  free_camoufox_signup_email: '填写 Camoufox 注册邮箱',
  free_camoufox_signup_password: '提交 Camoufox 注册密码',
  free_camoufox_browser: 'Camoufox 注册页面',
  free_camoufox_navigation: '打开 Camoufox 注册页面',
  free_camoufox_profile: '填写 Camoufox 账号资料',
  free_camoufox_challenge: '等待 Camoufox 安全验证',
  free_oauth_session: 'Free OAuth 会话',
  free_twofa_reauth: 'Free 2FA 重认证诊断',
  free_twofa_reauth_csrf: '2FA 重认证 CSRF',
  free_twofa_reauth_signin: '启动 2FA 重认证',
  free_twofa_reauth_authorize: '打开 2FA 重认证授权页面',
  free_twofa_otp_wait: '等待 2FA 邮箱验证码',
  free_twofa_otp_validate: '验证 2FA 邮箱验证码',
  free_twofa_reauth_callback: '刷新 2FA 重认证会话',
  free_oauth_security_challenge: '等待 Free OAuth 安全验证',
  oauth_bootstrap_html: '识别 Free OAuth 授权页面',
  free_email_identifier: '识别 Free 注册邮箱',
  free_email_password: '验证 Free 注册密码',
  free_email_otp_wait: '等待 Free 邮箱验证码',
  free_email_otp_validate: '验证 Free 邮箱验证码',
  free_account_create: '创建 Free 账号',
  free_oauth_callback: 'Free OAuth 回调',
  free_protocol_result: '读取 Free 协议注册结果',
  free_access_token: '获取 Free access token',
  free_phone_required: 'Free 注册手机号节点',
  free_plan_check: '查询 Free 套餐资格',
  free_twofa_enroll: '注册 Free 账号 2FA',
  free_twofa_activate: '激活 Free 账号 2FA',
  free_password_eligibility: '检查 Free 账号密码资格',
  free_password_reauth_csrf: '密码设置重认证 CSRF',
  free_password_reauth_signin: '启动密码设置重认证',
  free_password_reauth_authorize: '打开密码设置授权页面',
  free_password_otp_wait: '等待密码设置邮箱验证码',
  free_password_otp_validate: '验证密码设置邮箱验证码',
  free_password_mfa_challenge: '密码设置 2FA 验证',
  free_password_mfa_validate: '验证密码设置 2FA 动态码',
  free_password_enroll: '打开新密码页面',
  free_password_add: '提交 Free 账号密码',
  free_password_callback: '刷新密码设置会话',
  free_mailbox_released: '释放 Free 邮箱',
  free_result_save: '保存 Free 注册结果',
  free_process_recovery: '恢复 Free 任务状态',
  free_run_start: '启动 Free 注册',
  free_run_stop: '停止 Free 注册',
  free_run_stopped: 'Free 注册已停止',
  free_batch_shutdown_pending: '等待 Free 批次关闭',
  free_live_queued: 'Free 账号测活排队',
  free_live_fast: '快速测活',
  free_live_deep: '深度测活',
  free_live_email: '深度测活邮箱验证',
  free_live_mfa: '深度测活动态口令验证',
  free_live_plan: '刷新套餐与 Plus 资格',
  free_live_result: '保存 Free 测活结果',
  free_live_deactivated: '确认 Free 账号状态',
  free_live_account: '查询 Free 账号状态',
  free_live_eligibility: '查询 Free 账号资格',
  free_live_check: 'Free 账号测活',
  free_live_start: '启动 Free 账号测活',
  free_live_queue: '排队 Free 账号测活',
  free_live_proxy_blocked: '出口或服务端安全策略拒绝',
  free_live_session_rejected: '深度测活会话被拒绝',
  free_live_rate_limited: 'Free 测活触发限流',
  free_live_upstream_error: 'Free 测活上游服务异常',
  free_live_network_error: 'Free 测活网络异常',
  free_live_password_required: '深度测活需要真实账号密码',
  free_live_password_context_unknown: '识别深度测活密码页面',
}

const FREE_SUCCESS_STATUSES = new Set([
  'success',
  'succeeded',
  'complete',
  'completed',
  'uploaded',
  'consumed',
  'ok',
  'ready',
])

export function freeStageIsSuccess(status: unknown) {
  return FREE_SUCCESS_STATUSES.has(String(status || '').trim().toLowerCase())
}

export function freeStageLabel(value: unknown, fallback = '处理中', status?: unknown) {
  if (freeStageIsSuccess(status)) return '成功'
  const raw = String(value || '').trim()
  if (!raw) return fallback
  if (FREE_STAGE_LABELS[raw]) return FREE_STAGE_LABELS[raw]
  return /[\u4e00-\u9fff]/.test(raw) ? raw : fallback
}

export function freeStageType(stage: unknown, status: unknown = ''): 'primary' | 'success' | 'warning' | 'danger' | 'info' {
  const code = String(stage || '').trim().toLowerCase()
  const normalizedStatus = String(status || '').trim().toLowerCase()
  const label = freeStageLabel(stage).toLowerCase()
  if (freeStageIsSuccess(normalizedStatus)) return 'success'
  if (['failed', 'account_banned'].includes(normalizedStatus) || /失败|错误|拒绝|异常/.test(label) || /fail|error|reject|blocked/.test(code)) return 'danger'
  if (['stopped', 'cancelled'].includes(normalizedStatus)) return 'info'
  if (['partial_success', 'pending_rerun', 'twofa_pending'].includes(normalizedStatus) || /等待|待重试|排队|处理中|冷却/.test(label) || /wait|pending|queue|cooldown/.test(code)) return 'warning'
  return 'primary'
}

export function freeStageDetail(stage: unknown, stageLabel?: unknown, status?: unknown) {
  if (freeStageIsSuccess(status)) return '成功'
  const raw = String(stage || '').trim()
  const label = String(stageLabel || '').trim() || freeStageLabel(raw)
  return raw && raw !== label ? `${label} · ${raw}` : label
}
