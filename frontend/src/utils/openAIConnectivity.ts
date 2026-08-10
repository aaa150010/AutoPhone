import type {
  AppState,
  OpenAIAuthConnectivityState,
  OpenAIConnectivityStatus,
  RuntimeCapacitySnapshot,
  RuntimeState,
} from '../types/api'

export type ConnectivityTone = 'success' | 'warning' | 'danger' | 'info'

export interface OpenAIConnectivityBanner {
  type: 'error' | 'warning'
  title: string
  detail: string
}

export interface OpenAIConnectivityView {
  status: OpenAIConnectivityStatus
  sidebarLabel: string
  sidebarDetail: string
  tone: ConnectivityTone
  banner: OpenAIConnectivityBanner | null
}

export interface ConnectivityOutageNotice {
  title: string
  message: string
  type: 'error' | 'warning'
  duration: 0
}

export type ConnectivityNotificationAction =
  | { type: 'open-outage'; incident: string; state: OpenAIAuthConnectivityState }
  | { type: 'close-outage'; incident: string }
  | { type: 'show-recovery'; incident: string; state: OpenAIAuthConnectivityState }

const KNOWN_ORIGINS: Record<string, string> = {
  'auth.openai.com': 'Auth',
  'sentinel.openai.com': 'Sentinel',
}

function numeric(value: unknown) {
  const parsed = Number(value ?? 0)
  return Number.isFinite(parsed) ? Math.max(0, parsed) : 0
}

function revision(value: unknown): number | null {
  const parsed = Number(value)
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : null
}

function runtimeEpoch(value: unknown): number | null {
  const parsed = Number(value)
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null
}

export function preferNewestOpenAIConnectivityState(
  current: AppState | null | undefined,
  incoming: AppState,
): AppState {
  const currentState = current?.runtime?.connectivity?.openai_auth
  const incomingState = incoming.runtime?.connectivity?.openai_auth
  const currentEpoch = runtimeEpoch(currentState?.runtime_epoch)
  const incomingEpoch = runtimeEpoch(incomingState?.runtime_epoch)
  const currentRevision = revision(currentState?.revision)
  const incomingRevision = revision(incomingState?.revision)
  const olderEpoch = currentEpoch !== null && (
    incomingEpoch === null || incomingEpoch < currentEpoch
  )
  const newerEpoch = incomingEpoch !== null && (
    currentEpoch === null || incomingEpoch > currentEpoch
  )
  if (
    !currentState
    || newerEpoch
    || (!olderEpoch && (
      currentRevision === null
      || (incomingRevision !== null && incomingRevision >= currentRevision)
    ))
  ) {
    return incoming
  }
  return {
    ...incoming,
    runtime: {
      ...(incoming.runtime || {}),
      connectivity: {
        ...(incoming.runtime?.connectivity || {}),
        openai_auth: currentState,
      },
    },
  }
}

function protocolSnapshot(runtime: RuntimeState): RuntimeCapacitySnapshot {
  return runtime.concurrency?.protocol || {}
}

function protocolBaseline(runtime: RuntimeState) {
  const protocol = protocolSnapshot(runtime)
  return numeric(protocol.baseline) || numeric(protocol.base)
}

function protocolCeiling(runtime: RuntimeState) {
  const protocol = protocolSnapshot(runtime)
  return numeric(protocol.healthy_ceiling) || numeric(protocol.ceiling) || protocolBaseline(runtime)
}

function normalizedPauseReason(runtime: RuntimeState) {
  const protocol = protocolSnapshot(runtime)
  return String(protocol.pause_reason || protocol.last_reason || '').trim().toLowerCase()
}

function isRateLimitPause(runtime: RuntimeState) {
  const protocol = protocolSnapshot(runtime)
  const reason = normalizedPauseReason(runtime)
  return Boolean(
    (protocol.paused || protocol.suspended || numeric(protocol.pause_remaining_seconds) > 0)
    && (reason.includes('429') || reason.includes('rate_limit') || reason.includes('rate-limit')),
  )
}

function affectedOriginLabel(state: OpenAIAuthConnectivityState) {
  const labels = (state.affected_origins || [])
    .map(origin => KNOWN_ORIGINS[String(origin || '').trim().toLowerCase()])
    .filter((label): label is string => Boolean(label))
  return [...new Set(labels)].join('、')
}

function probeProgress(state: OpenAIAuthConnectivityState) {
  const success = numeric(
    state.probe_successful_rounds
    ?? state.probe_success_rounds
    ?? state.probe?.successful_rounds,
  )
  const required = numeric(state.probe_required_rounds ?? state.probe?.required_rounds)
  if (!required) return ''
  return `探测 ${Math.min(success, required)}/${required}`
}

function nextProbeText(state: OpenAIAuthConnectivityState, nowSeconds: number) {
  const reportedRemaining = numeric(state.next_probe_in_seconds)
  if (reportedRemaining) return `下次探测约 ${Math.ceil(reportedRemaining)} 秒`
  const nextProbeAt = numeric(state.next_probe_at ?? state.probe?.next_probe_at)
  if (!nextProbeAt) return ''
  return `下次探测约 ${Math.max(0, Math.ceil(nextProbeAt - nowSeconds))} 秒`
}

function outageDetail(state: OpenAIAuthConnectivityState, nowSeconds: number) {
  const parts = [
    String(state.reason_label || state.node_label || '代理、TLS 或远端连接异常').trim(),
  ]
  const origins = affectedOriginLabel(state)
  if (origins) parts.push(`受影响：${origins}`)
  const progress = probeProgress(state)
  if (progress) parts.push(progress)
  const nextProbe = nextProbeText(state, nowSeconds)
  if (nextProbe) parts.push(nextProbe)
  return parts.filter(Boolean).join('；')
}

export function buildOpenAIConnectivityView(
  runtime: RuntimeState | null | undefined,
  nowSeconds = Date.now() / 1000,
): OpenAIConnectivityView {
  const current = runtime || {}
  const state = current.connectivity?.openai_auth || {}
  const status = state.status || 'unknown'
  const baseline = protocolBaseline(current)
  const ceiling = protocolCeiling(current)

  const unavailable = status === 'outage' || status === 'recovering'
  if (state.enabled !== false && unavailable) {
    const recovering = status === 'recovering'
    const detail = outageDetail(state, nowSeconds)
    return {
      status,
      sidebarLabel: recovering ? 'OpenAI 恢复确认中' : 'OpenAI 链路中断',
      sidebarDetail: probeProgress(state) || (recovering ? '正在确认双域可达' : '协议请求已暂停'),
      tone: recovering ? 'warning' : 'danger',
      banner: {
        type: recovering ? 'warning' : 'error',
        title: recovering ? 'OpenAI 链路正在恢复确认' : 'OpenAI 鉴权链路异常，新的协议请求已暂停',
        detail,
      },
    }
  }

  if (isRateLimitPause(current)) {
    const remaining = Math.ceil(numeric(protocolSnapshot(current).pause_remaining_seconds))
    const capacity = baseline ? `基线并发 ${baseline}` : '基线并发'
    return {
      status,
      sidebarLabel: 'OpenAI 限流冷却',
      sidebarDetail: remaining ? `剩余 ${remaining} 秒` : '等待恢复准入',
      tone: 'warning',
      banner: {
        type: 'warning',
        title: 'OpenAI 请求限流，新的协议请求正在冷却',
        detail: `${remaining ? `${remaining} 秒后` : '冷却结束后'}按${capacity}继续，本批不再扩容`,
      },
    }
  }

  if (state.enabled === false) {
    return {
      status,
      sidebarLabel: 'OpenAI 保护已关闭',
      sidebarDetail: '链路状态仅供观察',
      tone: 'info',
      banner: null,
    }
  }

  if (status === 'healthy') {
    const stickyBaseline = Boolean(protocolSnapshot(current).sticky_baseline)
    const capacity = baseline
      ? stickyBaseline
        ? `基线 ${baseline} · 本批固定`
        : `基线 ${baseline}${ceiling > baseline ? ` · 上限 ${ceiling}` : ''}`
      : '链路可达'
    return {
      status,
      sidebarLabel: 'OpenAI 链路正常',
      sidebarDetail: capacity,
      tone: 'success',
      banner: null,
    }
  }

  return {
    status: 'unknown',
    sidebarLabel: 'OpenAI 链路待检测',
    sidebarDetail: '尚无链路状态',
    tone: 'info',
    banner: null,
  }
}

export function buildConnectivityOutageNotice(runtime: RuntimeState): ConnectivityOutageNotice {
  const view = buildOpenAIConnectivityView(runtime)
  return {
    title: view.banner?.title || 'OpenAI 鉴权链路异常',
    message: view.banner?.detail || '新的协议请求已暂停，系统正在自动探测。',
    type: view.banner?.type || 'error',
    duration: 0,
  }
}

export function buildConnectivityRecoveryMessage(runtime: RuntimeState) {
  const protocol = protocolSnapshot(runtime)
  const baseline = protocolBaseline(runtime)
  const baselineText = baseline > 0 ? `基线并发 ${baseline}` : '基线并发'
  if (isRateLimitPause(runtime)) {
    const remaining = Math.ceil(numeric(protocol.pause_remaining_seconds))
    const cooldown = remaining > 0 ? `，预计还需 ${remaining} 秒` : ''
    return `链路探测已通过，但 OpenAI 限流冷却仍在继续${cooldown}；冷却结束后按${baselineText}继续。`
  }
  return baseline > 0
    ? `链路探测已通过，新的协议请求已按${baselineText}恢复。`
    : '链路探测已通过，新的协议请求已恢复。'
}

function incidentIdentity(state: OpenAIAuthConnectivityState) {
  return String(
    state.incident_id
    || state.event_id
    || state.detected_at
    || `${state.reason_code || state.node_code || 'openai-connectivity'}:${state.revision || 0}`,
  )
}

function recoveryIdentity(state: OpenAIAuthConnectivityState, incident: string) {
  return `${incident}:${state.recovered_at || state.revision || state.updated_at || 'recovered'}`
}

export function createConnectivityNotificationTracker(limit = 128) {
  const maximum = Math.max(1, Math.min(1024, Math.trunc(Number(limit)) || 1))
  const recovered = new Set<string>()
  const recoveryOrder: string[] = []
  let activeIncident = ''
  let highestEpoch: number | null = null
  let highestRevision: number | null = null
  let highestRevisionIdentity = ''

  function rememberRecovery(identity: string) {
    recovered.add(identity)
    recoveryOrder.push(identity)
    while (recoveryOrder.length > maximum) {
      const oldest = recoveryOrder.shift()
      if (oldest) recovered.delete(oldest)
    }
  }

  return {
    observe(state: OpenAIAuthConnectivityState | null | undefined): ConnectivityNotificationAction[] {
      if (!state?.status) return []
      const observedEpoch = runtimeEpoch(state.runtime_epoch)
      if (highestEpoch !== null && (
        observedEpoch === null || observedEpoch < highestEpoch
      )) {
        return []
      }
      if (observedEpoch !== null && (
        highestEpoch === null || observedEpoch > highestEpoch
      )) {
        highestEpoch = observedEpoch
        highestRevision = null
        highestRevisionIdentity = ''
      }
      const observedRevision = revision(state.revision)
      if (observedRevision !== null) {
        const identity = `${state.enabled !== false}:${state.status}:${incidentIdentity(state)}:${state.recovered_at || ''}`
        if (
          highestRevision !== null
          && (
            observedRevision < highestRevision
            || (observedRevision === highestRevision && identity !== highestRevisionIdentity)
          )
        ) {
          return []
        }
        if (highestRevision === null || observedRevision > highestRevision) {
          highestRevision = observedRevision
          highestRevisionIdentity = identity
        }
      }
      if (state.status === 'unknown' || state.enabled === false) {
        if (!activeIncident) return []
        const incident = activeIncident
        activeIncident = ''
        return [{ type: 'close-outage', incident }]
      }
      const unavailable = state.status === 'outage' || state.status === 'recovering'
      if (unavailable) {
        const incident = incidentIdentity(state)
        if (activeIncident === incident) return []
        const actions: ConnectivityNotificationAction[] = []
        if (activeIncident) actions.push({ type: 'close-outage', incident: activeIncident })
        activeIncident = incident
        actions.push({ type: 'open-outage', incident, state })
        return actions
      }

      if (state.status !== 'healthy' || !activeIncident) return []
      const incident = activeIncident
      activeIncident = ''
      const actions: ConnectivityNotificationAction[] = [{ type: 'close-outage', incident }]
      const recovery = recoveryIdentity(state, incident)
      if (!recovered.has(recovery)) {
        rememberRecovery(recovery)
        actions.push({ type: 'show-recovery', incident, state })
      }
      return actions
    },
  }
}
