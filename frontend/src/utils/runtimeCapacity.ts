export interface RuntimeCapacitySnapshot {
  active?: unknown
  base?: unknown
  ceiling?: unknown
  last_reason?: unknown
  limit?: unknown
  pause_remaining_seconds?: unknown
  restore_ceiling?: unknown
  waiting?: unknown
}

export interface TaskCapacityView {
  active: number
  base: number
  currentLimit: number
  degraded: boolean
  healthCeiling: number
  pauseRemaining: number
  reasonLabel: string
  tooltip: string
  waiting: number
}

function capacityNumber(value: unknown) {
  const parsed = Number(value ?? 0)
  return Number.isFinite(parsed) ? Math.max(0, parsed) : 0
}

const REASON_LABELS: Record<string, string> = {
  account_banned_burst_expired: '封禁突发容量已到期',
  fd_usage_above_70_percent: '文件描述符使用率已达 70%',
  fd_usage_above_80_percent: '文件描述符使用率已达 80%',
  infrastructure_pressure: '持续基础设施压力',
  infrastructure_pressure_immediate: '即时基础设施压力',
  protocol_pressure: '协议请求压力',
  resource_fd_exhausted: '文件描述符耗尽',
}

function degradationReason(value: unknown) {
  const reason = String(value ?? '').trim().toLowerCase()
  if (!reason || reason === 'configured_baseline') return ''
  if (REASON_LABELS[reason]) return REASON_LABELS[reason]
  if (reason.includes('emfile') || reason.includes('fd_')) return '文件描述符压力'
  if (reason.includes('429') || reason.includes('rate_limit')) return '请求限流'
  if (reason.includes('session')) return '会话已失效'
  if (reason.includes('protocol')) return '协议请求压力'
  if (reason.includes('resource')) return '系统资源压力'
  if (reason.includes('pressure')) return '基础设施压力'
  return '运行保护已触发'
}

export function buildTaskCapacityView(
  snapshot: RuntimeCapacitySnapshot | null | undefined,
): TaskCapacityView {
  const value = snapshot ?? {}
  const active = capacityNumber(value.active)
  const base = capacityNumber(value.base)
  const currentLimit = capacityNumber(value.limit)
  const pauseRemaining = capacityNumber(value.pause_remaining_seconds)
  const waiting = capacityNumber(value.waiting)
  const healthCeiling = capacityNumber(value.restore_ceiling)
    || capacityNumber(value.ceiling)
    || Math.max(base, currentLimit)
  const translatedReason = degradationReason(value.last_reason)
  const degraded = pauseRemaining > 0
    || (base > 0 && currentLimit < base)
    || Boolean(translatedReason && ![
      'success_streak_with_backlog',
      'fd_usage_stable_below_60_percent',
    ].includes(String(value.last_reason ?? '').trim().toLowerCase()))
  const reasonLabel = degraded
    ? translatedReason
      || (base > 0 && currentLimit < base ? '当前容量低于基线' : '新任务准入暂时停止')
    : ''
  const tooltipParts = [
    `基线 ${base}`,
    `当前限制 ${currentLimit}`,
    `健康上限 ${healthCeiling}`,
  ]
  if (reasonLabel) tooltipParts.push(`降档原因：${reasonLabel}`)
  if (pauseRemaining > 0) tooltipParts.push(`暂停准入 ${pauseRemaining} 秒`)

  return {
    active,
    base,
    currentLimit,
    degraded,
    healthCeiling,
    pauseRemaining,
    reasonLabel,
    tooltip: tooltipParts.join('；'),
    waiting,
  }
}
