/**
 * Shared display label for Free registration driver values.
 *
 * Normalizes protocol/camoufox drivers to their Chinese labels and maps any
 * other non-empty value to the historical-driver label. ``emptyFallback`` lets
 * each call site keep its own label for empty/missing driver values.
 */

const DRIVER_LABELS: Record<string, string> = {
  protocol: '全协议',
  camoufox: 'Camoufox',
}

/** Protocol variant label override, e.g. the log center's short "协议". */
export function freeDriverLabel(value: unknown, emptyFallback = 'Free', protocolLabel = '全协议'): string {
  const normalized = String(value || '').trim().toLowerCase()
  if (!normalized) return emptyFallback
  if (normalized === 'protocol') return protocolLabel
  return DRIVER_LABELS[normalized] || '历史链路'
}
