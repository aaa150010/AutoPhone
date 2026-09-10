/** Shared date formatting helpers.

Every formatter here preserves the exact output of the page-local
implementations it replaces, so switching call sites over never changes what
the operator sees.
*/

/** Parse a persisted timestamp (seconds or ISO string) into a Date. */
export function parseTimestamp(value: unknown): Date | null {
  if (value === null || value === undefined || value === '') return null
  if (typeof value === 'number' && Number.isFinite(value)) {
    return new Date(value < 10_000_000_000 ? value * 1000 : value)
  }
  if (typeof value === 'string' && /^\d+$/.test(value.trim())) {
    const numeric = Number(value.trim())
    return new Date(numeric < 10_000_000_000 ? numeric * 1000 : numeric)
  }
  const date = new Date(String(value))
  return Number.isNaN(date.getTime()) ? null : date
}

/** Default locale rendering used by task/mailbox "created at" columns. */
export function formatDateTime(value: unknown): string {
  const date = parseTimestamp(value)
  return date ? date.toLocaleString() : ''
}

/** Locale rendering with a dash fallback for empty rows. */
export function formatDateTimeOrDash(value: unknown): string {
  const date = parseTimestamp(value)
  return date ? date.toLocaleString() : '-'
}

/** 24-hour zh-CN rendering, e.g. mailbox quota / draft timestamps. */
export function formatDateTimeZh(value: unknown): string {
  const date = parseTimestamp(value)
  return date ? date.toLocaleString('zh-CN', { hour12: false }) : '-'
}

/** Compact month/day hour/minute label used by batch columns; '-' fallback. */
export function formatShortDateTime(value: unknown): string {
  const date = parseTimestamp(value)
  if (!date) return '-'
  return date.toLocaleString('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  })
}
