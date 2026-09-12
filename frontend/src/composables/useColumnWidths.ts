import { ref } from 'vue'

export type DragColumn = { label?: string; noLabelText?: string }

// Persist user-dragged column widths per table, keyed by column label so the
// mapping survives column reordering in future edits.
// Bump to force another one-time reset of every table's saved widths.
const ONE_TIME_RESET_VERSION = 'v1'

// One-time migration: clear widths saved before a layout change (e.g. new or
// renamed columns) so stale drag results never shadow the new defaults. The
// flag marks the reset as done, so later drags persist normally again.
function consumeOneTimeReset(storageKey: string) {
  const flagKey = `${storageKey}.one-time-reset.${ONE_TIME_RESET_VERSION}`
  try {
    if (window.localStorage.getItem(flagKey)) return
    window.localStorage.removeItem(storageKey)
    window.localStorage.setItem(flagKey, '1')
  } catch {
    // storage unavailable: nothing persisted to reset
  }
}

export function useColumnWidths(storageKey: string, options?: { autoResetOnce?: boolean }) {
  if (options?.autoResetOnce) consumeOneTimeReset(storageKey)
  const widths = ref<Record<string, number>>(readStored())

  function readStored(): Record<string, number> {
    try {
      const raw = window.localStorage.getItem(storageKey)
      const parsed = raw ? JSON.parse(raw) : {}
      return parsed && typeof parsed === 'object' ? parsed : {}
    } catch {
      return {}
    }
  }

  function colWidth(label: string, fallback: number): number {
    const saved = widths.value[label]
    return Number.isFinite(saved) && Number(saved) >= 40 ? Number(saved) : fallback
  }

  function handleHeaderDragend(newWidth: number, _oldWidth: number, column: DragColumn) {
    const key = String(column?.label || column?.noLabelText || '').trim()
    if (!key) return
    const width = Math.max(40, Math.round(Number(newWidth) || 0))
    if (width === colWidth(key, -1)) return
    widths.value = { ...widths.value, [key]: width }
    try {
      window.localStorage.setItem(storageKey, JSON.stringify(widths.value))
    } catch {
      // storage unavailable (quota/private mode): keep in-memory widths only
    }
  }

  function resetWidths() {
    widths.value = {}
    try {
      window.localStorage.removeItem(storageKey)
    } catch {
      // storage unavailable: in-memory reset is enough for this session
    }
  }

  return { colWidth, handleHeaderDragend, resetWidths }
}
