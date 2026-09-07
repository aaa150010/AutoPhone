import { ref } from 'vue'

// Persist user-dragged column widths per table, keyed by column label so the
// mapping survives column reordering in future edits.
export function useColumnWidths(storageKey: string) {
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

  function handleHeaderDragend(newWidth: number, _oldWidth: number, column: { label?: string; noLabelText?: string }) {
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

  return { colWidth, handleHeaderDragend }
}
