export const RUN_LOG_PANEL_WIDTH_KEY = 'gptphone.run.log-panel-width'
export const DEFAULT_RUN_LOG_PANEL_WIDTH = 700
export const MIN_RUN_LOG_PANEL_WIDTH = 240
export const MAX_RUN_LOG_PANEL_WIDTH = 760

export function clampRunLogPanelWidth(value: unknown) {
  if (value === null || value === undefined || String(value).trim() === '') return DEFAULT_RUN_LOG_PANEL_WIDTH
  const parsed = Number(value)
  if (!Number.isFinite(parsed)) return DEFAULT_RUN_LOG_PANEL_WIDTH
  return Math.round(Math.min(MAX_RUN_LOG_PANEL_WIDTH, Math.max(MIN_RUN_LOG_PANEL_WIDTH, parsed)))
}

export function readRunLogPanelWidth(storage: Pick<Storage, 'getItem'> | null | undefined) {
  if (!storage) return DEFAULT_RUN_LOG_PANEL_WIDTH
  return clampRunLogPanelWidth(storage.getItem(RUN_LOG_PANEL_WIDTH_KEY))
}

export function saveRunLogPanelWidth(storage: Pick<Storage, 'setItem'> | null | undefined, value: unknown) {
  if (!storage) return DEFAULT_RUN_LOG_PANEL_WIDTH
  const width = clampRunLogPanelWidth(value)
  storage.setItem(RUN_LOG_PANEL_WIDTH_KEY, String(width))
  return width
}
