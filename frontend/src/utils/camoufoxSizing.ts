/**
 * Mirror of the backend Camoufox pool auto-sizing formula
 * (`mac_overrides/free_camoufox/pool_sizing.py`) for settings-page preview
 * only — the backend derivation at batch start stays authoritative.
 *
 * Capacity rules: contexts per process stay at 3 while the worker width is
 * small (≤6) and rise to 4 beyond; one extra context of headroom covers
 * per-slot recycle windows; the process count is capped at 4 so the maximum
 * capacity is 4 × 4 = 16, exactly the concurrency ceiling.
 */

export interface CamoufoxPoolSizingPreview {
  /** Real executor width: min(concurrency, targetCount, 16). */
  workers: number
  poolSize: number
  maxContexts: number
  capacity: number
}

function clampInt(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min
  return Math.min(max, Math.max(min, Math.floor(value)))
}

/** Derive the effective Camoufox pool footprint for preview display. */
export function deriveCamoufoxPoolSizing(concurrency: number, targetCount: number): CamoufoxPoolSizingPreview {
  const workers = clampInt(
    Math.min(Number(concurrency) || 3, Number(targetCount) || 1),
    1,
    16,
  )
  const maxContexts = workers <= 6 ? 3 : 4
  const poolSize = clampInt(Math.ceil((workers + 1) / maxContexts), 1, 4)
  return { workers, poolSize, maxContexts, capacity: poolSize * maxContexts }
}
