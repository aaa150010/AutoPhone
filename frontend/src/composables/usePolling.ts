/** Adaptive setTimeout polling loop shared by the runtime/mailbox pages.

The loop re-awaits ``tick`` before scheduling the next round, so a slow
refresh never overlaps itself.  The delay is recomputed each round through
``delayMs`` so callers can poll faster while a batch is running.  ``stop``
clears the pending timer and makes every scheduled round a no-op; it is safe
to call multiple times.
*/
import { getCurrentInstance, onUnmounted } from 'vue'

export interface PollingController {
  /** Schedule the next round now (used right after an explicit refresh). */
  schedule: () => void
  /** Stop the loop; subsequent rounds become no-ops. */
  stop: () => void
}

export function usePolling(
  tick: () => Promise<void> | void,
  delayMs: () => number,
): PollingController {
  let timer = 0
  let stopped = false

  async function loop() {
    if (stopped) return
    await tick()
    if (stopped) return
    timer = window.setTimeout(loop, Math.max(0, delayMs()))
  }

  function schedule() {
    if (stopped) return
    window.clearTimeout(timer)
    timer = window.setTimeout(loop, Math.max(0, delayMs()))
  }

  function stop() {
    stopped = true
    window.clearTimeout(timer)
    timer = 0
  }

  if (getCurrentInstance()) {
    onUnmounted(stop)
  }

  return { schedule, stop }
}
