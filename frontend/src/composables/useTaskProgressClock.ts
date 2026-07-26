import { onBeforeUnmount, ref, watch } from 'vue'
import type { TaskProgress } from '../types/api'

interface ProgressRow {
  progress?: TaskProgress | null
}

export function useTaskProgressClock(rows: () => ProgressRow[]) {
  const nowSeconds = ref(Math.floor(Date.now() / 1000))
  let timer = 0

  function stop() {
    if (!timer) return
    window.clearInterval(timer)
    timer = 0
  }

  function sync() {
    const active = rows().some(row => row.progress && row.progress.finished_at == null)
    if (!active) {
      stop()
      return
    }
    nowSeconds.value = Math.floor(Date.now() / 1000)
    if (!timer) {
      timer = window.setInterval(() => {
        nowSeconds.value = Math.floor(Date.now() / 1000)
      }, 1000)
    }
  }

  watch(rows, sync, { immediate: true })
  onBeforeUnmount(stop)

  return nowSeconds
}
