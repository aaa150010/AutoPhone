import { onBeforeUnmount, ref, watch } from 'vue'
import type { TaskProgress } from '../types/api'

interface ProgressRow {
  progress?: TaskProgress | null
}

export function useTaskProgressClock(rows: () => ProgressRow[], additionallyActive: () => boolean = () => false) {
  const nowSeconds = ref(Math.floor(Date.now() / 1000))
  let timer = 0

  function isActive() {
    return additionallyActive() || rows().some(row => row.progress && row.progress.finished_at == null)
  }

  function stop() {
    if (!timer) return
    window.clearInterval(timer)
    timer = 0
  }

  function sync() {
    if (!isActive()) {
      stop()
      return
    }
    nowSeconds.value = Math.floor(Date.now() / 1000)
    if (!timer) {
      timer = window.setInterval(() => {
        nowSeconds.value = Math.floor(Date.now() / 1000)
        if (!isActive()) stop()
      }, 1000)
    }
  }

  watch([rows, additionallyActive], sync, { immediate: true })
  onBeforeUnmount(stop)

  return nowSeconds
}
