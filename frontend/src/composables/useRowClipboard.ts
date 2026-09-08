/** Per-row copy/open loading-state helper.

The runtime/Free task tables repeat one template for every copy action:
guard against double clicks with a per-row loading array, await a value
producer, write it to the clipboard and surface the outcome through
ElMessage.  This composable owns the loading array so callers only describe
the per-row value producer.
*/
import { ref } from 'vue'
import { errorMessage } from '../utils/errorMessage'
import { ElMessage } from 'element-plus'
import { copyText } from '../utils/clipboard'

export function useRowClipboard() {
  const loadingIds = ref<string[]>([])

  function isBusy(rowId: string): boolean {
    return loadingIds.value.includes(rowId)
  }

  /**
   * Run one row-scoped clipboard action.
   *
   * ``produce`` returns the text to copy (or empty string to report the
   * ``emptyMessage`` as info).  ``successMessage`` may be a function so the
   * wording can reflect values learned inside ``produce``.  All feedback
   * strings keep the exact wording of the page-local implementations this
   * replaces.
   */
  async function copyForRow(options: {
    rowId: string
    produce: () => Promise<string> | string
    successMessage: string | (() => string)
    errorMessage: string
    emptyMessage?: string
  }): Promise<void> {
    const rowId = options.rowId
    if (!rowId || isBusy(rowId)) return
    if (!navigator.clipboard?.writeText) {
      ElMessage.error('当前浏览器不支持安全剪贴板写入')
      return
    }
    loadingIds.value = [...loadingIds.value, rowId]
    try {
      const value = String(await options.produce() || '').trim()
      if (options.emptyMessage && !value) {
        ElMessage.info(options.emptyMessage)
        return
      }
      const message = typeof options.successMessage === 'function'
        ? options.successMessage()
        : options.successMessage
      await copyText(value, message)
    } catch (error) {
      ElMessage.error(errorMessage(error) || options.errorMessage)
    } finally {
      loadingIds.value = loadingIds.value.filter(id => id !== rowId)
    }
  }

  return { loadingIds, isBusy, copyForRow }
}
