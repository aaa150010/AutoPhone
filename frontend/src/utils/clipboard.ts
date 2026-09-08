/** Shared clipboard helpers with consistent user feedback. */

import { ElMessage } from 'element-plus'
import { errorMessage } from './errorMessage'

/** Copy plain text, reporting success/failure through ElMessage. */
export async function copyText(value: string, successMessage = '已复制'): Promise<boolean> {
  if (!navigator.clipboard?.writeText) {
    ElMessage.warning('当前环境不支持复制')
    return false
  }
  try {
    await navigator.clipboard.writeText(value)
    ElMessage.success(successMessage)
    return true
  } catch (error) {
    ElMessage.error(errorMessage(error) || '复制失败')
    return false
  }
}

/** Reject empty payloads before touching the clipboard. */
export async function copyTextRequired(value: string, successMessage = '已复制'): Promise<boolean> {
  if (!value) return false
  return copyText(value, successMessage)
}
