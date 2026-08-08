import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import { retryPixelBatchTarget, retryPixelUpload } from '../api/client'

export function usePixelUploadRetry(refresh: () => Promise<unknown>) {
  const retryingKeys = ref<string[]>([])

  async function run(key: string, operation: () => Promise<any>, success: (value: any) => string) {
    if (retryingKeys.value.includes(key)) return
    retryingKeys.value = [...retryingKeys.value, key]
    try {
      const result = await operation()
      ElMessage.success(success(result))
      await refresh()
    } catch (error: any) {
      ElMessage.error(error?.message || '加入 Pixel 重传队列失败')
    } finally {
      retryingKeys.value = retryingKeys.value.filter(value => value !== key)
    }
  }

  function retryRecord(recordId: string, targetId?: string) {
    const key = `${recordId}:${targetId || '*'}`
    return run(
      key,
      () => retryPixelUpload(recordId, targetId),
      () => targetId ? `${targetId} 已加入重传队列` : '失败目标已加入重传队列',
    )
  }

  function retryBatchTarget(batchId: string, targetId: string) {
    const key = `batch:${batchId}:${targetId}`
    return run(
      key,
      () => retryPixelBatchTarget(batchId, targetId),
      result => `${targetId} 已批量加入 ${Number(result?.queued_records || 0)} 组重传记录`,
    )
  }

  return { retryingKeys, retryRecord, retryBatchTarget }
}
