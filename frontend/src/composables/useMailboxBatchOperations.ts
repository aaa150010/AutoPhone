import { computed, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { ApiError, startMailboxBatchOperation } from '../api/client'
import type {
  MailboxBatchOperation,
  MailboxOperationKind,
  MailboxPayload,
  MailboxRow,
} from '../types/api'
import {
  claimMailboxOperationNotification,
  claimMailboxOperationRetryPrompt,
  mailboxOperationNotificationId,
  retryableOpenAITestBindings,
  shouldApplyMailboxOperationUpdate,
} from '../utils/mailboxOperationState'
import { mailboxOperationMessage } from '../utils/mailboxOperationPresentation'

export function useMailboxBatchOperations(options: {
  candidates: (kind: MailboxOperationKind) => MailboxRow[]
  clearSelection: () => void
  onStarted?: () => void
}) {
  const operation = ref<MailboxBatchOperation | null>(null)
  const startingKind = ref<MailboxOperationKind | null>(null)
  let inMemoryNotification = ''
  let inMemoryRetryPrompt = ''
  let clearedTerminalJob = ''

  const running = computed(() => operation.value?.status === 'running')
  const busy = computed(() => running.value || startingKind.value !== null)
  const queryingQuota = computed(() => (
    startingKind.value === 'quota'
    || (running.value && operation.value?.kind === 'quota')
  ))
  const testingOpenAI = computed(() => (
    startingKind.value === 'openai_test'
    || (running.value && operation.value?.kind === 'openai_test')
  ))
  const quotaProgress = computed(() => (
    operation.value?.kind === 'quota' && running.value
      ? `${operation.value.completed}/${operation.value.total}`
      : ''
  ))
  const openaiTestProgress = computed(() => (
    operation.value?.kind === 'openai_test' && running.value
      ? `${operation.value.completed}/${operation.value.total}`
      : ''
  ))

  async function offerNetworkRetry(next: MailboxBatchOperation) {
    const retryRows = retryableOpenAITestBindings(next)
    if (!retryRows.length) return
    const id = mailboxOperationNotificationId(next)
    if (inMemoryRetryPrompt === id) return
    try {
      if (!claimMailboxOperationRetryPrompt(next, window.localStorage)) {
        inMemoryRetryPrompt = id
        return
      }
    } catch {
      // Keep one prompt per terminal job even when local storage is unavailable.
    }
    inMemoryRetryPrompt = id
    try {
      await ElMessageBox.confirm(
        `${retryRows.length} 个账号因本机网络连接问题测试失败，是否只重新测试这些账号？`,
        '重新测试网络失败项',
        {
          type: 'warning',
          confirmButtonText: '重新测试',
          cancelButtonText: '暂不测试',
        },
      )
    } catch {
      return
    }
    await start('openai_test', retryRows)
  }

  function notifyTerminal(next: MailboxBatchOperation) {
    if (next.status === 'running') return
    const id = mailboxOperationNotificationId(next)
    let showNotification = inMemoryNotification !== id
    if (showNotification) {
      try {
        if (!claimMailboxOperationNotification(next, window.localStorage)) {
          showNotification = false
        }
      } catch {
        // A private browsing policy may disable storage; in-memory tracking still deduplicates polls.
      }
      inMemoryNotification = id
    }
    if (showNotification) {
      const message = mailboxOperationMessage(next)
      if (next.status === 'failed') {
        ElMessage.error(message)
      } else if (next.failed || next.skipped || next.rate_limited || next.not_ready) {
        ElMessage.warning(message)
      } else {
        ElMessage.success(message)
      }
    }
    void offerNetworkRetry(next)
  }

  function sync(
    payload: MailboxPayload | { mailboxes?: MailboxPayload } | any,
    authoritativeJobId = '',
  ) {
    const source = payload?.mailboxes || payload
    if (!source || !Object.prototype.hasOwnProperty.call(source, 'operation')) return
    const next = source.operation
    const normalized = next && typeof next === 'object' ? next : null
    if (!shouldApplyMailboxOperationUpdate(operation.value, normalized, authoritativeJobId)) return
    operation.value = normalized
    if (operation.value) {
      if (
        operation.value.kind === 'openai_test'
        && operation.value.status !== 'running'
        && clearedTerminalJob !== operation.value.job_id
      ) {
        options.clearSelection()
        clearedTerminalJob = operation.value.job_id
      }
      notifyTerminal(operation.value)
    }
  }

  async function start(
    kind: MailboxOperationKind,
    requestedRows?: Array<{ row_id: string; line_no: number }>,
  ) {
    if (busy.value) {
      if (requestedRows) ElMessage.warning('已有邮箱批量操作正在执行，请稍后重试')
      return
    }
    const candidates = requestedRows || options.candidates(kind)
    if (!candidates.length) {
      ElMessage.warning(kind === 'quota'
        ? '当前没有可查询 OpenAI 额度的成功账号'
        : '当前没有可测试的邮箱')
      return
    }
    startingKind.value = kind
    if (kind === 'openai_test') options.clearSelection()
    try {
      const result = await startMailboxBatchOperation(
        kind,
        candidates.map(row => ({ row_id: row.row_id, line_no: row.line_no })),
      )
      sync(result, result.operation.job_id)
      options.onStarted?.()
    } catch (error: any) {
      if (error instanceof ApiError && error.payload?.operation) {
        sync(error.payload, error.payload.operation.job_id)
      }
      ElMessage.error(error?.message || (kind === 'quota'
        ? '批量查询 OpenAI 额度失败'
        : '本机 OpenAI 连接测试失败'))
    } finally {
      startingKind.value = null
    }
  }

  return {
    operation,
    running,
    busy,
    queryingQuota,
    testingOpenAI,
    quotaProgress,
    openaiTestProgress,
    sync,
    queryQuotas: () => start('quota'),
    testOpenAI: () => start('openai_test'),
  }
}
