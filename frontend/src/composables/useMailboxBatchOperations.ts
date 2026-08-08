import { computed, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { ApiError, startMailboxBatchOperation } from '../api/client'
import type {
  MailboxBatchOperation,
  MailboxOperationKind,
  MailboxPayload,
  MailboxRow,
} from '../types/api'
import {
  claimMailboxOperationNotification,
  mailboxOperationNotificationId,
  shouldApplyMailboxOperationUpdate,
} from '../utils/mailboxOperationState'

export function mailboxOperationMessage(operation: MailboxBatchOperation) {
  if (operation.status === 'failed') {
    return operation.error || '邮箱后台批量操作失败：未返回可用诊断'
  }
  if (operation.kind === 'quota') {
    const details = [
      operation.failed ? `失败 ${operation.failed} 条` : '',
      operation.skipped ? `跳过 ${operation.skipped} 条` : '',
    ].filter(Boolean).join('，')
    return `已查询 OpenAI 额度 ${operation.succeeded} 条${details ? `，${details}` : ''}`
  }
  const details = [
    operation.failed ? `测试失败 ${operation.failed} 条` : '',
    operation.rate_limited ? `额度受限 ${operation.rate_limited} 条` : '',
    operation.not_ready ? `未上传 ${operation.not_ready} 条` : '',
  ].filter(Boolean).join('，')
  return `已测试 ${operation.tested} 条${details ? `，${details}` : ''}`
}

export function useMailboxBatchOperations(options: {
  candidates: () => MailboxRow[]
  clearSelection: () => void
  onStarted?: () => void
}) {
  const operation = ref<MailboxBatchOperation | null>(null)
  const startingKind = ref<MailboxOperationKind | null>(null)
  let inMemoryNotification = ''
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

  function notifyTerminal(next: MailboxBatchOperation) {
    if (next.status === 'running') return
    const id = mailboxOperationNotificationId(next)
    if (inMemoryNotification === id) return
    try {
      if (!claimMailboxOperationNotification(next, window.localStorage)) {
        inMemoryNotification = id
        return
      }
    } catch {
      // A private browsing policy may disable storage; in-memory tracking still deduplicates polls.
    }
    inMemoryNotification = id
    const message = mailboxOperationMessage(next)
    if (next.status === 'failed') {
      ElMessage.error(message)
    } else if (next.failed || next.skipped || next.rate_limited || next.not_ready) {
      ElMessage.warning(message)
    } else {
      ElMessage.success(message)
    }
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

  async function start(kind: MailboxOperationKind) {
    if (busy.value) return
    const candidates = options.candidates()
    if (!candidates.length) {
      ElMessage.warning(kind === 'quota'
        ? '当前没有可查询 OpenAI 额度的成功账号'
        : '当前没有可测试的 OpenAI 成功账号')
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
