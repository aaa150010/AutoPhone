import type { MailboxBatchOperation } from '../types/api'

export function mailboxOperationMessage(operation: MailboxBatchOperation) {
  if (operation.status === 'failed') {
    return operation.error || '邮箱后台批量操作失败：未返回可用诊断'
  }
  if (operation.kind === 'quota') {
    const details = [
      operation.deactivated_deleted ? `已删除停用空间邮箱 ${operation.deactivated_deleted} 条` : '',
      operation.failed ? `失败 ${operation.failed} 条` : '',
      operation.skipped ? `跳过 ${operation.skipped} 条` : '',
    ].filter(Boolean).join('，')
    return `已查询 OpenAI 额度 ${operation.succeeded} 条${details ? `，${details}` : ''}`
  }
  const details = [
    operation.failed ? `测试失败 ${operation.failed} 条` : '',
    operation.rate_limited ? `额度受限 ${operation.rate_limited} 条` : '',
    operation.not_ready ? `缺少本地 OAuth 凭据 ${operation.not_ready} 条` : '',
  ].filter(Boolean).join('，')
  return `已测试 ${operation.tested} 条${details ? `，${details}` : ''}`
}
