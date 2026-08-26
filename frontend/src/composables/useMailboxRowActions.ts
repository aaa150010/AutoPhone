import { nextTick } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  api,
  ApiError,
  getMailboxTotp,
  getMailboxLatestCode,
  getMailboxUrl,
  markMailboxRowsManualUsed,
  moveMailboxRowsToDraft,
  reloginMailboxRows,
  restoreMailboxRowsManualUsed,
  setMailboxRowsUnavailable,
} from '../api/client'
import type { MailboxRow, MailboxRowAction } from '../types/api'
import { needsSub2Rerun } from '../utils/mailboxFilters'

type ReadonlyValue<T> = { readonly value: T }
type MutableValue<T> = { value: T }

interface MailboxRowActionOptions {
  loadingPasswords: MutableValue<string[]>
  loadingTotp: MutableValue<string[]>
  rowActionLoading: MutableValue<string[]>
  mutating: MutableValue<boolean>
  batchBusy: ReadonlyValue<boolean>
  refreshGuard: { invalidate: () => void }
  refresh: () => Promise<void>
  applyMailboxPayload: (payload: any) => void
  scheduleMailboxPoll: (delay: number) => void
}

export function useMailboxRowActions(options: MailboxRowActionOptions) {
  async function copyPassword(row: MailboxRow) {
    if (options.loadingPasswords.value.includes(row.row_id)) return
    if (!navigator.clipboard?.writeText) {
      ElMessage.error('当前浏览器不支持安全剪贴板写入')
      return
    }
    options.loadingPasswords.value = [...options.loadingPasswords.value, row.row_id]
    try {
      const result: { password: string } = await api('/api/mailboxes/password', {
        row_id: row.row_id,
        line_no: row.line_no,
      })
      await navigator.clipboard.writeText(String(result.password || ''))
      ElMessage.success('已复制密码')
    } catch (error: any) {
      if (error instanceof ApiError && error.payload?.code === 'mailbox_row_stale') {
        await options.refresh()
      }
      ElMessage.error(error?.message || '复制密码失败')
    } finally {
      options.loadingPasswords.value = options.loadingPasswords.value.filter(
        id => id !== row.row_id,
      )
    }
  }

  async function copyEmail(row: MailboxRow) {
    const value = String(row.email || '').trim()
    if (!value) return
    if (!navigator.clipboard?.writeText) {
      ElMessage.error('当前浏览器不支持安全剪贴板写入')
      return
    }
    try {
      await navigator.clipboard.writeText(value)
      ElMessage.success('已复制邮箱')
    } catch {
      ElMessage.error('复制邮箱失败')
    }
  }

  async function copyTotp(row: MailboxRow) {
    if (!row.has_totp || options.loadingTotp.value.includes(row.row_id)) return
    if (!navigator.clipboard?.writeText) {
      ElMessage.error('当前浏览器不支持安全剪贴板写入')
      return
    }
    options.loadingTotp.value = [...options.loadingTotp.value, row.row_id]
    try {
      const result = await getMailboxTotp({ row_id: row.row_id, line_no: row.line_no })
      await navigator.clipboard.writeText(String(result.code || ''))
      ElMessage.success(`已复制临时 2FA 验证码，约 ${result.remaining} 秒后刷新`)
    } catch (error: any) {
      if (error instanceof ApiError && error.payload?.code === 'mailbox_row_stale') {
        await options.refresh()
      }
      ElMessage.error(error?.message || '复制临时 2FA 验证码失败')
    } finally {
      options.loadingTotp.value = options.loadingTotp.value.filter(id => id !== row.row_id)
    }
  }

  async function openMailboxUrl(row: MailboxRow) {
    if (!row.has_mailbox_url) return
    const target = window.open('', '_blank')
    if (!target) {
      ElMessage.error('浏览器阻止了新窗口，请允许弹出窗口后重试')
      return
    }
    try {
      target.opener = null
      const result = await getMailboxUrl({ row_id: row.row_id, line_no: row.line_no })
      target.location.href = String(result.mailbox_url || '')
    } catch (error: any) {
      target.close()
      if (error instanceof ApiError && error.payload?.code === 'mailbox_row_stale') {
        await options.refresh()
      }
      ElMessage.error(error?.message || '打开取件 URL 失败')
    }
  }

  async function copyLatestCode(row: MailboxRow) {
    if (!row.has_mailbox_url || options.rowActionLoading.value.includes(row.row_id)) return
    if (!navigator.clipboard?.writeText) {
      ElMessage.error('当前浏览器不支持安全剪贴板写入')
      return
    }
    setActionLoading(row, true)
    try {
      const result = await getMailboxLatestCode({ row_id: row.row_id, line_no: row.line_no })
      const code = String(result.code || '').trim()
      if (!code) {
        ElMessage.info('未找到新的 OpenAI 邮箱验证码')
        return
      }
      await navigator.clipboard.writeText(code)
      ElMessage.success('验证码已复制')
    } catch (error: any) {
      if (error instanceof ApiError && error.payload?.code === 'mailbox_row_stale') await options.refresh()
      ElMessage.error(error?.message || '提取邮箱验证码失败')
    } finally {
      setActionLoading(row, false)
    }
  }

  function rowBinding(row: MailboxRow) {
    return [{ row_id: row.row_id, line_no: row.line_no }]
  }

  function setActionLoading(row: MailboxRow, loading: boolean) {
    if (loading) {
      if (!options.rowActionLoading.value.includes(row.row_id)) {
        options.rowActionLoading.value = [...options.rowActionLoading.value, row.row_id]
      }
      return
    }
    options.rowActionLoading.value = options.rowActionLoading.value.filter(
      id => id !== row.row_id,
    )
  }

  async function runMutation(
    row: MailboxRow,
    confirmation: string,
    action: () => Promise<any>,
    successMessage: string | ((result: any) => string),
  ) {
    if (
      options.mutating.value
      || options.batchBusy.value
      || options.rowActionLoading.value.includes(row.row_id)
    ) return
    try {
      await ElMessageBox.confirm(confirmation, '确认操作', { type: 'warning' })
    } catch {
      return
    }

    setActionLoading(row, true)
    options.mutating.value = true
    options.refreshGuard.invalidate()
    try {
      const result = await action()
      options.applyMailboxPayload(result)
      await nextTick()
      ElMessage.success(
        typeof successMessage === 'function' ? successMessage(result) : successMessage,
      )
    } catch (error: any) {
      if (error instanceof ApiError && error.status === 409) {
        window.setTimeout(() => void options.refresh(), 0)
      }
      ElMessage.error(error?.message || '操作失败')
    } finally {
      setActionLoading(row, false)
      options.mutating.value = false
    }
  }

  async function handleRowAction(action: MailboxRowAction, row: MailboxRow) {
    const bindings = rowBinding(row)
    const actions: Partial<Record<MailboxRowAction, () => Promise<void>>> = {
      copy_email: () => copyEmail(row),
      copy_password: () => copyPassword(row),
      copy_totp: () => copyTotp(row),
      open_url: () => openMailboxUrl(row),
      copy_latest_code: () => copyLatestCode(row),
      manual_used: () => runMutation(
        row,
        '确认将该邮箱标记为已手动接码？标记后会从可运行池移出。',
        () => markMailboxRowsManualUsed(bindings),
        result => `已标记手动接码 ${Number(result?.used || 0)} 条`,
      ),
      manual_unused: () => runMutation(
        row,
        '确认将该邮箱标记为未用并放回可运行池？',
        () => restoreMailboxRowsManualUsed(bindings),
        result => `已放回可运行 ${Number(result?.restored || 0)} 条`,
      ),
      draft: () => runMutation(
        row,
        '确认将该邮箱放入草稿箱？放入后不会参与运行。',
        () => moveMailboxRowsToDraft(bindings),
        result => `已放入草稿箱 ${Number(result?.drafted || 0)} 条`,
      ),
      restore: () => runMutation(
        row,
        '确认将该邮箱恢复为可运行状态？',
        () => api('/api/mailboxes/restore', { rows: bindings, line_nos: [row.line_no] }),
        '已恢复为可运行',
      ),
      unavailable: () => runMutation(
        row,
        '确认将该邮箱设置为不可用？',
        () => setMailboxRowsUnavailable(bindings),
        result => `已设置为不可用 ${Number(result?.unavailable || 0)} 条`,
      ),
      relogin: () => needsSub2Rerun(row.sub2_status)
        ? runMutation(
            row,
            '确认对该邮箱执行无手机号重登并更新 SUB2？',
            async () => {
              const result = await reloginMailboxRows(bindings)
              options.scheduleMailboxPoll(0)
              return result
            },
            '已启动重登任务',
          )
        : Promise.resolve(),
      delete: () => runMutation(
        row,
        '确定删除该邮箱？源邮箱行和历史结果会保留。',
        () => api('/api/mailboxes/delete', { rows: bindings, line_nos: [row.line_no] }),
        '已删除邮箱',
      ),
    }
    await actions[action]?.()
  }

  return {
    copyEmail,
    copyPassword,
    copyTotp,
    handleRowAction,
    openMailboxUrl,
    copyLatestCode,
  }
}
