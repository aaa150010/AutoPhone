/** Row-level Free task actions: secret copying, mailbox URL and latest code. */

import { ref } from 'vue'
import { openMailboxUrlInTab } from '../utils/openMailboxTab'
import { errorMessage } from '../utils/errorMessage'
import { ElMessage } from 'element-plus'
import {
  getFreeMailboxUrl,
  getFreeSecret,
  getFreeTaskLatestCode,
  type FreeTaskRow,
} from '../api/client'
import { freeRowSecretLookup, freeTaskSecretLookup } from '../utils/freeSecretLookup'

export type FreeSecretKind = 'token' | 'password' | 'totp' | 'credential'

export function useFreeTaskRowActions() {
  const loadingEmailTaskIds = ref<string[]>([])
  const loadingLatestCodeTaskIds = ref<string[]>([])
  const openingMailboxUrlTaskIds = ref<string[]>([])

  /** Copy one secret kind for a batch of tasks via the server-side secret API. */
  async function copyTaskSecret(kind: FreeSecretKind, tasks: FreeTaskRow[], label: string) {
    const ids = tasks.map(task => String(task?.task_id || '')).filter(Boolean)
    if (!ids.length) {
      ElMessage.warning('请先勾选账号')
      return
    }
    const eligible = kind === 'token'
      ? tasks.filter(task => task?.result?.has_access_token)
      : tasks.filter(task => kind === 'password' ? task?.result?.has_password : kind === 'totp' ? task?.result?.has_totp : task?.result?.has_credential)
    if (!eligible.length) {
      ElMessage.warning(`选中的账号没有可复制 ${label}`)
      return
    }
    try {
      const value = (await getFreeSecret(kind, { task_ids: eligible.map(task => String(task.task_id)) })).value
      if (!value || !navigator.clipboard?.writeText) throw new Error('当前环境不支持复制')
      await navigator.clipboard.writeText(value)
      ElMessage.success(`已复制 ${eligible.length} 个 Free ${label}`)
    } catch (error) {
      ElMessage.error(errorMessage(error) || `Free ${label} 复制失败`)
    }
  }

  async function copyTaskTokens(tasks: FreeTaskRow[]) {
    await copyTaskSecret('token', tasks, 'Token')
  }

  async function copyTaskToken(task: FreeTaskRow) {
    if (!task?.result?.has_access_token) {
      ElMessage.info('该任务暂无可复制的账号 Token')
      return
    }
    await copyTaskTokens([task])
  }

  async function copyTaskEmail(task: FreeTaskRow) {
    const taskId = String(task?.task_id || '').trim()
    if (!taskId || loadingEmailTaskIds.value.includes(taskId)) return
    if (!navigator.clipboard?.writeText) {
      ElMessage.error('当前浏览器不支持安全剪贴板写入')
      return
    }
    loadingEmailTaskIds.value = [...loadingEmailTaskIds.value, taskId]
    try {
      const rowId = String(task?.row_id || '').trim()
      const email = String((await getFreeSecret('email', freeTaskSecretLookup(taskId, rowId))).value || '').trim()
      if (!email) throw new Error('服务端未返回可复制邮箱')
      await navigator.clipboard.writeText(email)
      ElMessage.success('已复制真实邮箱')
    } catch (error) {
      ElMessage.error(errorMessage(error) || '邮箱复制失败')
    } finally {
      loadingEmailTaskIds.value = loadingEmailTaskIds.value.filter(id => id !== taskId)
    }
  }

  /** Copy the real mailbox email for a live/plan job row via its pool row id. */
  async function copyRunEmail(row: { task_id?: string; row_id?: string }) {
    const jobId = String(row?.task_id || '').trim()
    const rowId = String(row?.row_id || '').trim()
    if (!jobId || !rowId || loadingEmailTaskIds.value.includes(jobId)) return
    if (!navigator.clipboard?.writeText) {
      ElMessage.error('当前浏览器不支持安全剪贴板写入')
      return
    }
    loadingEmailTaskIds.value = [...loadingEmailTaskIds.value, jobId]
    try {
      const email = String((await getFreeSecret('email', freeRowSecretLookup(rowId))).value || '').trim()
      if (!email) throw new Error('服务端未返回可复制邮箱')
      await navigator.clipboard.writeText(email)
      ElMessage.success('已复制真实邮箱')
    } catch (error) {
      ElMessage.error(errorMessage(error) || '邮箱复制失败')
    } finally {
      loadingEmailTaskIds.value = loadingEmailTaskIds.value.filter(id => id !== jobId)
    }
  }

  async function openTaskMailboxUrl(task: FreeTaskRow) {
    const taskId = String(task?.task_id || '').trim()
    const rowId = String(task?.row_id || '').trim()
    if (!taskId || !rowId) {
      ElMessage.info('该任务尚未生成可用的任务标识')
      return
    }
    if (!task?.has_mailbox_url) {
      ElMessage.info('该任务暂无取件 URL')
      return
    }
    if (openingMailboxUrlTaskIds.value.includes(taskId)) return
    openingMailboxUrlTaskIds.value = [...openingMailboxUrlTaskIds.value, taskId]
    try {
      await openMailboxUrlInTab(() => getFreeMailboxUrl(rowId).then(result => result.mailbox_url))
    } finally {
      openingMailboxUrlTaskIds.value = openingMailboxUrlTaskIds.value.filter(id => id !== taskId)
    }
  }

  async function copyTaskLatestCode(task: FreeTaskRow) {
    const taskId = String(task?.task_id || '').trim()
    if (!taskId) {
      ElMessage.info('该任务尚未生成任务 ID')
      return
    }
    if (!task?.has_mailbox_url) {
      ElMessage.info('该任务暂无取件 URL，无法提取验证码')
      return
    }
    if (loadingLatestCodeTaskIds.value.includes(taskId)) return
    if (!navigator.clipboard?.writeText) {
      ElMessage.error('当前浏览器不支持安全剪贴板写入')
      return
    }
    loadingLatestCodeTaskIds.value = [...loadingLatestCodeTaskIds.value, taskId]
    try {
      const result = await getFreeTaskLatestCode(taskId)
      const code = String(result.code || '').trim()
      if (!code) {
        ElMessage.info('未找到新的 OpenAI 邮箱验证码')
        return
      }
      await navigator.clipboard.writeText(code)
      ElMessage.success('验证码已复制')
    } catch (error) {
      ElMessage.error(errorMessage(error) || '提取邮箱验证码失败')
    } finally {
      loadingLatestCodeTaskIds.value = loadingLatestCodeTaskIds.value.filter(id => id !== taskId)
    }
  }

  return {
    loadingEmailTaskIds,
    loadingLatestCodeTaskIds,
    openingMailboxUrlTaskIds,
    copyTaskSecret,
    copyTaskTokens,
    copyTaskToken,
    copyTaskEmail,
    copyRunEmail,
    openTaskMailboxUrl,
    copyTaskLatestCode,
  }
}
