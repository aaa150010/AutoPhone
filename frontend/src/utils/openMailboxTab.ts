/**
 * Shared "open a placeholder tab, resolve the pickup URL, navigate" flow.
 *
 * RunPage / the Free task row actions / the mailbox row actions all used to
 * hand-roll this sequence (open → sever opener → fetch URL → safe-navigate →
 * close the tab on failure). Preconditions and re-entrancy bookkeeping stay
 * at the call sites; only the tab choreography lives here.
 */
import { ElMessage } from 'element-plus'
import { errorMessage } from './errorMessage'
import { safeMailboxUrl } from './safeMailboxUrl'

export async function openMailboxUrlInTab(
  resolveUrl: () => Promise<string>,
  options: {
    /** Invoked with the caught error before the failure message (stale-row refresh hook). */
    onStale?: (error: unknown) => Promise<void> | void
    failureMessage?: string
  } = {},
): Promise<boolean> {
  const target = window.open('', '_blank')
  if (!target) {
    ElMessage.error('浏览器阻止了新窗口，请允许弹出窗口后重试')
    return false
  }
  try {
    target.opener = null
    const result = await resolveUrl()
    const destination = safeMailboxUrl(result)
    if (!destination) throw new Error('取件 URL 无效或协议不安全')
    target.location.replace(destination)
    return true
  } catch (error) {
    target.close()
    if (options.onStale) await options.onStale(error)
    ElMessage.error(errorMessage(error) || options.failureMessage || '打开取件 URL 失败')
    return false
  }
}
