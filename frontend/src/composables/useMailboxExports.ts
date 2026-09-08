import { ref, type Ref } from 'vue'
import { errorMessage } from '../utils/errorMessage'
import { ElMessage, ElMessageBox } from 'element-plus'
import { ApiError, exportMailboxSource, exportMailboxSub2 } from '../api/client'
import type { MailboxRow } from '../types/api'
import { browserDownload } from '../utils/browserDownload'

interface MailboxExportOptions {
  selectedRows: Ref<MailboxRow[]>
  refresh: () => Promise<void>
}

export function useMailboxExports(options: MailboxExportOptions) {
  const exportingSub2 = ref(false)
  const exportingSource = ref(false)
  const bindings = () => options.selectedRows.value.map(row => ({
    row_id: row.row_id,
    line_no: row.line_no,
  }))

  async function confirmExport(message: string, title: string) {
    if (!options.selectedRows.value.length) {
      ElMessage.warning('请先选择邮箱')
      return false
    }
    try {
      await ElMessageBox.confirm(message, title, {
        type: 'warning',
        confirmButtonText: '确认导出',
        cancelButtonText: '取消',
      })
      return true
    } catch {
      return false
    }
  }

  async function exportSub2() {
    if (!await confirmExport('导出文件包含完整 OAuth Token，仅应保存在可信设备。', '导出 SUB2API')) return
    exportingSub2.value = true
    try {
      const result = await exportMailboxSub2(bindings())
      browserDownload(JSON.stringify(result.export, null, 2), 'application/json', result.filename || 'sub2api-export.json')
      const skipped = Number(result.skipped || 0)
      ElMessage.success(`已导出 ${Number(result.count || 0)} 条${skipped ? `，跳过 ${skipped} 条` : ''}`)
    } catch (error) {
      if (error instanceof ApiError && error.status === 409) await options.refresh()
      ElMessage.error(errorMessage(error) || 'SUB2API 导出失败')
    } finally {
      exportingSub2.value = false
    }
  }

  async function exportSource() {
    if (!await confirmExport(
      '导出文件包含所选邮箱的完整密码、2FA、取件 URL 或 OAuth 凭据，仅应保存在可信设备。',
      '导出原始格式',
    )) return
    exportingSource.value = true
    try {
      const result = await exportMailboxSource(bindings())
      browserDownload(result.content, 'text/plain;charset=utf-8', result.filename || 'mailboxes-original.txt')
      ElMessage.success(`已按原始格式导出 ${Number(result.count || 0)} 条`)
    } catch (error) {
      if (error instanceof ApiError && error.status === 409) await options.refresh()
      ElMessage.error(errorMessage(error) || '原始格式导出失败')
    } finally {
      exportingSource.value = false
    }
  }

  return { exportingSource, exportingSub2, exportSource, exportSub2 }
}
