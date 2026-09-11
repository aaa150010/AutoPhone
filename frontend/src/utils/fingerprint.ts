/**
 * Cheap change fingerprints for polled Free state payloads.
 *
 * Polling refreshes arrive every second; these helpers let callers skip the
 * reactive assignment (and the whole downstream computed/render chain) when
 * the payload is equivalent to the currently rendered one. Any mutation the
 * backend performs bumps `updated_at` on the affected row, so per-row
 * `task_id/status/updated_at` tuples plus the scalar summary fields are a
 * sound identity for "did anything change".
 */
import type { FreeLiveCheckState, FreeMailboxRow, FreeState } from '../types/free'
import type { MailboxRow } from '../types/api'

function freeStateFingerprint(state: FreeState | undefined): string {
  if (!state) return 'none'
  const tasks = state.tasks || []
  const taskPart = tasks
    .map(task => `${task.task_id || ''}:${task.status || ''}:${task.updated_at || 0}:${task.retry_resolved ? 1 : 0}`)
    .join('|')
  const pool = state.pool || {}
  const scheduler = state.scheduler || {}
  const summary = state.summary || {}
  const camoufox = state.camoufox_debug || {}
  return [
    state.running ? 1 : 0,
    state.batch_id || '',
    state.driver || '',
    pool.total ?? '',
    pool.available ?? '',
    pool.proxies ?? '',
    scheduler.concurrency ?? '',
    scheduler.active_slots ?? '',
    scheduler.queued_slots ?? '',
    summary.total ?? '',
    summary.active ?? '',
    summary.success ?? '',
    summary.failed ?? '',
    summary.stopped ?? '',
    camoufox.used ?? '',
    camoufox.available ?? '',
    taskPart,
  ].join('\u0000')
}

function freeLiveStateFingerprint(state: FreeLiveCheckState | undefined): string {
  if (!state) return 'none'
  const jobs = state.jobs || []
  const jobPart = jobs
    .map(job => `${job.task_id || ''}:${job.status || ''}:${job.stage || ''}:${job.checked_at || 0}`)
    .join('|')
  return [state.running ? 1 : 0, state.workers ?? '', state.active ?? '', jobPart].join('\u0000')
}

function freeMailboxRowsFingerprint(rows: FreeMailboxRow[] | undefined | null): string {
  if (!rows) return 'none'
  return rows
    .map(row => {
      const progressStamp = (row.progress?.['updated_at'] as number | string | undefined) ?? ''
      return `${row.row_id || ''}:${row.status || ''}:${row.live_check_status || ''}:${row.plan_check_status || ''}:${progressStamp}`
    })
    .join('|')
}

function mailboxRowsFingerprint(rows: MailboxRow[] | undefined | null): string {
  if (!rows) return 'none'
  return rows
    .map(row => `${row.row_id || ''}:${row.status || ''}:${row.task_status || ''}:${row.progress?.entered_at ?? ''}:${row.progress?.finished_at ?? ''}:${row.updated_at ?? ''}`)
    .join('|')
}

export { freeLiveStateFingerprint, freeMailboxRowsFingerprint, freeStateFingerprint, mailboxRowsFingerprint }
