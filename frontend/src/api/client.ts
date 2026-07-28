import type { ApiErrorPayload, AppState, MailboxPayload } from '../types/api'

export class ApiError extends Error {
  status: number
  payload: ApiErrorPayload

  constructor(message: string, status: number, payload: ApiErrorPayload = {}) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.payload = payload
  }
}

export async function api<T = any>(path: string, body?: unknown): Promise<T> {
  const options: RequestInit = body === undefined
    ? { cache: 'no-store' }
    : {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        cache: 'no-store',
      }
  const response = await fetch(path, options)
  const payload = await response.json().catch(() => ({}))
  if (!response.ok || payload.ok === false) {
    throw new ApiError(payload.error || '操作失败', response.status, payload)
  }
  return payload
}

export const getState = () => api<{ state: AppState }>('/api/state')
export const getLocalConfig = () => api<{ config: Record<string, any> }>('/api/local-config')
export const getSecret = (id: string) => api<{ value: string | string[] }>('/api/local-config/secret', { id })
export const saveConfig = (data: Record<string, any>) => api('/api/config', data)
export const preflightRun = (data: Record<string, any>) => api('/api/preflight', data)
export const startExistingRun = (data: Record<string, any>) => api('/api/start-existing', data)
export const stopRun = () => api('/api/stop', {})
export const getMailboxes = () => api<MailboxPayload>('/api/mailboxes')
export const testEmailNotification = (data: Record<string, any>) => api('/api/notifications/email/test', data)
