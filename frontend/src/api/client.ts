export async function api<T = any>(path: string, body?: unknown): Promise<T> {
  const response = await fetch(path, body === undefined ? { cache: 'no-store' } : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  const payload = await response.json().catch(() => ({}))
  if (!response.ok || payload.ok === false) throw new Error(payload.error || '操作失败')
  return payload
}

export const getState = () => api<{ state: any }>('/api/state')
export const getLocalConfig = () => api<{ config: any }>('/api/local-config')
export const getSecret = (id: string) => api<{ value: string | string[] }>('/api/local-config/secret', { id })
export const saveConfig = (data: any) => api('/api/config', data)
export const preflightRun = (data: any) => api('/api/preflight', data)
export const startRun = (data: any) => api('/api/start', data)
export const stopRun = () => api('/api/stop', {})
export const getMailboxes = () => api<any>('/api/mailboxes')
