/**
 * Return a normalized mailbox URL only when it is an explicit HTTP(S) URL.
 * Empty, malformed, and non-web schemes stay unusable so callers do not
 * navigate a newly opened tab to an empty or unsafe destination.
 */
export function safeMailboxUrl(value: unknown): string {
  const raw = String(value ?? '').trim()
  if (!raw) return ''
  try {
    const url = new URL(raw)
    return ['http:', 'https:'].includes(url.protocol) ? url.href : ''
  } catch {
    return ''
  }
}
