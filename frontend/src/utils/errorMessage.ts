/**
 * Unknown-error message extraction.
 *
 * Single helper for `catch (error: unknown)` bodies: resolves the message of
 * an Error/ApiError instance without leaking non-error payloads to the UI.
 */
export function errorMessage(error: unknown, fallback = ''): string {
  if (error instanceof Error) {
    const message = String(error.message || '').trim()
    if (message) return message
  }
  return fallback
}
