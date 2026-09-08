/**
 * Manual verification (2FA / email code) request helpers.
 *
 * Identity keys and deadline math shared by the verification input widgets.
 */
import type { ManualVerificationRequest } from '../types/api'

export function manualVerificationRequestKey(
  taskId: string,
  request: Pick<ManualVerificationRequest, 'input_kind' | 'generation'>,
) {
  return `${taskId}:${request.input_kind}:${request.generation}`
}
