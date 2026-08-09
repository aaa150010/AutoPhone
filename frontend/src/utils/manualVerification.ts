import type { ManualVerificationRequest } from '../types/api'

export function manualVerificationRequestKey(
  taskId: string,
  request: Pick<ManualVerificationRequest, 'input_kind' | 'generation'>,
) {
  return `${taskId}:${request.input_kind}:${request.generation}`
}
