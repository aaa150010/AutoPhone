export interface FreeSecretLookup {
  task_ids?: string[]
  row_ids?: string[]
}

/** Build the private lookup payload used by Free secret actions. */
export function freeTaskSecretLookup(taskId: unknown, rowId?: unknown): FreeSecretLookup {
  const task = String(taskId || '').trim()
  if (task) return { task_ids: [task] }
  const row = String(rowId || '').trim()
  return row ? { row_ids: [row] } : {}
}

export function freeRowSecretLookup(rowId: unknown): FreeSecretLookup {
  const row = String(rowId || '').trim()
  return row ? { row_ids: [row] } : {}
}
