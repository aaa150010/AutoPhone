export interface MailboxSplitResult {
  sourceCount: number
  splitCount: number
  remainingCount: number
  splitText: string
  remainingText: string
  valid: boolean
}

export function mailboxSourceLines(source: string): string[] {
  return source
    .replace(/\r\n?/g, '\n')
    .split('\n')
    .filter(line => line.trim().length > 0)
}

export function splitMailboxText(source: string, amount: number): MailboxSplitResult {
  const lines = mailboxSourceLines(source)
  const valid = Number.isInteger(amount) && amount >= 1 && amount <= lines.length
  if (!valid) {
    return {
      sourceCount: lines.length,
      splitCount: 0,
      remainingCount: 0,
      splitText: '',
      remainingText: '',
      valid: false,
    }
  }
  const splitLines = lines.slice(0, amount)
  const remainingLines = lines.slice(amount)
  return {
    sourceCount: lines.length,
    splitCount: splitLines.length,
    remainingCount: remainingLines.length,
    splitText: splitLines.join('\n'),
    remainingText: remainingLines.join('\n'),
    valid: true,
  }
}

export function mailboxSplitFilename(kind: 'remaining' | 'split', count: number): string {
  return `${kind === 'remaining' ? '剩余' : '分割'}-${Math.max(0, Math.floor(count))}条.txt`
}
