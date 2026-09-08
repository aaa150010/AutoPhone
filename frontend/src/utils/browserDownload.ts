/**
 * Browser download helper.
 *
 * Creates a blob URL and triggers a single click download without leaving
 * DOM remnants.
 */
export function browserDownload(content: BlobPart, type: string, filename: string) {
  const blob = new Blob([content], { type })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}
