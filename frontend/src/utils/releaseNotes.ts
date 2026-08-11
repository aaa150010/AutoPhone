const ACKNOWLEDGED_VERSION_KEY = 'gptphone.release-notes.acknowledged-version'

interface ReleaseStorage {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
}

export function shouldShowReleaseNotes(storage: ReleaseStorage, version: string): boolean {
  try {
    return storage.getItem(ACKNOWLEDGED_VERSION_KEY) !== version
  } catch {
    return true
  }
}

export function acknowledgeReleaseNotes(storage: ReleaseStorage, version: string): void {
  try {
    storage.setItem(ACKNOWLEDGED_VERSION_KEY, version)
  } catch {
    // A disabled storage backend means the notes will be shown again next launch.
  }
}

export { ACKNOWLEDGED_VERSION_KEY }
