import { computed, reactive } from 'vue'
import { splitMailboxText } from '../utils/mailboxSplitter'

const sessionState = reactive({ source: '', amount: 0 })

export function useMailboxSplitter() {
  const result = computed(() => splitMailboxText(sessionState.source, Number(sessionState.amount)))
  const clear = () => {
    sessionState.source = ''
    sessionState.amount = 0
  }
  return { state: sessionState, result, clear }
}
