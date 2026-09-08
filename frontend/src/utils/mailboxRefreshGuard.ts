/**
 * Mailbox refresh guard.
 *
 * Issues monotonic refresh tickets so a stale in-flight request can never
 * overwrite a newer snapshot.
 */
export interface MailboxRefreshTicket {
  request: number
  generation: number
}

export function createMailboxRefreshGuard() {
  let generation = 0
  let latestRequest = 0

  return {
    invalidate() {
      generation += 1
      latestRequest += 1
    },
    begin(): MailboxRefreshTicket {
      return { request: ++latestRequest, generation }
    },
    accepts(ticket: MailboxRefreshTicket) {
      return ticket.request === latestRequest && ticket.generation === generation
    },
  }
}
