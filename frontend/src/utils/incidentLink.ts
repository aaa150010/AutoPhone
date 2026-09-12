/**
 * Shared deep-link to the log center for one diagnostic incident id.
 *
 * Three pages emitted the same URL template; the encoder lives in one place
 * so the query format cannot drift between entry points.
 */
export function incidentCenterUrl(incidentId: string): string {
  return `/logs?incident_id=${encodeURIComponent(incidentId)}`
}
