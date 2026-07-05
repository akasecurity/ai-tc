// Data Shares — UI-only view state. The domain shapes (destinations, endpoints,
// call sites, trust/transport/data-class enums) now live in @akasecurity/schema
// (`packages/schema/src/zod/shares.ts`) and are consumed directly by the views;
// only this presentation-navigation shape has no schema equivalent.

/**
 * A destination (+ optional endpoint) selected in the detail drawer. Endpoints
 * are addressed by their stable `id` (not a list index) so the selection stays
 * valid across the list → detail two-fetch boundary.
 */
export interface ShareSelection {
  id: string;
  endpointId?: string;
}
