// Data Shares domain shapes — outbound data egress detected in a customer's
// software, grouped by destination.
//
// TEMPORARY HOME: these live here (not in @akasecurity/schema) only until the Data
// Shares API is built; the dashboard supplies dummy data shaped to them today.
// When the endpoint lands, move the semantic shapes/enums to
// packages/schema/src/zod and re-import them here. Presentation (labels, icons,
// tones) stays in ./meta.ts — never on these types.

/** How a destination is grouped in the register. */
export type DestKind = 'provider' | 'internal' | 'ip';

/** Wire transport a request goes out over. `http`/plaintext is insecure. */
export type TransportKind = 'https' | 'http' | 'sftp' | 'grpc' | 'smtp';

/** What kind of data a request sends — ordered by sensitivity in ./meta.ts. */
export type DataClass =
  | 'secrets'
  | 'pii'
  | 'customer'
  | 'source'
  | 'telemetry'
  | 'logs'
  | 'metrics'
  | 'none';

/** Trust posture of a destination. */
export type TrustLevel = 'recognized' | 'internal' | 'unverified' | 'ip';

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE';

/** Where in the software a URL is invoked. */
export interface CallSite {
  project: string;
  file: string;
  line: number;
  snippet: string;
  /** URL built at runtime (e.g. from template vars) rather than a literal. */
  dynamic?: boolean;
  /** Call originates from vendored/third-party code, not first-party source. */
  vendored?: boolean;
}

/** A single detected egress endpoint on a destination. */
export interface ShareEndpoint {
  method: HttpMethod;
  transport: TransportKind;
  url: string;
  /** URL contains `${…}` template segments filled at runtime. */
  template: boolean;
  cls: DataClass;
  lastSeen: string;
  sites: CallSite[];
}

/** A destination (provider / internal domain / raw IP) with its endpoints. */
export interface ShareDestination {
  id: string;
  kind: DestKind;
  name: string;
  category: string;
  trust: TrustLevel;
  lastSeen: string;
  // provider lettermark
  short?: string;
  color?: string;
  // network / DNS metadata
  host?: string;
  geo?: string;
  ptr?: string;
  note?: string;
  endpoints: ShareEndpoint[];
}

/** A destination (+ optional endpoint index) selected in the detail drawer. */
export interface ShareSelection {
  id: string;
  ei?: number;
}

/** Destinations for one kind section of the grouped register. */
export interface ShareGroup {
  kind: DestKind;
  items: ShareDestination[];
}
