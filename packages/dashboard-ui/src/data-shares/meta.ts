// Presentational lookups for the Data Shares views — semantic keys (transport /
// data-class / trust) → label + icon + badge tone. Lives in @akasecurity/dashboard-ui
// so the Vite dashboard and the OSS web-ui render identical styling. The API
// returns semantic-only shapes (raw counts, ISO timestamps, stable enums); the
// presentation descriptors here (labels, icons, tones, the provider lettermark)
// are derived client-side — never sent by the server.
import type {
  DataClass,
  DestinationKind,
  ReviewReason,
  ShareTrustLevel,
  Transport,
} from '@akasecurity/schema';
import type { BadgeProps } from '@akasecurity/ui-kit';

import type { IconComponent } from '../lib/icons.ts';
import {
  ActivityIcon,
  AlertIcon,
  AlertOctagonIcon,
  CheckCircleIcon,
  CodeIcon,
  FingerprintIcon,
  GlobeIcon,
  InboxIcon,
  InfoIcon,
  KeyIcon,
  ListIcon,
  LockIcon,
  PulseIcon,
  RouteIcon,
  ShieldCheckIcon,
  UploadIcon,
  UserIcon,
} from '../shared/icons.tsx';

/** ui-kit Badge variants used by the shares chips. */
export type Tone = NonNullable<BadgeProps['variant']>;

// ─── Transport ───────────────────────────────────────────────────────────────

export interface TransportMeta {
  label: string;
  icon: IconComponent;
  secure: boolean;
}
export const TRANSPORT_META: Record<Transport, TransportMeta> = {
  https: { label: 'HTTPS', icon: LockIcon, secure: true },
  http: { label: 'HTTP', icon: GlobeIcon, secure: false },
  sftp: { label: 'SFTP', icon: UploadIcon, secure: true },
  grpc: { label: 'gRPC', icon: RouteIcon, secure: true },
  smtp: { label: 'SMTP', icon: InboxIcon, secure: true },
};

/** True when any transport in the set is plaintext/insecure (only `http`). */
export function hasInsecureTransport(transports: Transport[]): boolean {
  return transports.some((t) => !TRANSPORT_META[t].secure);
}

// ─── Data classification (server sends most-sensitive first) ─────────────────

export interface ClassMeta {
  label: string;
  tone: Tone;
  icon: IconComponent;
}
export const CLASS_META: Record<DataClass, ClassMeta> = {
  secrets: { label: 'Secrets', tone: 'critical', icon: KeyIcon },
  pii: { label: 'PII', tone: 'high', icon: FingerprintIcon },
  customer: { label: 'Customer data', tone: 'high', icon: UserIcon },
  source: { label: 'Source code', tone: 'low', icon: CodeIcon },
  telemetry: { label: 'Telemetry', tone: 'teal', icon: PulseIcon },
  logs: { label: 'Logs', tone: 'default', icon: ListIcon },
  metrics: { label: 'Metrics', tone: 'teal', icon: ActivityIcon },
  none: { label: 'No payload', tone: 'default', icon: InfoIcon },
};

// ─── Trust posture ───────────────────────────────────────────────────────────

export interface TrustMeta {
  label: string;
  tone: Tone;
  icon: IconComponent;
}
export const TRUST_META: Record<ShareTrustLevel, TrustMeta> = {
  recognized: { label: 'Known provider', tone: 'success', icon: CheckCircleIcon },
  internal: { label: 'Your organization', tone: 'primary', icon: ShieldCheckIcon },
  unverified: { label: 'Unverified domain', tone: 'high', icon: AlertIcon },
  ip: { label: 'Raw IP address', tone: 'critical', icon: AlertOctagonIcon },
};

// ─── Kind grouping ───────────────────────────────────────────────────────────

export const KIND_LABEL: Record<DestinationKind, string> = {
  provider: 'Providers',
  internal: 'Internal & corporate domains',
  ip: 'Raw IP addresses',
};
export const KIND_ORDER: DestinationKind[] = ['provider', 'internal', 'ip'];

// ─── Review reasons ──────────────────────────────────────────────────────────

/** Why a destination is flagged for review; server sends `review.reasons`. */
export const REVIEW_REASON_META: Record<ReviewReason, string> = {
  raw_ip: 'Connects to a raw IP with no reverse DNS',
  unverified_domain: 'Corporate-looking domain not owned by your org',
  plaintext_transport: 'Sends data over a plaintext transport',
};

/** Severity order, most-severe first — matches the strip's sort. */
const REVIEW_REASON_ORDER: ReviewReason[] = ['raw_ip', 'unverified_domain', 'plaintext_transport'];

/** Human-readable copy for the most-severe reason a destination is flagged. */
export function flagReason(reasons: ReviewReason[]): string {
  const top = REVIEW_REASON_ORDER.find((r) => reasons.includes(r));
  return top ? REVIEW_REASON_META[top] : 'Needs review';
}

// ─── Destination mark ────────────────────────────────────────────────────────

/** Icon-tile fill+text tone for a non-provider destination mark. */
export function destMarkStyle(d: { kind: DestinationKind; trust: ShareTrustLevel }): string {
  if (d.kind === 'ip') return 'bg-sev-critical-fill text-sev-critical';
  if (d.trust === 'unverified') return 'bg-sev-high-fill text-sev-high';
  return 'bg-primary-tint text-primary';
}

/** Colored lettermark for a provider destination. */
export interface ProviderMark {
  short: string;
  color: string;
}

/** Deterministic fallback palette for open-ended SaaS destinations. */
const FALLBACK_COLORS = ['#2563EB', '#7C3AED', '#DB2777', '#0891B2', '#CA8A04', '#059669'];

/** Two-letter initials from a display name (e.g. "New Relic" → "NR"). */
function initials(name: string): string {
  const words = name
    .trim()
    .split(/[\s.\-_/]+/u)
    .filter(Boolean);
  const first = words[0] ?? '';
  if (words.length <= 1) return (first.slice(0, 2) || '?').toUpperCase();
  const second = words[1] ?? '';
  return ((first[0] ?? '') + (second[0] ?? '')).toUpperCase() || '?';
}

/**
 * Provider lettermark ({short,color}) derived client-side from name/host — the
 * API doesn't send it, since SaaS destinations are open-ended.
 */
export function providerMark(name: string, host?: string): ProviderMark {
  const key = host ?? name;
  let hash = 0;
  for (let i = 0; i < key.length; i++) hash = (hash * 31 + key.charCodeAt(i)) >>> 0;
  return {
    short: initials(name),
    color: FALLBACK_COLORS[hash % FALLBACK_COLORS.length] ?? '#2563EB',
  };
}
