// Presentational lookups for the Data Shares views — semantic keys (transport /
// data-class / trust) → label + icon + badge tone. Lives in @akasecurity/dashboard-ui
// so the Vite dashboard and the OSS web-ui render identical styling. Derived
// per-destination rollups also live here so views stay pure/props-driven.
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
import type { DataClass, DestKind, ShareDestination, TransportKind, TrustLevel } from './types.ts';

/** ui-kit Badge variants used by the shares chips. */
export type Tone = NonNullable<BadgeProps['variant']>;

// ─── Transport ───────────────────────────────────────────────────────────────

export interface TransportMeta {
  label: string;
  icon: IconComponent;
  secure: boolean;
}
export const TRANSPORT_META: Record<TransportKind, TransportMeta> = {
  https: { label: 'HTTPS', icon: LockIcon, secure: true },
  http: { label: 'HTTP', icon: GlobeIcon, secure: false },
  sftp: { label: 'SFTP', icon: UploadIcon, secure: true },
  grpc: { label: 'gRPC', icon: RouteIcon, secure: true },
  smtp: { label: 'SMTP', icon: InboxIcon, secure: true },
};

// ─── Data classification (order = sensitivity, high → low) ───────────────────

export interface ClassMeta {
  label: string;
  tone: Tone;
  icon: IconComponent;
  rank: number;
}
export const CLASS_META: Record<DataClass, ClassMeta> = {
  secrets: { label: 'Secrets', tone: 'critical', icon: KeyIcon, rank: 7 },
  pii: { label: 'PII', tone: 'high', icon: FingerprintIcon, rank: 6 },
  customer: { label: 'Customer data', tone: 'high', icon: UserIcon, rank: 5 },
  source: { label: 'Source code', tone: 'low', icon: CodeIcon, rank: 4 },
  telemetry: { label: 'Telemetry', tone: 'teal', icon: PulseIcon, rank: 3 },
  logs: { label: 'Logs', tone: 'default', icon: ListIcon, rank: 2 },
  metrics: { label: 'Metrics', tone: 'teal', icon: ActivityIcon, rank: 1 },
  none: { label: 'No payload', tone: 'default', icon: InfoIcon, rank: 0 },
};

// ─── Trust posture ───────────────────────────────────────────────────────────

export interface TrustMeta {
  label: string;
  tone: Tone;
  icon: IconComponent;
}
export const TRUST_META: Record<TrustLevel, TrustMeta> = {
  recognized: { label: 'Known provider', tone: 'success', icon: CheckCircleIcon },
  internal: { label: 'Your organization', tone: 'primary', icon: ShieldCheckIcon },
  unverified: { label: 'Unverified domain', tone: 'high', icon: AlertIcon },
  ip: { label: 'Raw IP address', tone: 'critical', icon: AlertOctagonIcon },
};

// ─── Kind grouping ───────────────────────────────────────────────────────────

export const KIND_LABEL: Record<DestKind, string> = {
  provider: 'Providers',
  internal: 'Internal & corporate domains',
  ip: 'Raw IP addresses',
};
export const KIND_ORDER: DestKind[] = ['provider', 'internal', 'ip'];

/** Icon-tile fill+text tone for a non-provider destination mark. */
export function destMarkStyle(d: ShareDestination): string {
  if (d.kind === 'ip') return 'bg-sev-critical-fill text-sev-critical';
  if (d.trust === 'unverified') return 'bg-sev-high-fill text-sev-high';
  return 'bg-primary-tint text-primary';
}

// ─── Derived per-destination rollups ─────────────────────────────────────────

/** Total call sites across all endpoints. */
export function destSites(d: ShareDestination): number {
  return d.endpoints.reduce((n, ep) => n + ep.sites.length, 0);
}
/** Distinct transports used, in first-seen order. */
export function destTransports(d: ShareDestination): TransportKind[] {
  return Array.from(new Set(d.endpoints.map((ep) => ep.transport)));
}
/** Distinct data classes sent, most-sensitive first. */
export function destClasses(d: ShareDestination): DataClass[] {
  return Array.from(new Set(d.endpoints.map((ep) => ep.cls))).sort(
    (a, b) => CLASS_META[b].rank - CLASS_META[a].rank,
  );
}
/** The single most-sensitive class this destination sends. */
export function destTopClass(d: ShareDestination): DataClass | undefined {
  return destClasses(d)[0];
}
/** Any endpoint goes out over a plaintext/insecure transport. */
export function hasInsecure(d: ShareDestination): boolean {
  return d.endpoints.some((ep) => !TRANSPORT_META[ep.transport].secure);
}
/** Destination warrants manual review (raw IP, unverified domain, or plaintext). */
export function isFlagged(d: ShareDestination): boolean {
  return d.kind === 'ip' || d.trust === 'unverified' || hasInsecure(d);
}
/** Human-readable reason a destination is flagged (drives the review strip). */
export function flagReason(d: ShareDestination): string {
  if (d.kind === 'ip') return 'Connects to a raw IP with no reverse DNS';
  if (d.trust === 'unverified') return 'Corporate-looking domain not owned by your org';
  const t = destTransports(d).find((tr) => !TRANSPORT_META[tr].secure);
  return 'Sends data over plaintext ' + (t ? TRANSPORT_META[t].label : 'transport');
}
