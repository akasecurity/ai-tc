// Pure grouping helper for the Data Shares register: folds the hosts of one
// provider (matching, non-null `providerId`, and `kind === 'provider'`) into
// a single expandable row, so a provider with many endpoints doesn't
// dominate the register with one row per host. A lone provider host is left
// as a plain destination row — nothing changes for the common case — and
// destinations with no matched provider (`providerId: null`) or a non-provider
// kind sharing a `providerId` by coincidence are never folded, even when
// their names happen to match. This is a presentation fold over the rows a
// page already holds, with no store-side counterpart.
import type { DataClass, ShareDestinationSummary, Transport } from '@akasecurity/schema';

import { hasInsecureTransport } from './meta.ts';

/** Prefix on a provider row's `id`, so it cannot collide with a destination id. */
export const PROVIDER_ROW_PREFIX = 'provider:';

/** One provider's hosts folded into a single register row. */
export interface ProviderGroup {
  /** Expansion/selection key: `PROVIDER_ROW_PREFIX` + providerId. */
  id: string;
  providerId: string;
  /** From the most recently seen host. */
  name: string;
  /** From the most recently seen host. */
  category: string;
  /** In the order they appear in the input. */
  hosts: ShareDestinationSummary[];
  endpointCount: number;
  callSiteCount: number;
  /** Union across hosts, first-seen order. */
  transports: Transport[];
  /** Union across hosts, first-seen order. */
  dataClasses: DataClass[];
  /** The latest `lastSeen` across hosts. */
  lastSeen: string;
  /** True when any host sends over a plaintext transport. */
  insecure: boolean;
}

/** One register row: either a plain destination, or a folded provider group. */
export type RegisterRow =
  | { type: 'destination'; item: ShareDestinationSummary }
  | { type: 'provider'; group: ProviderGroup };

function buildProviderGroup(providerId: string, hosts: ShareDestinationSummary[]): ProviderGroup {
  let endpointCount = 0;
  let callSiteCount = 0;
  const transports: Transport[] = [];
  const dataClasses: DataClass[] = [];
  let insecure = false;

  for (const host of hosts) {
    endpointCount += host.endpointCount;
    callSiteCount += host.callSiteCount;
    for (const t of host.transports) if (!transports.includes(t)) transports.push(t);
    for (const c of host.dataClasses) if (!dataClasses.includes(c)) dataClasses.push(c);
    if (hasInsecureTransport(host.transports)) insecure = true;
  }

  // `.reduce` with no seed is typed as returning `T`, never `T | undefined` —
  // safe here without an explicit non-empty check, since this is only called
  // for a bucket of 2+ hosts.
  const mostRecent = hosts.reduce((a, b) => (b.lastSeen > a.lastSeen ? b : a));

  return {
    id: PROVIDER_ROW_PREFIX + providerId,
    providerId,
    name: mostRecent.name,
    category: mostRecent.category,
    hosts,
    endpointCount,
    callSiteCount,
    transports,
    dataClasses,
    lastSeen: mostRecent.lastSeen,
    insecure,
  };
}

/**
 * Folds `kind === 'provider'` destinations sharing a non-null `providerId`
 * into one `ProviderGroup` row apiece, at the position of the group's first
 * member. Every other item — a `providerId: null` destination, a
 * non-provider-kind destination that happens to share a `providerId`, or the
 * sole host of a provider nobody else shares — passes through as its own
 * `destination` row, unchanged from today.
 */
export function groupByProvider(items: ShareDestinationSummary[]): RegisterRow[] {
  const foldable = (
    item: ShareDestinationSummary,
  ): item is ShareDestinationSummary & { providerId: string } =>
    item.providerId !== null && item.kind === 'provider';

  const buckets = new Map<string, ShareDestinationSummary[]>();
  for (const item of items) {
    if (!foldable(item)) continue;
    const bucket = buckets.get(item.providerId);
    if (bucket) bucket.push(item);
    else buckets.set(item.providerId, [item]);
  }

  const rows: RegisterRow[] = [];
  const emitted = new Set<string>();

  for (const item of items) {
    if (foldable(item)) {
      const providerId = item.providerId;
      const bucket = buckets.get(providerId) ?? [];
      if (bucket.length >= 2) {
        if (emitted.has(providerId)) continue;
        emitted.add(providerId);
        rows.push({ type: 'provider', group: buildProviderGroup(providerId, bucket) });
        continue;
      }
    }
    rows.push({ type: 'destination', item });
  }

  return rows;
}
