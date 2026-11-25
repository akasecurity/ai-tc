// This plugin's store-health seam. The module lives in
// @akasecurity/plugin-runtime and is shared by every plugin; hooks import it
// from here so each plugin has one place to reach it. What this file adds is
// the hook server's gateway handling: a process that runs many hooks can hold
// one gateway, and can close the ones each hook opened.
import { statSync } from 'node:fs';

import type { GatewayOpen } from '@akasecurity/plugin-runtime';
import { resolveDataGateway } from '@akasecurity/plugin-runtime';
import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';

export type { GatewayOpen, StoreEventSubject, StoreLock } from '@akasecurity/plugin-runtime';
export {
  claimStoreDegradedWarning,
  claimStoreUnavailableWarning,
  isSessionMarked,
  markSession,
  storeAheadMessage,
  storeBusyMessage,
  storeDegradedMessage,
  storeOpenCause,
  storeRedirectedMessage,
  storeUnavailableMessage,
  warnIfStoreRedirected,
} from '@akasecurity/plugin-runtime';

/**
 * Open the data gateway, fail-open: any store-open failure (corrupt aka.db,
 * bad permissions, a held lock, a store written by a NEWER AKA build) yields a
 * null gateway instead of a throw, so the caller can both keep the session
 * alive AND know that detection is off — a silent catch at the hook entry
 * can't tell those apart.
 *
 * The reason is carried out rather than swallowed, because it decides what the
 * user is told: see `storeDegradedMessage`. A bare catch made every cause read
 * as the same one, and the advice that generic message gives is wrong — and
 * destructive — for the newer-store case.
 */
export function openGateway(config: PluginConfig): GatewayOpen {
  try {
    if (reuseGateway) return { gateway: heldGatewayFor(config) };
    const gateway = resolveDataGateway(config);
    openedGateways?.push(gateway);
    return { gateway };
  } catch (error) {
    return { gateway: null, error };
  }
}

// The gateways opened since `closingGateways` began, while it runs. A hook
// process leaves them to its exit; a process that runs several hooks closes
// each one's when that hook is done.
let openedGateways: DataGateway[] | null = null;

/**
 * Runs `work`, then closes every gateway `openGateway` opened during it. For a
 * caller that outlives one hook; it must run one `work` at a time. A gateway
 * held for reuse (see `reuseGateways`) is not closed here.
 */
export async function closingGateways<T>(work: () => Promise<T>): Promise<T> {
  const mine: DataGateway[] = [];
  openedGateways = mine;
  try {
    return await work();
  } finally {
    openedGateways = null;
    for (const gateway of mine) {
      try {
        await gateway.close();
      } catch {
        // A close that fails leaves nothing the next request depends on.
      }
    }
  }
}

// A process that runs many hooks keeps ONE gateway instead of opening the store
// for each: an open applies the schema checks, which write, and on a large
// store that dwarfs the hook's own work. The gateway is checked against the
// store file on every use and replaced when the file is not the one it opened
// (removed and recreated, or moved), and dropped when a hook fails.
interface HeldGateway {
  readonly gateway: DataGateway;
  readonly lent: DataGateway;
  readonly dbPath: string;
  readonly identity: string;
}
let reuseGateway = false;
let heldGateway: HeldGateway | null = null;

function fileIdentity(path: string): string {
  try {
    const info = statSync(path);
    return `${String(info.dev)}:${String(info.ino)}`;
  } catch {
    return 'absent';
  }
}

function heldGatewayFor(config: PluginConfig): DataGateway {
  const identity = fileIdentity(config.dbPath);
  if (heldGateway !== null) {
    if (heldGateway.dbPath === config.dbPath && heldGateway.identity === identity) {
      return heldGateway.lent;
    }
    void dropHeldGateway();
  }
  const real = resolveDataGateway(config);
  // The runtime a hook creates closes the gateway it is given when the hook is
  // done. What is handed out ignores that close, and the held one is closed by
  // `dropHeldGateway`.
  const lent = new Proxy(real, {
    get(target, property) {
      if (property === 'close') return () => Promise.resolve();
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === 'function' ? (value as () => unknown).bind(target) : value;
    },
  });
  // Read after the open, which creates the file when there was none.
  heldGateway = {
    gateway: real,
    lent,
    dbPath: config.dbPath,
    identity: fileIdentity(config.dbPath),
  };
  return lent;
}

/** Turns gateway reuse on or off for this process; off closes the held gateway. */
export function reuseGateways(on: boolean): Promise<void> {
  reuseGateway = on;
  return on ? Promise.resolve() : dropHeldGateway();
}

/** Closes the held gateway, if any; the next open makes a new one. */
export async function dropHeldGateway(): Promise<void> {
  const held = heldGateway;
  heldGateway = null;
  if (held === null) return;
  try {
    await held.gateway.close();
  } catch {
    // Already closed, or never usable.
  }
}

/**
 * The same open, for the callers that only branch on whether they got one.
 * A caller that WARNS wants `openGateway` — it cannot say anything true about
 * the failure from a null alone.
 */
export function openGatewayOrNull(config: PluginConfig): DataGateway | null {
  return openGateway(config).gateway;
}
