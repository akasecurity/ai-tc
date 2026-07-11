// Store-health degradation surfacing for the hook adapters.
//
// Every hook is fail-open: a store that cannot open must never break the
// user's session, so enforcement errors collapse to "allow". But silence has a
// cost of its own — with an unopenable store (corrupt/locked aka.db) NOTHING
// is scanned, enforced, or recorded, and without a signal the session looks
// protected while it is not. This module is the middle ground the adapters
// share: opening the gateway stays fail-open (null instead of a throw), and
// the user is told ONCE per session that detection is off and how to recover.
//
// Pure logic + a tiny fs marker only — no main() side effect, so tests can
// import it (hook ENTRY files run main() on import and must never be imported
// by tests).
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { resolveDataGateway } from '@akasecurity/plugin-runtime';
import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';
import { DATA_DIR_MODE, DATA_FILE_MODE } from '@akasecurity/plugin-sdk';

// A single marker holding the last session id warned — one file, overwritten
// each new session so it never accumulates (same scheme as the onboarding
// nudge marker).
const STORE_WARNING_MARKER = 'store-warning-last-session';

/**
 * Open the data gateway, fail-open: any store-open failure (corrupt aka.db,
 * bad permissions, a held lock) yields null instead of a throw, so the caller
 * can both keep the session alive AND know that detection is off — a silent
 * catch at the hook entry can't tell those apart.
 */
export function openGatewayOrNull(config: PluginConfig): DataGateway | null {
  try {
    return resolveDataGateway(config);
  } catch {
    return null;
  }
}

/** The once-per-session degradation warning shown when the store cannot open. */
export function storeUnavailableMessage(dbPath: string): string {
  return (
    `AKA could not open its local store (${dbPath}) — detection, enforcement, and recording are OFF for this session (fails open, so your session keeps working). ` +
    'To restore protection, check the file and its permissions; a corrupt store can be moved aside and AKA will recreate it.'
  );
}

/**
 * Gate the store-unavailable warning to once per Claude Code session instead
 * of once per hook fire. Records the current session id in a single marker
 * file and returns true only the first time a given session asks. Fail-open
 * toward WARNING: with no session id (can't dedupe), or on any fs error, it
 * returns true — repeating the warning is noise; hiding that detection is off
 * is not.
 */
export function claimStoreUnavailableWarning(
  dataDir: string,
  sessionId: string | undefined,
): boolean {
  if (!sessionId) return true; // no session id → can't dedupe, warn anyway
  const path = join(dataDir, STORE_WARNING_MARKER);
  try {
    if (readFileSync(path, 'utf8') === sessionId) return false;
  } catch {
    // No marker yet (or unreadable) → this is the first warning for the session.
  }
  try {
    mkdirSync(dataDir, { recursive: true, mode: DATA_DIR_MODE });
    writeFileSync(path, sessionId, { mode: DATA_FILE_MODE });
  } catch {
    // Couldn't record the claim → still warn now (an extra warning beats silence).
  }
  return true;
}
