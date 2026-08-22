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
// Identical to plugins/claude-code/src/hooks/store-health.ts — no
// harness-specific logic here, only @akasecurity/plugin-runtime/plugin-sdk
// calls and a session-id-keyed fs marker.
//
// Pure logic + a tiny fs marker only — no main() side effect, so tests can
// import it (hook ENTRY files run main() on import and must never be imported
// by tests).
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import type { SymlinkedStorePath } from '@akasecurity/persistence';
import { symlinkedStorePaths } from '@akasecurity/persistence';
import { resolveDataGateway } from '@akasecurity/plugin-runtime';
import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';
import { DATA_DIR_MODE, DATA_FILE_MODE } from '@akasecurity/plugin-sdk';

// A single marker holding the last session id warned — one file, overwritten
// each new session so it never accumulates (same scheme as the onboarding
// nudge marker).
const STORE_WARNING_MARKER = 'store-warning-last-session';

// The redirect warning's own marker. Separate from the one above rather than
// shared: the two conditions are independent, and a session that has already
// been told the store cannot open must still be told WHERE it was being written
// once it can. One marker would let whichever fired first silence the other.
const STORE_REDIRECT_MARKER = 'store-redirect-last-session';

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
 * Gate the store-unavailable warning to once per Codex session instead
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
  const dirs = markerDirs(dataDir);
  if (alreadyClaimed(dirs, STORE_WARNING_MARKER, sessionId)) return false;
  recordClaim(dirs, STORE_WARNING_MARKER, sessionId);
  return true;
}

// Where a session marker may live, in preference order.
//
// data/ is its natural home, but data/ is exactly what a store path pointing at
// something unresolvable makes unwritable — and that is a configuration these
// warnings exist to report. With only data/ to write to, both the mkdir and the
// write fail, the claim is never recorded, and "once per session" silently
// becomes "once per hook fire": a fresh warning on every tool call for the rest
// of the session. Falling back to the base keeps the dedupe wherever the home
// itself is intact. When nothing under the home can be written there is no
// cross-process memory to be had, and repeating is the honest failure.
function markerDirs(dataDir: string): string[] {
  return [dataDir, dirname(dataDir)];
}

// Has this session already been warned? Every candidate is consulted, so a
// marker recorded in the fallback is still found once data/ is writable again.
function alreadyClaimed(dirs: readonly string[], marker: string, sessionId: string): boolean {
  return dirs.some((dir) => {
    try {
      return readFileSync(join(dir, marker), 'utf8') === sessionId;
    } catch {
      return false; // no marker yet, or unreadable → not a claim
    }
  });
}

// Record the claim in the first candidate that accepts it. Best-effort: with
// none writable the caller has already warned, and the next fire warns again.
function recordClaim(dirs: readonly string[], marker: string, sessionId: string): void {
  for (const dir of dirs) {
    try {
      mkdirSync(dir, { recursive: true, mode: DATA_DIR_MODE });
      writeFileSync(join(dir, marker), sessionId, { mode: DATA_FILE_MODE });
      return;
    } catch {
      // This candidate is unusable — try the next.
    }
  }
}

/**
 * The once-per-session warning shown when a store path is a symlink.
 *
 * A symlinked store path is not a failure: the store opens, and everything is
 * scanned, enforced and recorded exactly as it should be. What is wrong is
 * WHERE — the store, including the prompt corpus in `aka.db`, is written inside
 * the link's target, under whatever permissions that target already carries,
 * because a chmod is never applied through a symlink and `mkdir` does not follow
 * the final link. Both facts are invisible from the outside, so the only thing
 * separating a home a user symlinked on purpose (a dotfiles manager, another
 * volume) from a link someone else planted is being told the path is there.
 *
 * One line, naming each redirected path, its target, and the inherited mode when
 * that mode is not owner-only — the half a reader has to act on.
 *
 * The trailing clauses are built from what is actually true of THESE paths, not
 * fixed, for the same reason `symlinkWarnings` renders three shapes rather than
 * one: a link resolving NOWHERE has received nothing and inherited nothing, so
 * saying the store "is written there under the target's own permissions" is
 * false twice over; and on Windows no mode is ever applied, so claiming the
 * target's own is kept describes a control that does not exist there. `platform`
 * is a parameter so both branches are reachable from any host.
 */
export function storeRedirectedMessage(
  paths: readonly SymlinkedStorePath[],
  platform: NodeJS.Platform = process.platform,
): string {
  const where = paths
    .map(({ path, target, holds, missing, mode }) => {
      if (missing) return `${path} -> ${target} (which does not exist; ${holds} cannot land there)`;
      const loose = mode !== undefined && (mode & 0o077) !== 0 ? ', NOT owner-only' : '';
      const inherited = mode === undefined ? '' : ` (${formatMode(mode)}${loose})`;
      return `${path} -> ${target}${inherited}, holding ${holds}`;
    })
    .join('; ');
  // Plural only when it is: a reader who is told "a store path" and handed three
  // may repair the first and stop.
  const subject =
    paths.length === 1
      ? 'a store path is a symlink'
      : `${String(paths.length)} store paths are symlinks`;
  // Every path resolving nowhere means nothing has been redirected yet, so the
  // "writing into the target" framing would be false for all of them.
  const anyResolves = paths.some(({ missing }) => !missing);
  const lead = anyResolves
    ? `${subject}, so AKA is writing into the target instead: ${where}. `
    : `${subject} resolving nowhere, so AKA cannot write there: ${where}. `;
  // Only claim the inheritance where a mode is actually applied and something
  // actually landed.
  const kept =
    anyResolves && platform !== 'win32'
      ? 'Permissions are never changed through a symlink, so the store keeps whatever the target already had. '
      : '';
  return (
    `[aka] ${lead}${kept}` +
    'If you did not create that link, treat it as untrusted and run `aka init` for the full report.\n'
  );
}

function formatMode(mode: number): string {
  return `0${mode.toString(8).padStart(3, '0')}`;
}

/**
 * Say once per session that a store path is redirected through a symlink.
 *
 * On stderr rather than through `emit()`: a hook's stdout carries at most one
 * JSON object, and this warning has to reach hooks that are also emitting a real
 * decision — a second write there would concatenate into something that does not
 * parse, which the host reads as no opinion and would cost the very enforcement
 * this is warning about. stderr has no such contract and is the channel the rule
 * quarantine already warns on.
 *
 * Called from every hook that loads config: `user-prompt-submit`, `pre-tool-use`,
 * `post-tool-use` and `stop`. `session-start` reaches its config through
 * `handleSessionStart`'s own default and is covered by whichever hook fires
 * first in the session.
 *
 * Wholly best-effort: every step is inside the try, so a hostile or unreadable
 * home makes this a no-op rather than an exception on the hook's entry path.
 * The store home is derived from `dataDir` — the layout puts `data/` directly
 * under the base, and `plugin-sdk`'s `PluginConfig` resolves the leaves rather
 * than carrying the base. `store-health.test.ts` pins that derivation, so a
 * layout change fails there instead of silently reporting the wrong home.
 */
export function warnIfStoreRedirected(
  config: Pick<PluginConfig, 'dataDir'>,
  sessionId: string | undefined,
  write: (message: string) => void = (message) => void process.stderr.write(message),
): void {
  try {
    const paths = symlinkedStorePaths(dirname(config.dataDir));
    if (paths.length === 0) return;
    if (!sessionId) {
      write(storeRedirectedMessage(paths)); // no session id → can't dedupe, warn anyway
      return;
    }
    const dirs = markerDirs(config.dataDir);
    if (alreadyClaimed(dirs, STORE_REDIRECT_MARKER, sessionId)) return;
    // Write BEFORE recording the claim. The default writer is fire-and-forget
    // and `process.exit(0)` does not flush a queued pipe write, so consuming the
    // claim first would let a dropped message mark the session as warned and
    // leave the user in exactly the exit-0-and-silence state this exists to
    // remove. Recording second costs a repeat at worst, never a silence.
    write(storeRedirectedMessage(paths));
    recordClaim(dirs, STORE_REDIRECT_MARKER, sessionId);
  } catch {
    // Never break a hook over a warning — this path is advisory by construction.
  }
}
