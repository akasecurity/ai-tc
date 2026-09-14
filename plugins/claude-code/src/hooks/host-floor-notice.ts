// The once-per-session notice that this Claude Code is too old for part of what
// AKA enforces. Split out of the hook entries so it can be unit-tested without
// importing one (a hook ENTRY runs main() on import and would block collection).
//
// WHY THIS FIRES FROM Stop AND PostToolUse, AND NOT FROM SessionStart. The host
// version is only discoverable from the transcript, and at SessionStart the
// transcript is either empty (a fresh session) or still holds the PREVIOUS run's
// records (a resume). Warning from there tells a user who has just upgraded to
// upgrade — the one outcome this feature must never produce. Stop and PostToolUse
// both fire after the assistant has written to the transcript in THIS run, so
// "newest version-bearing record" is the running host by the hook's own
// semantics, with no marker, clock or cutoff needed to establish it.
//
// The cost is that the notice lands at the end of the first turn rather than at
// the session banner, and that a session with no turns never observes anything.
// `aka status` and /aka:health cover that user from the cache instead.
import { mkdirSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  DATA_DIR_MODE,
  DATA_FILE_MODE,
  hostFloorNotice,
  hostVersionFromTranscript,
  type PluginConfig,
  recordHostVersion,
} from '@akasecurity/plugin-sdk';

// One file per session rather than a single shared marker holding the last id.
// The shared form has two failure modes this path actually hits: two windows on
// the same old host each invalidate the other's claim, so the notice reprints
// every turn in both; and PostToolUse is the first caller that runs CONCURRENTLY
// (Claude Code spawns a hook per parallel tool call), so a read-then-write claim
// lets every racer through at once.
const CLAIM_DIR = 'host-floor-claims';

// A resumed session keeps its id, so a claim that never expired would silence
// the notice for the life of a session someone `--continue`s for days. Long
// enough that one sitting is never nagged twice; short enough that tomorrow's
// sitting is told again.
const CLAIM_TTL_MS = 12 * 60 * 60 * 1000;

// Claims outlive their sessions; sweep on the rare path that creates one.
const CLAIM_SWEEP_MS = 7 * 24 * 60 * 60 * 1000;

function sweep(dir: string): void {
  try {
    for (const name of readdirSync(dir)) {
      const path = join(dir, name);
      try {
        if (Date.now() - statSync(path).mtimeMs > CLAIM_SWEEP_MS) rmSync(path, { force: true });
      } catch {
        // Raced with another sweeper, or unreadable — leave it.
      }
    }
  } catch {
    // No directory yet.
  }
}

/**
 * Take the right to print for this session, or null when somebody already has it.
 *
 * Returns a RELEASE so a fire that learned nothing — or whose write threw — does
 * not consume the session's one notice. That is the ordering
 * `warnIfStoreRedirected` gets by claiming after it writes; an exclusive create
 * has to come first to exclude concurrent hooks, so the claim is undone instead.
 */
function tryClaim(dataDir: string, sessionId: string | undefined): (() => void) | null {
  // No session id → nothing to dedupe on. Warn anyway: repeating a notice is
  // noise, hiding that a protection is off is not.
  if (sessionId === undefined || sessionId === '') return () => undefined;
  const dir = join(dataDir, CLAIM_DIR);
  const path = join(dir, encodeURIComponent(sessionId));
  try {
    if (Date.now() - statSync(path).mtimeMs < CLAIM_TTL_MS) return null;
    rmSync(path, { force: true });
  } catch {
    // No claim for this session yet.
  }
  try {
    mkdirSync(dir, { recursive: true, mode: DATA_DIR_MODE });
    // `wx` is the whole point: exclusive create is atomic, so exactly one of N
    // racing hooks wins and the rest get EEXIST.
    writeFileSync(path, String(Date.now()), { flag: 'wx', mode: DATA_FILE_MODE });
  } catch (err) {
    // EEXIST means a peer won. Anything else means the claim cannot be recorded
    // at all, and then warning without dedupe beats staying silent.
    if ((err as NodeJS.ErrnoException).code === 'EEXIST') return null;
    return () => undefined;
  }
  sweep(dir);
  return () => {
    try {
      rmSync(path, { force: true });
    } catch {
      // Best effort; a stale claim expires on its own.
    }
  };
}

/**
 * Observe the running host's version, cache it, and warn once per session when
 * it is below a floor AKA needs.
 *
 * Silent on every unknown — no transcript path, an unreadable file, no
 * version-bearing record, a string no comparison can act on. A false "update
 * Claude Code" on a correct install costs more than a missed warning.
 */
export function warnIfHostBelowFloor(
  config: Pick<PluginConfig, 'dataDir'>,
  sessionId: string | undefined,
  transcriptPath: string | undefined,
  write: (message: string) => void = (message) => void process.stderr.write(message),
): void {
  try {
    // The cheap gate goes FIRST. Everything below is a transcript read and a
    // cache write, and PostToolUse fires per tool call — so with the gate last,
    // a current host (where there is never anything to say) paid both on every
    // call for the whole session.
    const release = tryClaim(config.dataDir, sessionId);
    if (release === null) return;
    let settled = false;
    try {
      const version = hostVersionFromTranscript(transcriptPath);
      // Learned nothing — a fresh transcript with no version-bearing record yet.
      // Release, so a later fire in this session can still observe.
      if (version === undefined) return;
      recordHostVersion(config.dataDir, version);
      const notice = hostFloorNotice(version);
      if (notice !== null) write(`[aka] ${notice}\n`);
      // Set last: a write that threw leaves this false, so the claim is released
      // and the next fire retries rather than the session losing its one notice.
      settled = true;
    } finally {
      if (!settled) release();
    }
  } catch {
    // Never break a hook over a warning — this path is advisory by construction.
  }
}
