import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { DATA_DIR_MODE, DATA_FILE_MODE } from './data-dir.ts';

// A single marker holding the last session id we nudged. One file, overwritten
// each new session, so it never accumulates the way a per-session marker would.
const NUDGE_MARKER = 'nudge-last-session';

// The same single-marker scheme for the SessionStart inventory pass: SessionStart
// can fire several times for one session (startup, resume, clear), but the
// resolve + ensureInventory + open-session work only needs to run once.
const SESSION_START_MARKER = 'session-start-last';

/**
 * Gate the "not yet onboarded" `/aka:setup` nudge to once per Claude Code
 * session instead of once per prompt — otherwise a user who sends N clean
 * prompts before onboarding sees the same pointer N times.
 *
 * Records the current session id in a single marker file and returns true only
 * the first time a given session asks; later prompts in the same session return
 * false. Fail-open: with no session id (can't dedupe), or on any fs error, it
 * returns true — showing the nudge an extra time is harmless; silently breaking
 * the hook path is not.
 */
export function claimOnboardingNudge(dataDir: string, sessionId: string | undefined): boolean {
  return claimOncePerSession(dataDir, NUDGE_MARKER, sessionId);
}

/**
 * Claim the per-session SessionStart inventory pass: returns true the first time
 * a given session id is seen, false thereafter, so the resolve + ensureInventory
 * + open-session work runs once per session even though SessionStart can fire
 * repeatedly. Fail-open: no session id (can't dedupe) or any fs error returns
 * true — doing the idempotent inventory work an extra time is harmless; breaking
 * the hook is not.
 */
export function claimSessionStart(dataDir: string, sessionId: string | undefined): boolean {
  return claimOncePerSession(dataDir, SESSION_START_MARKER, sessionId);
}

// Single-marker "once per session" claim shared by the nudge and SessionStart
// passes: a file holds the last session id, overwritten each new session so it
// never accumulates. Returns true the first time `sessionId` claims `marker`.
//
// Two deliberate semantics, both safe because the callers are idempotent (the
// inventory upserts are content-addressed and the audit root uses INSERT OR
// IGNORE):
//   1. The marker records "attempted", not "succeeded": it is written before the
//      caller's work runs, so a pass that fails mid-way is NOT retried on a later
//      SessionStart for the same session. Re-running the idempotent work is the
//      cheaper trade than persisting a claim only on success.
//   2. The marker is a single shared file, so two concurrent Claude Code sessions
//      can overwrite each other's id and a session may re-run its pass. Harmless
//      for the same reason; a per-session marker would just leak files.
function claimOncePerSession(
  dataDir: string,
  marker: string,
  sessionId: string | undefined,
): boolean {
  if (!sessionId) return true; // no session id → can't dedupe, just run
  const path = join(dataDir, marker);
  try {
    if (readFileSync(path, 'utf8') === sessionId) return false;
  } catch {
    // no marker yet (or unreadable) → this is the first claim for the session
  }
  try {
    mkdirSync(dataDir, { recursive: true, mode: DATA_DIR_MODE });
    writeFileSync(path, sessionId, { mode: DATA_FILE_MODE });
  } catch {
    // couldn't record the claim → still run once now (fail-open)
  }
  return true;
}
