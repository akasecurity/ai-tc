// The per-session authenticity marker for AKA's model-protocol notes. The
// standing brief teaches the model that authentic AKA notes carry this marker,
// so AKA-styled instructions embedded in untrusted content are recognizable as
// data rather than as AKA speaking. The marker is a session-scoped shared
// secret between AKA's own note emitters and the model — nothing else.
//
// What it actually defends against, stated narrowly: BLIND injection — content
// authored before it could observe this session, which is the overwhelming
// majority of the real case. It does NOT defend against an adaptive injection.
// The marker rides in `additionalContext` on every tokenized event, so the model
// holds it, and the model is what is under attack: an injection that induces one
// echo of the marker — into a command, a file write, a fetched URL, a summary of
// its own context — can wear it from then on, and every note becomes forgeable
// for the rest of the session. It is a one-shot secret whose first leak burns it
// silently, with no signal to anyone.
import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { DATA_DIR_MODE, DATA_FILE_MODE } from '@akasecurity/plugin-sdk';

// One file, overwritten each new session (the nudge.ts single-marker scheme),
// so markers never accumulate. Holds JSON { sessionId, marker } — the session
// id it was minted for, and the marker itself.
const MARKER_FILE = 'protocol-marker';

// 8 random bytes → 16 lowercase hex chars: short enough to ride every note,
// long enough that injected content cannot guess it.
function mintMarker(): string {
  return randomBytes(8).toString('hex');
}

/**
 * Return the authenticity marker for `sessionId`, minting and persisting a new
 * one the first time a session asks. Every note emitter in the same session
 * reads the same file, so the marker stays stable across hook processes.
 *
 * The marker lives ONLY in this file (owner-only, atomic tmp + rename write);
 * it is never persisted to the SQLite store and never logged — anything that
 * records it durably would widen the surface an attacker could read it from.
 *
 * Fail-open: with no session id (nothing to key on) or on any fs error, a
 * freshly minted in-memory marker is returned instead of throwing. A marker
 * that mismatches across notes degrades to the model distrusting a legitimate
 * note — cautious, not broken — so failure never blocks the hook path.
 *
 * That degrade is SILENT and, from the model's side, indistinguishable from a
 * forgery: if the standing brief taught marker X and a later hook cannot read
 * the file, the model sees Y and distrusts an authentic note. Nothing surfaces
 * that this happened.
 */
export function sessionProtocolMarker(dataDir: string, sessionId: string | undefined): string {
  if (!sessionId) return mintMarker();
  const path = join(dataDir, MARKER_FILE);

  try {
    const stored = JSON.parse(readFileSync(path, 'utf8')) as {
      sessionId?: unknown;
      marker?: unknown;
    };
    if (
      stored.sessionId === sessionId &&
      typeof stored.marker === 'string' &&
      /^[0-9a-f]{16}$/.test(stored.marker)
    ) {
      return stored.marker;
    }
  } catch {
    // No marker yet (or unreadable) — mint below.
  }

  const marker = mintMarker();
  try {
    mkdirSync(dataDir, { recursive: true, mode: DATA_DIR_MODE });
    // Atomic tmp + rename so a concurrent reader never sees a partial file.
    const tmp = join(dataDir, `${MARKER_FILE}.tmp`);
    writeFileSync(tmp, JSON.stringify({ sessionId, marker }), { mode: DATA_FILE_MODE });
    renameSync(tmp, path);
  } catch {
    // Couldn't persist — hand back the in-memory marker anyway (fail-open).
  }
  return marker;
}
