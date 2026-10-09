import { readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';

/** The directory under the data dir where the Claude Code mod notes that it is running. */
export const MOD_SESSIONS_DIR = 'mod-sessions';

/** How long a note counts as "the mod is running": the mod renews it on every prompt. */
export const MOD_ACTIVE_TTL_MS = 15 * 60 * 1000;

const SWEEP_AFTER_MS = 7 * 24 * 60 * 60 * 1000;

/** How a Claude Code session handles a prompt whose policy says `redact`. */
export type PromptRedactionMode = 'in-place' | 'block';

/** The file name the mod writes for a session. */
export function modSessionFileName(sessionId: string): string {
  return `${encodeURIComponent(sessionId)}.json`;
}

/** The note the mod writes: the session it belongs to and when it was last renewed. */
export function modSessionNote(sessionId: string, now: number): string {
  return JSON.stringify({ v: 1, sessionId, at: now });
}

interface Note {
  sessionId: string;
  at: number;
}

function parseNote(text: string): Note | null {
  try {
    const raw: unknown = JSON.parse(text);
    if (typeof raw !== 'object' || raw === null) return null;
    const { v, sessionId, at } = raw as { v?: unknown; sessionId?: unknown; at?: unknown };
    if (v !== 1 || typeof sessionId !== 'string' || typeof at !== 'number') return null;
    return Number.isFinite(at) ? { sessionId, at } : null;
  } catch {
    return null;
  }
}

function readNotes(dataDir: string): Note[] {
  const dir = join(dataDir, MOD_SESSIONS_DIR);
  const notes: Note[] = [];
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return notes;
  }
  for (const name of names) {
    const path = join(dir, name);
    try {
      const note = parseNote(readFileSync(path, 'utf8'));
      if (note !== null) notes.push(note);
      if (Date.now() - statSync(path).mtimeMs > SWEEP_AFTER_MS) rmSync(path, { force: true });
    } catch {
      // Unreadable or removed by another reader: not a note.
    }
  }
  return notes;
}

/**
 * The mode a Claude Code session redacts prompts in, from evidence that its mod
 * ran: a note for that session (or, with no session, for any session) renewed
 * within `MOD_ACTIVE_TTL_MS`. Anything else, including an unreadable directory,
 * is `block`.
 */
export function promptRedactionMode(
  dataDir: string,
  sessionId: string | undefined,
  now = Date.now(),
): PromptRedactionMode {
  const fresh = readNotes(dataDir).some(
    (n) =>
      (sessionId === undefined || n.sessionId === sessionId) &&
      now - n.at >= 0 &&
      now - n.at < MOD_ACTIVE_TTL_MS,
  );
  return fresh ? 'in-place' : 'block';
}

/**
 * The line for `aka status` and /aka:health, or none for a machine with no
 * Claude Code on it (`claudeCodeSeen` false).
 */
export function promptRedactionLines(
  dataDir: string,
  claudeCodeSeen: boolean,
  now = Date.now(),
): string[] {
  if (!claudeCodeSeen) return [];
  return promptRedactionMode(dataDir, undefined, now) === 'in-place'
    ? ['  prompts: redacted in place (the Claude Code mod is running)']
    : [
        '  prompts: blocked when they need redaction (the Claude Code mod has not run in a recent session)',
      ];
}
