// The note the prompt mod's helper leaves for the UserPromptSubmit command hook.
//
// The helper records the prompt's event and findings (it holds the store and the
// original text). The command hook then runs on the REWRITTEN prompt; recording
// that too would put a second event in Activity for one prompt. So the helper
// writes the SHA-256 of the text it handed back, and the hook, finding its own
// prompt's hash there, skips its capture once. The hash is of the rewritten text
// (pointers and markers), so it names no raw value and cannot be reversed to one.
//
// The tool.call mod's helper leaves the same kind of note for a tool call, named by
// the tool and the input it will run with, and the PreToolUse command hook consumes
// it the same way. There the note carries more weight than a missing row: the
// helper may have spent a single-use grant, which a second pass could not.
//
// Best effort throughout: a missing, unreadable or corrupt file means the hook
// captures as it always did, which can only add a row, never lose one.
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { DATA_DIR_MODE, DATA_FILE_MODE } from '@akasecurity/plugin-sdk';

const HANDOFF_FILE = 'mod-handoff.json';
// A hook runs within a second or two of the mod; this is only the bound on a
// note nobody consumed (the host was not running the hook).
export const HANDOFF_TTL_MS = 2 * 60 * 1000;
const MAX_ENTRIES = 16;

interface Entry {
  hash: string;
  at: number;
}

function hashOf(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}

function read(path: string, now: number): Entry[] {
  try {
    const parsed: unknown = JSON.parse(readFileSync(path, 'utf8'));
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (e): e is Entry =>
        typeof e === 'object' &&
        e !== null &&
        typeof (e as Entry).hash === 'string' &&
        typeof (e as Entry).at === 'number' &&
        now - (e as Entry).at < HANDOFF_TTL_MS,
    );
  } catch {
    return [];
  }
}

function write(dataDir: string, path: string, entries: Entry[]): void {
  mkdirSync(dataDir, { recursive: true, mode: DATA_DIR_MODE });
  const tmp = `${path}.${String(process.pid)}.tmp`;
  writeFileSync(tmp, JSON.stringify(entries.slice(-MAX_ENTRIES)), { mode: DATA_FILE_MODE });
  renameSync(tmp, path);
}

function record(dataDir: string, hash: string, now: number): void {
  try {
    const path = join(dataDir, HANDOFF_FILE);
    write(dataDir, path, [...read(path, now), { hash, at: now }]);
  } catch {
    // The hook captures too: a duplicate row, never a missing one.
  }
}

/** Leaves a note that `rewritten` is a prompt whose event is already recorded. */
export function recordModHandoff(dataDir: string, rewritten: string, now = Date.now()): void {
  record(dataDir, hashOf(rewritten), now);
}

/** True once per note: the prompt is one the mod's helper already recorded. */
export function consumeModHandoff(dataDir: string, prompt: string, now = Date.now()): boolean {
  return consume(dataDir, hashOf(prompt), now);
}

// A tool call is named by its tool and its input, with object keys in a fixed
// order so the host re-serialising the input cannot change the name. The
// `tool:` prefix keeps it apart from a prompt's hash.
function toolKey(toolName: string, toolInput: unknown): string {
  const canonical = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(canonical);
    if (typeof value !== 'object' || value === null) return value;
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([k, v]) => [k, canonical(v)]),
    );
  };
  return hashOf(`tool:${toolName}\0${JSON.stringify(canonical(toolInput))}`);
}

/**
 * Leaves a note that the call (`toolName`, `toolInput`) was decided by the
 * tool.call mod's helper, which recorded its findings and spent any grant it
 * needed. `toolInput` is the input the tool will run with.
 */
export function recordToolHandoff(
  dataDir: string,
  toolName: string,
  toolInput: unknown,
  now = Date.now(),
): void {
  record(dataDir, toolKey(toolName, toolInput), now);
}

/** True once per note: this call is one the mod's helper already decided. */
export function consumeToolHandoff(
  dataDir: string,
  toolName: string,
  toolInput: unknown,
  now = Date.now(),
): boolean {
  return consume(dataDir, toolKey(toolName, toolInput), now);
}

function consume(dataDir: string, hash: string, now: number): boolean {
  try {
    const path = join(dataDir, HANDOFF_FILE);
    const entries = read(path, now);
    const at = entries.findIndex((e) => e.hash === hash);
    if (at === -1) return false;
    entries.splice(at, 1);
    write(dataDir, path, entries);
    return true;
  } catch {
    return false;
  }
}
