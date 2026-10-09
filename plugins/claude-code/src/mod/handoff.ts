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
// One file per note, under <dataDir>/mod-handoff/. Several helpers (one per
// prompt, one per tool call, in parallel) write notes while hooks consume them, so
// no note shares a file with another: a shared file read, changed and renamed back
// by two processes loses whichever write lands first. A note is written to a
// temporary name (created exclusively) and renamed into place, so it is never seen
// half written; consuming a note is unlinking exactly that file, and the unlink
// that succeeds is the one consumption, so a note is spent once however many hooks
// race for it. A note expires by its age: past the TTL, or dated ahead of this
// machine's clock by more than a small skew (a future date must not make a note
// immortal), it is spent without being honoured. Stale files are swept a bounded
// number at a time as notes are recorded.
//
// Best effort throughout: a missing, unreadable or corrupt note means the hook
// captures as it always did, which can only add a row, never lose one.
import { createHash, randomBytes } from 'node:crypto';
import {
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';

import { DATA_DIR_MODE, DATA_FILE_MODE } from '@akasecurity/plugin-sdk';

const HANDOFF_DIR = 'mod-handoff';
// The single shared file earlier builds kept every note in; no longer read.
const LEGACY_FILE = 'mod-handoff.json';
// A hook runs within a second or two of the mod; this is only the bound on a
// note nobody consumed (the host was not running the hook).
export const HANDOFF_TTL_MS = 2 * 60 * 1000;
// How far ahead of this machine's clock a note may be dated and still be fresh.
export const HANDOFF_SKEW_MS = 5 * 1000;
// A directory this full is not written to (the hook then captures, as ever).
const MAX_NOTES = 512;
// What one sweep may look at and remove, so recording stays cheap however much
// has piled up.
const SWEEP_SCAN = 256;
const SWEEP_REMOVE = 64;

function hashOf(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}

// A note's content: when it was written, by the writer's clock.
function isFresh(path: string, now: number): boolean {
  try {
    const parsed: unknown = JSON.parse(readFileSync(path, 'utf8'));
    const at = (parsed as { at?: unknown } | null)?.at;
    return typeof at === 'number' && at <= now + HANDOFF_SKEW_MS && now - at < HANDOFF_TTL_MS;
  } catch {
    return false;
  }
}

// Removes files nobody consumed, a bounded number at a time. A file's own mtime
// (the real clock, not the `now` a caller passes) says it is stale: older than the
// TTL, or dated ahead of the clock.
function sweep(dir: string, dataDir: string, names: readonly string[]): void {
  const clock = Date.now();
  let removed = 0;
  for (const name of names.slice(0, SWEEP_SCAN)) {
    if (removed >= SWEEP_REMOVE) break;
    try {
      const { mtimeMs } = statSync(join(dir, name));
      if (mtimeMs < clock - HANDOFF_TTL_MS || mtimeMs > clock + HANDOFF_SKEW_MS) {
        unlinkSync(join(dir, name));
        removed += 1;
      }
    } catch {
      // Gone already, or not ours to remove.
    }
  }
  rmSync(join(dataDir, LEGACY_FILE), { force: true });
}

function record(dataDir: string, hash: string, now: number): void {
  try {
    const dir = join(dataDir, HANDOFF_DIR);
    mkdirSync(dir, { recursive: true, mode: DATA_DIR_MODE });
    const names = readdirSync(dir);
    sweep(dir, dataDir, names);
    if (names.length >= MAX_NOTES) return;
    const nonce = `${String(process.pid)}-${randomBytes(6).toString('hex')}`;
    const tmp = join(dir, `.${nonce}.tmp`);
    writeFileSync(tmp, JSON.stringify({ at: now }), { mode: DATA_FILE_MODE, flag: 'wx' });
    renameSync(tmp, join(dir, `${hash}.${nonce}.json`));
  } catch {
    // The hook captures too: a duplicate row, never a missing one.
  }
}

function consume(dataDir: string, hash: string, now: number): boolean {
  try {
    const dir = join(dataDir, HANDOFF_DIR);
    const prefix = `${hash}.`;
    for (const name of readdirSync(dir)) {
      if (!name.startsWith(prefix) || !name.endsWith('.json')) continue;
      const path = join(dir, name);
      const fresh = isFresh(path, now);
      try {
        unlinkSync(path);
      } catch {
        // Another hook spent it first.
        continue;
      }
      if (fresh) return true;
    }
    return false;
  } catch {
    return false;
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
