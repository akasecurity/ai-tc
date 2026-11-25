// Registering this plugin's hooks in a Cursor `hooks.json`, as pure functions
// over the parsed file so they unit-test without touching a real one.
//
// Cursor reads user-level hooks from `~/.cursor/hooks.json`:
//
//   { "version": 1,
//     "hooks": { "<event>": [ { "command": "…", "timeout": 30 }, … ], … } }
//
// The file belongs to the user and may hold hooks of their own, so a merge
// touches only the entries this plugin owns. An entry is ours when its command
// carries `OWNER_MARKER` as its last argument; the hook scripts read their
// event from `argv[2]` and ignore the rest, so the marker costs nothing at run
// time and survives the scripts moving to a new directory on update.
import { join } from 'node:path';

import type { HookEvent } from './hooks/event-name.ts';

export const OWNER_MARKER = 'aka-cursor';

/** Seconds Cursor waits for a hook; `WATCHDOG_MS` in ./hooks/shared.ts sits under it. */
export const HOOK_TIMEOUT_SECONDS = 30;

/** The events this plugin registers, and the built script each one runs. */
export const HOOK_SCRIPTS = {
  sessionStart: 'session-start.js',
  beforeSubmitPrompt: 'before-submit-prompt.js',
  preToolUse: 'pre-tool-use.js',
  postToolUse: 'post-tool-use.js',
} as const satisfies Partial<Record<HookEvent, string>>;

export type RegisteredEvent = keyof typeof HOOK_SCRIPTS;

export interface HookEntry {
  command?: string;
  timeout?: number;
  [key: string]: unknown;
}

export interface HooksFile {
  version: number;
  hooks: Record<string, HookEntry[]>;
  [key: string]: unknown;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * The command for one event. Both paths are double-quoted so a home directory
 * with a space in it survives the shell Cursor runs the command through.
 */
export function hookCommand(nodePath: string, scriptsDir: string, event: RegisteredEvent): string {
  const script = join(scriptsDir, HOOK_SCRIPTS[event]);
  return `"${nodePath}" "${script}" ${event} ${OWNER_MARKER}`;
}

/** Whether an entry is one this plugin wrote. */
export function isOwnEntry(entry: HookEntry): boolean {
  if (typeof entry.command !== 'string') return false;
  const parts = entry.command.trim().split(/\s+/);
  return parts.at(-1) === OWNER_MARKER;
}

/**
 * Validate a parsed `hooks.json`. Throws on a shape this module cannot merge
 * into without losing something, so the caller refuses rather than overwriting
 * a file it does not understand. An absent file is `undefined` and reads as
 * empty.
 */
export function parseHooksFile(parsed: unknown): HooksFile {
  if (parsed === undefined) return { version: 1, hooks: {} };
  if (!isRecord(parsed)) throw new Error('expected a JSON object at the top level');
  if (parsed.version !== undefined && typeof parsed.version !== 'number') {
    throw new Error('expected "version" to be a number');
  }
  const hooks = parsed.hooks ?? {};
  if (!isRecord(hooks)) throw new Error('expected "hooks" to be an object');
  const checked: Record<string, HookEntry[]> = {};
  for (const [event, entries] of Object.entries(hooks)) {
    if (!Array.isArray(entries) || !entries.every(isRecord)) {
      throw new Error(`expected "hooks.${event}" to be an array of objects`);
    }
    checked[event] = entries;
  }
  return { ...parsed, version: parsed.version ?? 1, hooks: checked };
}

/** Every entry this plugin owns removed; an event left with none is dropped. */
export function removeOwnHooks(file: HooksFile): HooksFile {
  const hooks: Record<string, HookEntry[]> = {};
  for (const [event, entries] of Object.entries(file.hooks)) {
    const kept = entries.filter((entry) => !isOwnEntry(entry));
    if (kept.length > 0) hooks[event] = kept;
  }
  return { ...file, hooks };
}

/**
 * This plugin's entries replaced with one per registered event, pointing at
 * `scriptsDir`. Entries of the user's own keep their place; ours go last.
 */
export function mergeOwnHooks(file: HooksFile, nodePath: string, scriptsDir: string): HooksFile {
  const base = removeOwnHooks(file);
  const hooks = { ...base.hooks };
  for (const event of Object.keys(HOOK_SCRIPTS) as RegisteredEvent[]) {
    hooks[event] = [
      ...(hooks[event] ?? []),
      { command: hookCommand(nodePath, scriptsDir, event), timeout: HOOK_TIMEOUT_SECONDS },
    ];
  }
  return { ...base, hooks };
}
