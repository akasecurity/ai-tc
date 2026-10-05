// Claude Code stdio helpers — the only tool-specific glue the adapter keeps.
// Detection, policy, and persistence live in @akasecurity/plugin-sdk; these
// just move bytes between Claude Code and the runtime.

import { dirname, isAbsolute, normalize } from 'node:path';

import { dataDir, recordHookFailOpen, resolveRepoAttribution } from '@akasecurity/plugin-sdk';
import type { EventMetadata } from '@akasecurity/schema';

import type { PreModelSwitchOutput } from './model-guard.ts';
import type { PreToolUseOutput } from './pre-tool-use-decision.ts';

// An 'error' event on an EventEmitter with no listener throws — and because it
// fires asynchronously, that throw lands as an uncaughtException outside any
// `try { await main() } catch {}` wrapper, turning a stalled/broken stdin into
// a non-zero exit instead of the fail-open contract every hook promises. A
// stalled stdin with no error either is just as bad: nothing here ever
// rejects or times out, so it hangs to the harness's own kill budget. Resolve
// with whatever was read so far on either 'error' or a 5s timeout (half the
// 10s hook budget), so a broken or stalled caller degrades to "scan whatever
// arrived" instead of a crash or a full hang.
//
// The 'error' listener is deliberately never removed, even after settling:
// hooks call readStdin() once and exit shortly after, so one leftover no-op
// listener for the rest of the process's life is free — and it means ANY
// stdin error, no matter when it lands relative to the read, is caught.
export async function readStdin(): Promise<string> {
  return new Promise<string>((resolve) => {
    let data = '';
    let settled = false;

    const finish = (): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      process.stdin.removeListener('data', onData);
      process.stdin.removeListener('end', finish);
      resolve(data);
    };
    const onData = (chunk: string): void => {
      data += chunk;
    };
    const timer = setTimeout(finish, 5_000);

    process.stdin.setEncoding('utf8');
    process.stdin.on('data', onData);
    process.stdin.on('end', finish);
    process.stdin.on('error', finish);
  });
}

export function parseJson(raw: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(raw);
    return typeof parsed === 'object' && parsed !== null
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

export function getString(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key];
  return typeof value === 'string' ? value : undefined;
}

// Every JSON object a hook may write to stdout, as one union. `emit` takes this
// rather than `unknown`, so a new output shape cannot reach the wire without
// being added here first — which is what makes the enumeration in CLAUDE.md §1
// checkable instead of remembered. Two shapes sit at the top level; the rest are
// one `hookSpecificOutput` per hook, discriminated by `hookEventName`.
export type HookOutput =
  | { decision: 'block'; reason: string }
  // Spelled here even though `PreToolUseOutput` below ends in the same arm, so
  // that a bare systemMessage — what UserPromptSubmit and the store-unavailable
  // paths emit — does not depend on a type named for a different hook. The two
  // are structurally identical, so deleting this line still compiles and no test
  // can object: it is a silent downgrade rather than a cleanup.
  | { systemMessage: string }
  | PreToolUseOutput
  | PreModelSwitchOutput
  | {
      hookSpecificOutput: {
        hookEventName: 'PostToolUse';
        updatedToolOutput: unknown;
        additionalContext?: string;
      };
      systemMessage: string;
    }
  | { hookSpecificOutput: { hookEventName: 'MessageDisplay'; displayContent: string } }
  | { hookSpecificOutput: { hookEventName: 'SessionStart'; additionalContext: string } };

// Hook output protocol: write one JSON object to stdout and exit 0.
// Writing nothing and exiting 0 means "no opinion" (allow).
//
// The flush must be awaited: hook entries call process.exit(0) right after
// main(), and exit does not wait for pending pipe writes — anything past the
// ~64KB pipe buffer is dropped, Claude Code sees invalid JSON, and the
// original (possibly secret-bearing) payload passes through untouched.
export function emit(output: HookOutput): Promise<void> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (): void => {
      if (settled) return;
      settled = true;
      resolve();
    };
    // Same hazard as readStdin: an unhandled 'error' on stdout (e.g. EPIPE if
    // the caller closed its end) is an uncaughtException, not a rejection —
    // resolve instead so the hook still exits 0 rather than crashing on
    // write. Deliberately never removed, for the same reason: a hook process
    // exits right after, so one leftover no-op listener is free, and it
    // means any later stdout error before exit is caught too.
    process.stdout.on('error', finish);
    process.stdout.write(JSON.stringify(output), finish);
  });
}

// Base event metadata every Claude Code hook can derive from its stdin payload:
// the session id and the repo slug. Repo is resolved from the hook's `cwd` (all
// Claude Code hook events carry it), falling back to the hook process's own cwd —
// hooks run in the project root, so this is the same directory. Returns undefined
// when nothing could be derived, so callers keep passing the optional metadata
// through unchanged. Per-hook fields (filePath, …) are layered on by the caller.
//
// The slug comes from `resolveRepoAttribution`, the memoised walk
// `captureScopeKey` below shares, so a hook that asks for both pays for one
// `.git` walk and one config read. `repo` is exactly what `resolveRepo` returned
// here before.
export function baseMetadata(input: Record<string, unknown>): EventMetadata | undefined {
  const metadata: EventMetadata = {};
  const sessionId = getString(input, 'session_id');
  if (sessionId) metadata.sessionId = sessionId;
  const repo = resolveRepoAttribution(getString(input, 'cwd') ?? process.cwd()).repo;
  if (repo) metadata.repo = repo;
  return Object.keys(metadata).length > 0 ? metadata : undefined;
}

// The scope key of the checkout this event happened in: the canonical
// `host/owner/repo` of its origin (else first) remote. It is undefined for a
// directory with no remote, a remote that is a local path, or no checkout at
// all. A scoped attachment's verdict compares it against the enrolled repos,
// and no key keeps the event on this machine.
//
// WHICH DIRECTORY. An event that names an ABSOLUTE file (the `filePath` the
// caller stamps as metadata.filePath: a Write, Edit, MultiEdit or NotebookEdit
// target, a Read source) is keyed by that file's checkout. A session that
// starts in one repo and writes into another must have each write keyed where
// it landed, or a file in a personal checkout would leave under the work key.
// That key never falls back to the cwd: a file outside any checkout, or in one
// with no remote, gets no key at all.
//
// Every other event (no file, or a relative path) is keyed from the directory
// baseMetadata reads, fallback included. SessionStart keys the session root
// from that directory too (session-start.ts resolves `cwd ?? process.cwd()` the
// same way), so a path-less event and its root agree by construction. A
// relative path is not resolved against the cwd: the file tools take absolute
// paths, and the cwd key is what an event without one gets.
//
// The path is normalised first. The walk climbs by dirname, so a `..` segment
// left in place would climb back into the directory it left and find that
// checkout's `.git` for a file that is not in it.
//
// COST. A path-less event pays nothing extra: baseMetadata has just walked the
// same directory, and the resolver is memoised per directory. A file's
// directory is one more walk (one existsSync per level up to its `.git`, one
// config read), memoised the same way. It is not skipped for a file under the
// cwd's checkout, because a nested clone or submodule there is its own
// checkout with its own key.
//
// TOTAL. The resolver never throws by contract, but `process.cwd()` does when
// the working directory has been deleted. A throw here would reach the hook's
// outer catch and cost the capture itself. A key that cannot be resolved is
// simply absent, which fails closed toward the server and never open toward
// the harness.
//
// The key rides BESIDE the event (`CaptureInput.scopeKey`), never inside
// EventMetadata, because that is a published wire shape and this attribute is
// local. metadata.repo stays the cwd's slug either way: it is wire too, and
// machine-mode bytes do not change.
export function captureScopeKey(
  input: Record<string, unknown>,
  filePath?: string,
): string | undefined {
  try {
    const dir =
      filePath !== undefined && isAbsolute(filePath)
        ? dirname(normalize(filePath))
        : (getString(input, 'cwd') ?? process.cwd());
    return resolveRepoAttribution(dir).scopeKey;
  } catch {
    return undefined;
  }
}

// The scope key for an event that names a SEARCH ROOT rather than a file: Grep's
// `path`, which is a directory or a single file. It follows captureScopeKey's
// rules (an absolute root is normalised and never falls back to the cwd; no
// root, or a relative one, takes the cwd key) with one difference: the walk
// starts at the root ITSELF, not at its parent. A root may be a checkout's top
// level, and starting at the parent would miss that checkout, or name the
// enclosing one when the root is a nested clone or submodule. A single-file
// root needs no special case: the resolver climbs by name, and a file has no
// `.git` of its own to find on the way.
export function searchRootScopeKey(
  input: Record<string, unknown>,
  searchRoot?: string,
): string | undefined {
  try {
    const dir =
      searchRoot !== undefined && isAbsolute(searchRoot)
        ? normalize(searchRoot)
        : (getString(input, 'cwd') ?? process.cwd());
    return resolveRepoAttribution(dir).scopeKey;
  } catch {
    return undefined;
  }
}

// The one thing a hook does on its way out of its fail-open catch: count the
// exit, so `aka status` can say the hooks have been failing open on this
// machine. Nothing here may throw: a throw from inside that catch would escape
// as an uncaught exception and turn a silent allow into a non-zero exit, which
// is the one outcome the catch exists to prevent. `recordHookFailOpen`
// swallows every fs error by contract, but the home directory is resolved
// before it is called — and `os.homedir()` throws when the platform cannot
// name one — so the whole body is guarded here as well. Stdout is untouched,
// so the silence the host reads as "no opinion" is preserved exactly.
//
// `base` is the ~/.aka root and exists for tests; a hook passes nothing and
// resolves the same home `loadConfig` does (`homedir()`, which honours the
// HOME the e2e matrix injects). Resolved from the layout rather than from a
// config read, because a settings read is one more thing that could be what
// threw.
export function countFailOpen(base?: string): void {
  try {
    recordHookFailOpen(dataDir(base), Date.now());
  } catch {
    // A fail-open exit that cannot even be located is still a fail-open exit.
  }
}
