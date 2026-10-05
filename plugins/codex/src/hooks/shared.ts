// Codex CLI stdio helpers — the only tool-specific glue the adapter keeps.
// Detection, policy, and persistence live in @akasecurity/plugin-sdk; these
// just move bytes between Codex and the runtime. Structurally identical to
// plugins/claude-code/src/hooks/shared.ts — Codex's hook stdin/stdout
// contract is the same JSON-over-stdio shape.

import { dirname, isAbsolute, normalize, resolve as resolvePath } from 'node:path';

import { dataDir, recordHookFailOpen, resolveRepoAttribution } from '@akasecurity/plugin-sdk';
import type { EventMetadata } from '@akasecurity/schema';

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
    // A stalled or never-closed stdin must not hang the hook past the host's
    // own timeout: settle with whatever arrived and let the caller fail open.
    const timer = setTimeout(finish, 5_000);

    process.stdin.setEncoding('utf8');
    process.stdin.on('data', onData);
    process.stdin.on('end', finish);
    // An unhandled 'error' here would be an uncaughtException, not a
    // rejection — settle instead so the hook still exits 0.
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

// Hook output protocol: write one JSON object to stdout and exit 0.
// Writing nothing and exiting 0 means "no opinion" (allow).
//
// The flush must be awaited: hook entries call process.exit(0) right after
// main(), and exit does not wait for pending pipe writes — anything past the
// ~64KB pipe buffer is dropped, Codex sees invalid JSON, and the original
// (possibly secret-bearing) payload passes through untouched.
export function emit(output: unknown): Promise<void> {
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
    // write. Deliberately never removed: a hook process exits right after, so
    // one leftover no-op listener is free.
    process.stdout.on('error', finish);
    process.stdout.write(JSON.stringify(output), finish);
  });
}

// Base event metadata every Codex hook can derive from its stdin payload: the
// session id and the repo slug. Repo is resolved from the hook's `cwd` (every
// Codex hook event carries it), falling back to the hook process's own cwd —
// hooks run in the project root, so this is the same directory. Returns
// undefined when nothing could be derived, so callers keep passing the
// optional metadata through unchanged. Per-hook fields (filePath, toolName, …)
// are layered on by the caller.
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
// all. A scoped attachment is meant to compare it against the repositories it
// covers, and to keep an event with no key on this machine; that check is not
// part of this change.
//
// WHICH DIRECTORY. An event that names a file (the `filePath` the caller stamps
// as metadata.filePath; today post-tool-use stamps one from
// `tool_input.file_path`) is keyed by that file's checkout, so a session that
// reads from a second checkout keys that read where the file lives. That key
// never falls back to the cwd: a file outside any checkout, or in one with no
// remote, gets no key at all.
//
// A RELATIVE file path names a location too, read against the event's cwd: it is
// resolved against an absolute cwd and keyed as an absolute one is, so a `..`
// that leaves the checkout the session is in lands in the checkout it really
// reaches, or in none. The cwd is the payload's own, else the hook process's. A
// cwd that is not absolute gives no key, because the path would then be read
// from the hook's own directory, which the session does not choose.
//
// Every other event (no file, or an empty path) is keyed from the directory
// baseMetadata reads, fallback included. SessionStart keys the session root
// from that directory too (session-start.ts resolves `cwd ?? process.cwd()` the
// same way), so a path-less event and its root agree by construction. An
// apply_patch names its files inside the patch body, which is not parsed here,
// so the hooks pass it no key at all rather than calling this (see
// pre-tool-use.ts and post-tool-use.ts).
//
// The path is normalised first. The walk climbs by dirname, so a `..` segment
// left in place would climb back into the directory it left and find that
// checkout's `.git` for a file that is not in it.
//
// COST. A path-less event pays nothing extra: baseMetadata has just walked the
// same directory, and the resolver is memoised per directory. A file's
// directory is one more walk, memoised the same way. It is not skipped for a
// file under the cwd's checkout, because a nested clone or submodule there is
// its own checkout with its own key.
//
// TOTAL. `process.cwd()` throws when the working directory has been deleted, and
// a throw here would reach the hook's outer catch and cost the capture itself.
// A key that cannot be resolved is simply absent: fail closed toward the
// server, never open toward the harness.
//
// The key rides BESIDE the event (`CaptureInput.scopeKey`), never inside
// EventMetadata, because that is a published wire shape and this attribute is
// local. metadata.repo stays the cwd's slug either way.
export function captureScopeKey(
  input: Record<string, unknown>,
  filePath?: string,
): string | undefined {
  try {
    if (filePath === undefined || filePath === '') {
      return resolveRepoAttribution(getString(input, 'cwd') ?? process.cwd()).scopeKey;
    }
    if (isAbsolute(filePath)) return resolveRepoAttribution(dirname(normalize(filePath))).scopeKey;
    const cwd = getString(input, 'cwd') ?? process.cwd();
    if (!isAbsolute(cwd)) return undefined;
    return resolveRepoAttribution(dirname(resolvePath(cwd, filePath))).scopeKey;
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
// so the silence Codex reads as "no opinion" is preserved exactly.
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
