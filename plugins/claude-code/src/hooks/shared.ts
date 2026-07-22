// Claude Code stdio helpers — the only tool-specific glue the adapter keeps.
// Detection, policy, and persistence live in @akasecurity/plugin-sdk; these
// just move bytes between Claude Code and the runtime.

import { resolveRepo } from '@akasecurity/plugin-sdk';
import type { EventMetadata } from '@akasecurity/schema';

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

// Hook output protocol: write one JSON object to stdout and exit 0.
// Writing nothing and exiting 0 means "no opinion" (allow).
//
// The flush must be awaited: hook entries call process.exit(0) right after
// main(), and exit does not wait for pending pipe writes — anything past the
// ~64KB pipe buffer is dropped, Claude Code sees invalid JSON, and the
// original (possibly secret-bearing) payload passes through untouched.
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
export function baseMetadata(input: Record<string, unknown>): EventMetadata | undefined {
  const metadata: EventMetadata = {};
  const sessionId = getString(input, 'session_id');
  if (sessionId) metadata.sessionId = sessionId;
  const repo = resolveRepo(getString(input, 'cwd') ?? process.cwd());
  if (repo) metadata.repo = repo;
  return Object.keys(metadata).length > 0 ? metadata : undefined;
}
