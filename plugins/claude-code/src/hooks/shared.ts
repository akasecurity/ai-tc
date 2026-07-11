// Claude Code stdio helpers — the only tool-specific glue the adapter keeps.
// Detection, policy, and persistence live in @akasecurity/plugin-sdk; these
// just move bytes between Claude Code and the runtime.

import { resolveRepo } from '@akasecurity/plugin-sdk';
import type { EventMetadata } from '@akasecurity/schema';

export async function readStdin(): Promise<string> {
  return new Promise<string>((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk: string) => {
      data += chunk;
    });
    process.stdin.on('end', () => {
      resolve(data);
    });
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
    process.stdout.write(JSON.stringify(output), () => {
      resolve();
    });
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
