import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { denyPointerMessage } from '../../src/hooks/pre-tool-use-decision.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
// test/hooks -> plugins/codex
const PLUGIN_ROOT = join(HERE, '..', '..');
// The built entry (built before tests run — turbo's test task depends on
// build). Driving it proves the emit ORDER, not just the exported decision.
const HOOK_SCRIPT = join(PLUGIN_ROOT, 'scripts', 'pre-tool-use.js');

interface HookRun {
  stdout: string;
  stderr: string;
  status: number;
}

// Drive the real built hook against a throwaway ~/.aka home, feeding a Codex
// PreToolUse payload on stdin. process.execPath is an absolute node path, so
// the child needs no host PATH and inherits no ambient environment.
function runHook(home: string, payload: unknown): HookRun {
  try {
    const stdout = execFileSync(process.execPath, [HOOK_SCRIPT], {
      env: { HOME: home, USERPROFILE: home },
      input: JSON.stringify(payload),
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
    });
    return { stdout, stderr: '', status: 0 };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; status?: number };
    return { stdout: e.stdout ?? '', stderr: e.stderr ?? '', status: e.status ?? 1 };
  }
}

// A shape-valid vault pointer, never a minted one: 'secret' is a real
// DetectionCategory and the three base32 segments carry the pinned widths
// (2-char key version, 26-char pointer id, 16-char tag), so it matches
// POINTER_TOKEN_PATTERN without any vault row existing anywhere.
const POINTER = `[[aka:secret:AA.${'A'.repeat(26)}.${'A'.repeat(16)}]]`;

// Replace the store the hook reads with unreadable bytes: not the
// "SQLite format 3\0" header, so the first PRAGMA on open fails SQLITE_NOTADB.
// The pointer deny below must fire anyway — it is decided BEFORE the store is
// opened — while the secret scan cannot run and must fail open.
function corruptStore(home: string): void {
  const dataDir = join(home, '.aka', 'data');
  mkdirSync(dataDir, { recursive: true });
  writeFileSync(join(dataDir, 'aka.db'), 'AKA corrupt-store fixture — not a database\n'.repeat(64));
}

function submitBash(home: string, command: string): HookRun {
  return runHook(home, {
    tool_name: 'Bash',
    tool_input: { command },
    session_id: 'sess-pointer-deny',
    cwd: '/tmp',
    hook_event_name: 'PreToolUse',
  });
}

describe('pre-tool-use built hook — the pointer deny precedes the store open', () => {
  it('denies a Bash command carrying a pointer even when the store cannot open', () => {
    const home = mkdtempSync(join(tmpdir(), 'aka-codex-ptu-pointer-'));
    try {
      corruptStore(home);
      const run = submitBash(home, `echo ${POINTER}`);
      expect(run.status).toBe(0);
      const payload = JSON.parse(run.stdout) as {
        hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string };
      };
      expect(payload.hookSpecificOutput?.permissionDecision).toBe('deny');
      expect(payload.hookSpecificOutput?.permissionDecisionReason).toBe(denyPointerMessage('Bash'));
      // A deny that depended on the store would have degraded to the
      // store-unavailable warning instead — its absence pins the ordering.
      expect(run.stdout).not.toContain('OFF for this session');
    } finally {
      removeTree(home);
    }
  });

  it('stays fail-open on a clean command over the same corrupt store — never a deny', () => {
    const home = mkdtempSync(join(tmpdir(), 'aka-codex-ptu-failopen-'));
    try {
      corruptStore(home);
      const run = submitBash(home, 'echo hello');
      expect(run.status).toBe(0);
      expect(run.stdout).not.toContain('"permissionDecision":"deny"');
      expect(run.stdout).not.toContain('"decision":"block"');
    } finally {
      removeTree(home);
    }
  });
});
