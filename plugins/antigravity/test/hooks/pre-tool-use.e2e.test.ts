// Drives the REAL built pre-tool-use hook as a child process.
//
// The headline invariant here is Antigravity-specific and is the reason this
// suite exists at all: THE HOST FAILS CLOSED. Antigravity reads a non-zero exit
// — or stdout that its schema rejects, including empty stdout — as a `deny` on
// the tool call, and surfaces it as "Tool call denied by <hook>". So on this
// host "fail-open" cannot mean "say nothing and exit 0" the way it does for
// Claude Code and Codex: every path must print an explicit
// {"decision":"allow"}. A regression that merely stopped printing would be
// invisible to a unit test of the decision module and would block every tool
// call the user makes.
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { denyPointerMessage } from '../../src/hooks/pre-tool-use-decision.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
// test/hooks -> plugins/antigravity
const PLUGIN_ROOT = join(HERE, '..', '..');
// The built entry (built before tests run — turbo's test task depends on
// build). Driving it proves the emit ORDER, not just the exported decision.
const HOOK_SCRIPT = join(PLUGIN_ROOT, 'scripts', 'pre-tool-use.js');

interface HookRun {
  stdout: string;
  stderr: string;
  status: number;
}

// Drive the real built hook against a throwaway ~/.aka home, feeding an
// Antigravity PreToolUse payload on stdin. process.execPath is an absolute node
// path, so the child needs no host PATH and inherits no ambient environment.
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

/**
 * Parse what the host would parse, and assert the two things the host requires
 * of EVERY run: exit 0, and stdout that is a JSON object naming a decision.
 * Empty stdout fails here rather than silently satisfying a `not.toContain`.
 */
function decisionOf(run: HookRun): { decision?: string; reason?: string } {
  expect(run.status).toBe(0);
  expect(run.stdout).not.toBe('');
  const payload = JSON.parse(run.stdout) as { decision?: string; reason?: string };
  expect(payload.decision).toBeDefined();
  return payload;
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

function runCommand(home: string, commandLine: string): HookRun {
  return runHook(home, {
    toolCall: { name: 'run_command', args: { CommandLine: commandLine } },
    stepIdx: 0,
    conversationId: 'conv-pointer-deny',
    workspacePaths: ['/tmp'],
    transcriptPath: '/tmp/does-not-exist/transcript.jsonl',
    artifactDirectoryPath: '/tmp/does-not-exist/artifacts',
  });
}

describe('pre-tool-use built hook — the pointer deny precedes the store open', () => {
  it('denies a run_command carrying a pointer even when the store cannot open', () => {
    const home = mkdtempSync(join(tmpdir(), 'aka-antigravity-ptu-pointer-'));
    try {
      corruptStore(home);
      const payload = decisionOf(runCommand(home, `echo ${POINTER}`));
      expect(payload.decision).toBe('deny');
      expect(payload.reason).toBe(denyPointerMessage('run_command'));
      // A deny that depended on the store would have degraded to the
      // store-unavailable warning instead — its absence pins the ordering.
      expect(payload.reason).not.toContain('OFF for this session');
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });

  it('emits an EXPLICIT allow on a clean command over the same corrupt store', () => {
    // The fail-closed regression: an earlier design exited 0 with no stdout on
    // this path, which Antigravity reads as a deny. Asserting the literal
    // `allow` (not merely the absence of "deny") is the only form that catches
    // it — empty stdout satisfies every not.toContain.
    const home = mkdtempSync(join(tmpdir(), 'aka-antigravity-ptu-failopen-'));
    try {
      corruptStore(home);
      expect(decisionOf(runCommand(home, 'echo hello')).decision).toBe('allow');
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });

  it('emits an explicit allow for a tool it does not scan', () => {
    const home = mkdtempSync(join(tmpdir(), 'aka-antigravity-ptu-untracked-'));
    try {
      const run = runHook(home, {
        toolCall: { name: 'view_file', args: { TargetFile: '/etc/hosts' } },
        stepIdx: 1,
        conversationId: 'conv-untracked',
        workspacePaths: ['/tmp'],
      });
      expect(decisionOf(run).decision).toBe('allow');
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });

  it('emits an explicit allow on a malformed payload rather than staying silent', () => {
    // Garbage in must not become a deny: the host cannot tell "the hook broke"
    // from "the hook refused", so a parse failure has to answer allow.
    const home = mkdtempSync(join(tmpdir(), 'aka-antigravity-ptu-malformed-'));
    try {
      const run = runHook(home, 'not-an-object');
      expect(decisionOf(run).decision).toBe('allow');

      // …including a payload with no toolCall at all.
      const noCall = runHook(home, { conversationId: 'c', workspacePaths: [] });
      expect(decisionOf(noCall).decision).toBe('allow');
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });
});
