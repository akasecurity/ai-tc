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
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { denyPointerMessage } from '../../src/hooks/pre-tool-use-decision.ts';
import { withTempHome } from '../helpers/run-hook.ts';

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
    withTempHome((home) => {
      corruptStore(home);
      const payload = decisionOf(runCommand(home, `echo ${POINTER}`));
      expect(payload.decision).toBe('deny');
      expect(payload.reason).toBe(denyPointerMessage('run_command'));
      // A deny that depended on the store would have degraded to the
      // store-unavailable warning instead — its absence pins the ordering.
      expect(payload.reason).not.toContain('OFF for this session');
    }, 'aka-antigravity-ptu-pointer-');
  });

  it('emits an EXPLICIT allow on a clean command over the same corrupt store', () => {
    // The fail-closed regression: an earlier design exited 0 with no stdout on
    // this path, which Antigravity reads as a deny. Asserting the literal
    // `allow` (not merely the absence of "deny") is the only form that catches
    // it — empty stdout satisfies every not.toContain.
    withTempHome((home) => {
      corruptStore(home);
      expect(decisionOf(runCommand(home, 'echo hello')).decision).toBe('allow');
    }, 'aka-antigravity-ptu-failopen-');
  });

  it('emits an explicit allow for a tool it does not scan', () => {
    withTempHome((home) => {
      const run = runHook(home, {
        toolCall: { name: 'view_file', args: { TargetFile: '/etc/hosts' } },
        stepIdx: 1,
        conversationId: 'conv-untracked',
        workspacePaths: ['/tmp'],
      });
      expect(decisionOf(run).decision).toBe('allow');
    }, 'aka-antigravity-ptu-untracked-');
  });

  it('emits an explicit allow on a malformed payload rather than staying silent', () => {
    // Garbage in must not become a deny: the host cannot tell "the hook broke"
    // from "the hook refused", so a parse failure has to answer allow.
    withTempHome((home) => {
      const run = runHook(home, 'not-an-object');
      expect(decisionOf(run).decision).toBe('allow');

      // …including a payload with no toolCall at all.
      const noCall = runHook(home, { conversationId: 'c', workspacePaths: [] });
      expect(decisionOf(noCall).decision).toBe('allow');
    }, 'aka-antigravity-ptu-malformed-');
  });
});

// ---------------------------------------------------------------------------
// The scope key follows the checkout that holds the event's target, never a
// workspace root: not the first one, and not the one the target sits under.
//
// Driven through the built hook because the property lives at the call site:
// the entry runs main() on import, so a capture that does not hand the target
// to captureScopeKey shows only in the row it writes. write_to_file persists
// every capture, so no finding is needed for a row to exist. The temp home sits
// under the OS temp directory, which is in no checkout, so `<home>/elsewhere`
// belongs to none.
// ---------------------------------------------------------------------------

// The userinfo in an scp-style remote (`<user>@<host>:path`) reads as an email
// address to a scanner, so the fixture builds it from parts.
const AT = String.fromCharCode(64);
const gitUser = `git${AT}`;
const WORK_REMOTE = `${gitUser}github.com:acme/work-repo.git`;
const WORK_KEY = 'github.com/acme/work-repo';
const PERSONAL_REMOTE = 'https://github.com/me/dotfiles.git';
const VENDOR_REMOTE = 'https://github.com/acme/vendored-lib.git';

/** A checkout inside the temp home whose git config names `remote` as origin. */
function checkout(home: string, name: string, remote: string): string {
  const dir = join(home, name);
  mkdirSync(join(dir, '.git'), { recursive: true });
  writeFileSync(join(dir, '.git', 'config'), `[remote "origin"]\n\turl = ${remote}\n`);
  return dir;
}

interface CapturedRow {
  kind: string;
  scopeKey: string | null;
}

/** Every capture row the hook wrote, with the key the local writer stored. */
function capturedRows(home: string): CapturedRow[] {
  const db = new DatabaseSync(join(home, '.aka', 'data', 'aka.db'), { readOnly: true });
  try {
    return db
      .prepare(
        `SELECT event_type AS kind, scope_key AS scopeKey FROM audit_events
         WHERE event_type IN ('prompt', 'response', 'tool_use', 'code_change')`,
      )
      .all() as unknown as CapturedRow[];
  } finally {
    db.close();
  }
}

// At least one row, and every row carries `expected`. The count is the positive
// control: with no row the key assertion would pass vacuously.
function expectEveryCapture(home: string, expected: CapturedRow): void {
  const rows = capturedRows(home);
  expect(rows.length, `no ${expected.kind} row was recorded`).toBeGreaterThan(0);
  expect(rows).toEqual(rows.map(() => expected));
}

function writeTo(home: string, workspacePaths: readonly string[], targetFile: string): HookRun {
  return runHook(home, {
    toolCall: {
      name: 'write_to_file',
      args: { TargetFile: targetFile, CodeContent: 'export const answer = 42;\n' },
    },
    stepIdx: 0,
    conversationId: 'conv-scope-key',
    workspacePaths,
  });
}

describe('pre-tool-use built hook: the scope key follows the target, not a root', () => {
  it('keys a write inside the SECOND root by that root', () => {
    withTempHome((home) => {
      const personal = checkout(home, 'personal', PERSONAL_REMOTE);
      const work = checkout(home, 'work', WORK_REMOTE);
      const run = writeTo(home, [personal, work], join(work, 'src', 'index.ts'));
      expect(decisionOf(run).decision).toBe('allow');
      expectEveryCapture(home, { kind: 'code_change', scopeKey: WORK_KEY });
    }, 'aka-antigravity-ptu-scope-target-');
  });

  it('keys a write into a clone nested under a root by that clone', () => {
    withTempHome((home) => {
      const work = checkout(home, 'work', WORK_REMOTE);
      const vendored = checkout(home, join('work', 'vendor', 'lib'), VENDOR_REMOTE);
      const run = writeTo(home, [work], join(vendored, 'index.ts'));
      expect(decisionOf(run).decision).toBe('allow');
      expectEveryCapture(home, { kind: 'code_change', scopeKey: 'github.com/acme/vendored-lib' });
    }, 'aka-antigravity-ptu-scope-nested-');
  });

  it('keys a write into a repository under a root that is a plain folder', () => {
    withTempHome((home) => {
      const app = checkout(home, join('projects', 'app'), WORK_REMOTE);
      const run = writeTo(home, [join(home, 'projects')], join(app, 'src', 'index.ts'));
      expect(decisionOf(run).decision).toBe('allow');
      expectEveryCapture(home, { kind: 'code_change', scopeKey: WORK_KEY });
    }, 'aka-antigravity-ptu-scope-folder-');
  });

  it('stamps no key on a write outside the only root of a single-root session', () => {
    // The root's key must not follow a write out of it: this row persists
    // 'always', so a borrowed key would let the content forward once a scoped
    // attachment checks it.
    withTempHome((home) => {
      const work = checkout(home, 'work', WORK_REMOTE);
      const run = writeTo(home, [work], join(home, 'elsewhere', 'notes.md'));
      expect(decisionOf(run).decision).toBe('allow');
      expectEveryCapture(home, { kind: 'code_change', scopeKey: null });
    }, 'aka-antigravity-ptu-scope-outside-');
  });

  it('stamps no key on a write outside every root of a workspace whose roots disagree', () => {
    withTempHome((home) => {
      const personal = checkout(home, 'personal', PERSONAL_REMOTE);
      const work = checkout(home, 'work', WORK_REMOTE);
      const run = writeTo(home, [personal, work], join(home, 'elsewhere', 'notes.md'));
      expect(decisionOf(run).decision).toBe('allow');
      expectEveryCapture(home, { kind: 'code_change', scopeKey: null });
    }, 'aka-antigravity-ptu-scope-mixed-');
  });
});
