/**
 * The Copilot capture site stamps the scope key of the checkout its payload
 * names, driven through the REAL built pre-tool-use hook against a throwaway
 * store. The entry runs main() on import, so the row it writes is the only
 * place a missing `scopeKey` shows.
 *
 * Copilot is stricter than the other hosts about WHERE the key of a capture
 * that names no file may come from: only a cwd the payload carries, on either
 * dialect, and never the hook process's own. That holds even on the CLI, where
 * the repo slug does fall back to the process cwd. The third case pins the
 * asymmetry from the process side: the hook is spawned INSIDE a keyed checkout
 * with a payload that names no cwd, and the row must carry the slug and no key.
 *
 * A VS Code single-file write is the one capture keyed by a file: the absolute
 * `filePath` it writes, with or without a payload cwd. Without an absolute one
 * it gets no key, never the cwd's, because that field name is unrecorded. The
 * slug stays the cwd's throughout.
 */
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import { withTempHome } from '../helpers/run-hook.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
// test/e2e -> plugins/copilot
const PLUGIN_ROOT = join(HERE, '..', '..');
const SCRIPT = join(PLUGIN_ROOT, 'scripts', 'pre-tool-use.js');
const MANIFEST = join(PLUGIN_ROOT, 'plugin.json');

const WORK_REMOTE = 'git@GitHub.com:acme/work-repo.git';
const WORK_KEY = 'github.com/acme/work-repo';
const PERSONAL_REMOTE = 'https://github.com/someone/dotfiles.git';
const PERSONAL_KEY = 'github.com/someone/dotfiles';
const SESSION_ID = 'c1779e76-9889-419b-ab12-f7bb8a957e15';
const RULE_ID = 'secrets/twilio-key';

function secretFixture(): { namespace: string; packId: string; example: string } {
  // Taken from the rule's own examples: this repository is public, and a
  // credential-shaped literal does not belong in it.
  const pack = bundledDetections().find((p) => p.rules.some((r) => r.id === RULE_ID));
  const example = pack?.rules.find((r) => r.id === RULE_ID)?.examples?.[0];
  if (pack === undefined || example === undefined) {
    throw new Error(`bundled rule ${RULE_ID} is missing from the pack registry or has no example`);
  }
  return { namespace: pack.namespace, packId: pack.packId, example };
}
const FIXTURE = secretFixture();

// Monitor records every finding and enforces none, so the `with-findings`
// tool_use capture writes its row.
function seedMonitor(home: string): void {
  const db = openLocalDatabase(join(home, '.aka', 'data'));
  try {
    db.installedPacks.recordInventory(bundledDetections());
    db.installedPacks.setPolicy(FIXTURE.namespace, FIXTURE.packId, 'monitor');
  } finally {
    db.close();
  }
}

function checkout(home: string, name = 'checkout', remote = WORK_REMOTE): string {
  const dir = join(home, name);
  mkdirSync(join(dir, '.git'), { recursive: true });
  writeFileSync(join(dir, '.git', 'config'), `[remote "origin"]\n\turl = ${remote}\n`);
  return dir;
}

// Spawned with an explicit process cwd, so the no-cwd case can put the hook
// INSIDE a keyed checkout. The env carries the temp home alone.
function runHook(
  event: string,
  home: string,
  payload: unknown,
  processCwd: string,
): { status: number; stderr: string } {
  const result = spawnSync(process.execPath, [SCRIPT, event, MANIFEST], {
    cwd: processCwd,
    env: { HOME: home, USERPROFILE: home },
    input: JSON.stringify(payload),
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  const { status, stderr } = result as unknown as {
    status: number | null;
    stderr: string | null;
  };
  return { status: status ?? 1, stderr: stderr ?? '' };
}

interface CapturedRow {
  kind: string;
  scopeKey: string | null;
  repo: string | null;
}

function capturedRows(home: string): CapturedRow[] {
  const db = new DatabaseSync(join(home, '.aka', 'data', 'aka.db'), { readOnly: true });
  try {
    return db
      .prepare(
        `SELECT event_type AS kind, scope_key AS scopeKey, repo FROM audit_events
         WHERE event_type IN ('prompt', 'response', 'tool_use', 'code_change')`,
      )
      .all() as unknown as CapturedRow[];
  } finally {
    db.close();
  }
}

// At least one row, and every row carries `expected`. The count is the positive
// control.
function expectEveryCapture(home: string, expected: CapturedRow): void {
  const rows = capturedRows(home);
  expect(rows.length, `no ${expected.kind} row was recorded`).toBeGreaterThan(0);
  expect(rows).toEqual(rows.map(() => expected));
}

const command = (): string => `export TWILIO_KEY=${FIXTURE.example}`;

function cliCall(cwd: string | undefined): Record<string, unknown> {
  return {
    sessionId: SESSION_ID,
    timestamp: 1788547866483,
    ...(cwd === undefined ? {} : { cwd }),
    toolName: 'bash',
    toolArgs: { command: command(), description: 'e2e', mode: 'sync', initial_wait: 30 },
  };
}

function vscodeCall(cwd: string): Record<string, unknown> {
  return {
    hook_event_name: 'PreToolUse',
    session_id: SESSION_ID,
    timestamp: 1788547866483,
    cwd,
    tool_name: 'run_in_terminal',
    tool_input: { command: command(), explanation: 'e2e', isBackground: false },
  };
}

// A VS Code writer call. Its content is plain code: a `code_change` is recorded
// with the default persist, so the row is written with no finding at all.
function vscodeWrite(
  cwd: string | undefined,
  toolName: string,
  toolInput: Record<string, unknown>,
): Record<string, unknown> {
  return {
    hook_event_name: 'PreToolUse',
    session_id: SESSION_ID,
    timestamp: 1788547866483,
    ...(cwd === undefined ? {} : { cwd }),
    tool_name: toolName,
    tool_input: toolInput,
  };
}

const CODE = 'export const answer = 42;\n';

describe('pre-tool-use stamps the scope key of the cwd its payload names', () => {
  it('CLI dialect: the tool_use row carries the canonical repo key', () => {
    withTempHome((home) => {
      seedMonitor(home);
      const run = runHook('preToolUse', home, cliCall(checkout(home)), home);
      expect(run.status, run.stderr).toBe(0);
      expectEveryCapture(home, { kind: 'tool_use', scopeKey: WORK_KEY, repo: 'work-repo' });
    }, 'aka-copilot-scope-key-cli-');
  });

  it('VS Code dialect with a declared cwd: keyed the same way', () => {
    withTempHome((home) => {
      seedMonitor(home);
      const run = runHook('PreToolUse', home, vscodeCall(checkout(home)), home);
      expect(run.status, run.stderr).toBe(0);
      expectEveryCapture(home, { kind: 'tool_use', scopeKey: WORK_KEY, repo: 'work-repo' });
    }, 'aka-copilot-scope-key-vscode-');
  });

  it('no payload cwd: no key, though the hook runs inside a keyed checkout', () => {
    withTempHome((home) => {
      seedMonitor(home);
      const run = runHook('preToolUse', home, cliCall(undefined), checkout(home));
      expect(run.status, run.stderr).toBe(0);
      // The slug took the CLI's process-cwd fallback; the key did not.
      expectEveryCapture(home, { kind: 'tool_use', scopeKey: null, repo: 'work-repo' });
    }, 'aka-copilot-scope-key-nocwd-');
  });
});

// A CLI call to the file-write tool this host names. Its patch is recorded whole as
// a `code_change`, and names its files inside its body, which the hook does not read.
function cliPatch(cwd: string): Record<string, unknown> {
  return {
    sessionId: SESSION_ID,
    timestamp: 1788547866483,
    cwd,
    toolName: 'apply_patch',
    toolArgs: { input: `*** Begin Patch\n*** Add File: notes.ts\n+${CODE}\n*** End Patch\n` },
  };
}

describe('a CLI apply_patch is never keyed by the payload cwd', () => {
  it('records its code_change row with no key, though the cwd is a keyed checkout', () => {
    withTempHome((home) => {
      seedMonitor(home);
      const run = runHook('preToolUse', home, cliPatch(checkout(home)), home);
      expect(run.status, run.stderr).toBe(0);
      // The slug is the cwd's; the key is withheld because the patch names its files itself.
      expectEveryCapture(home, { kind: 'code_change', scopeKey: null, repo: 'work-repo' });
    }, 'aka-copilot-scope-key-cli-patch-');
  });
});

describe('a VS Code single-file write is keyed by the file it writes, or not at all', () => {
  it('a write into a second checkout carries that checkout key, not the payload cwd key', () => {
    withTempHome((home) => {
      seedMonitor(home);
      const work = checkout(home);
      const personal = checkout(home, 'personal', PERSONAL_REMOTE);
      const call = vscodeWrite(work, 'create_file', {
        filePath: join(personal, 'notes.ts'),
        content: CODE,
      });
      const run = runHook('PreToolUse', home, call, home);
      expect(run.status, run.stderr).toBe(0);
      // Keyed by the file; the slug stays the cwd's.
      expectEveryCapture(home, { kind: 'code_change', scopeKey: PERSONAL_KEY, repo: 'work-repo' });
    }, 'aka-copilot-scope-key-write-');
  });

  it('a write with no payload cwd is keyed by its file all the same', () => {
    withTempHome((home) => {
      seedMonitor(home);
      const personal = checkout(home, 'personal', PERSONAL_REMOTE);
      const call = vscodeWrite(undefined, 'create_file', {
        filePath: join(personal, 'notes.ts'),
        content: CODE,
      });
      const run = runHook('PreToolUse', home, call, home);
      expect(run.status, run.stderr).toBe(0);
      // VS Code gets no slug without a payload cwd; the file still names a key.
      expectEveryCapture(home, { kind: 'code_change', scopeKey: PERSONAL_KEY, repo: null });
    }, 'aka-copilot-scope-key-write-nocwd-');
  });

  it.each([
    ['no filePath', 'create_file', { content: CODE }],
    [
      'a relative filePath',
      'replace_string_in_file',
      { filePath: 'notes.ts', oldString: 'a', newString: CODE },
    ],
    // The patch names its file in its body, which the hook does not parse.
    [
      'an apply_patch',
      'apply_patch',
      { input: `*** Begin Patch\n*** Add File: notes.ts\n+${CODE}\n*** End Patch\n` },
    ],
  ])('a write with %s gets no key, not the payload cwd key', (_label, toolName, toolInput) => {
    withTempHome((home) => {
      seedMonitor(home);
      const call = vscodeWrite(checkout(home), toolName, toolInput);
      const run = runHook('PreToolUse', home, call, home);
      expect(run.status, run.stderr).toBe(0);
      expectEveryCapture(home, { kind: 'code_change', scopeKey: null, repo: 'work-repo' });
    }, 'aka-copilot-scope-key-write-failclosed-');
  });
});
