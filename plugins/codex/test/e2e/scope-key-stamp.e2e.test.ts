/**
 * Every Codex capture site stamps the scope key of the checkout it ran in,
 * driven through the REAL built hooks against a throwaway store. A hook entry
 * runs main() on import and can never be imported by a test, so a capture that
 * forgot to pass `scopeKey` is visible only in the row it wrote. The key never
 * leaves the machine, so nothing else would notice.
 *
 * A capture that names a file is keyed by that file's checkout; a relative path
 * is read against the session cwd, so a `..` that leaves the session's checkout
 * is keyed where it lands. On Codex only post-tool-use stamps a file
 * (`tool_input.file_path`), and the file cases pin that its call site hands that
 * path to captureScopeKey.
 *
 * An apply_patch, at either hook, gets NO key: it names its files inside the
 * patch body, which the hooks do not parse, and the cwd's key could name a
 * checkout it never wrote. The two apply_patch cases pin that.
 *
 * The secret comes from a bundled rule's own `examples`. It is needed because
 * the tool_use and response sites persist `with-findings` and record nothing
 * without a finding.
 */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import { runHook, tempHomeEnv, withTempHome } from '../helpers/run-hook.ts';

const SESSION_ID = 'scope-key-e2e-session';
const WORK_REMOTE = 'git@GitHub.com:acme/work-repo.git';
const WORK_KEY = 'github.com/acme/work-repo';
// A second checkout the session is not in, for the file case.
const PERSONAL_REMOTE = 'https://github.com/someone/dotfiles.git';
const PERSONAL_KEY = 'github.com/someone/dotfiles';
const RULE_ID = 'secrets/twilio-key';

function secretFixture(): { pack: ReturnType<typeof bundledDetections>[number]; example: string } {
  const pack = bundledDetections().find((p) => p.rules.some((r) => r.id === RULE_ID));
  const example = pack?.rules.find((r) => r.id === RULE_ID)?.examples?.[0];
  if (pack === undefined || example === undefined) {
    throw new Error(`bundled rule ${RULE_ID} is missing from the pack registry or has no example`);
  }
  return { pack, example };
}

const { pack: SECRET_PACK, example: SECRET } = secretFixture();

// The payloads a live Codex sent for an apply_patch call (see
// test/fixtures/hooks/README.md). The apply_patch cases below keep their shape
// and swap only the patch text, the result text, the session and the cwd.
interface RecordedApplyPatch extends Record<string, unknown> {
  tool_input: { command: string };
}

function recorded(file: string): RecordedApplyPatch {
  return JSON.parse(
    readFileSync(new URL(`../fixtures/hooks/${file}`, import.meta.url), 'utf8'),
  ) as RecordedApplyPatch;
}

const RECORDED_PATCH_PRE = recorded('apply_patch.pre-tool-use.json');
const RECORDED_PATCH_POST = recorded('apply_patch.post-tool-use.json');
// The absolute path the recorded patch writes, which the cases point elsewhere.
const RECORDED_PATCH_TARGET = '/Users/dev/project/hello.txt';

// Monitor records every finding and enforces none.
function seedMonitor(home: string): void {
  const db = openLocalDatabase(join(home, '.aka', 'data'));
  try {
    db.installedPacks.recordInventory(bundledDetections());
    db.installedPacks.setPolicy(SECRET_PACK.namespace, SECRET_PACK.packId, 'monitor');
  } finally {
    db.close();
  }
}

function checkout(home: string, remote: string | undefined, name = 'checkout'): string {
  const dir = join(home, name);
  mkdirSync(join(dir, '.git'), { recursive: true });
  writeFileSync(
    join(dir, '.git', 'config'),
    remote === undefined ? '[core]\n\tbare = false\n' : `[remote "origin"]\n\turl = ${remote}\n`,
  );
  return dir;
}

interface CapturedRow {
  kind: string;
  scopeKey: string | null;
}

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
// control.
function expectEveryCapture(home: string, expected: CapturedRow): void {
  const rows = capturedRows(home);
  expect(rows.length, `no ${expected.kind} row was recorded`).toBeGreaterThan(0);
  expect(rows).toEqual(rows.map(() => expected));
}

interface CaptureSite {
  readonly hook: string;
  readonly kind: 'prompt' | 'tool_use' | 'response';
  readonly payload: (cwd: string) => Record<string, unknown>;
}

const PROMPT_SITE: CaptureSite = {
  hook: 'user-prompt-submit',
  kind: 'prompt',
  payload: (cwd) => ({
    prompt: `deploy the service using ${SECRET}`,
    session_id: SESSION_ID,
    cwd,
    hook_event_name: 'UserPromptSubmit',
  }),
};

const CAPTURE_SITES: readonly CaptureSite[] = [
  PROMPT_SITE,
  {
    hook: 'pre-tool-use',
    kind: 'tool_use',
    payload: (cwd) => ({
      tool_name: 'Bash',
      tool_input: { command: `export TWILIO_KEY=${SECRET}` },
      session_id: SESSION_ID,
      cwd,
      hook_event_name: 'PreToolUse',
    }),
  },
  {
    hook: 'post-tool-use',
    kind: 'response',
    payload: (cwd) => ({
      tool_name: 'Bash',
      tool_input: { command: 'cat .env' },
      tool_response: { stdout: `TWILIO_KEY=${SECRET}`, stderr: '' },
      session_id: SESSION_ID,
      cwd,
      hook_event_name: 'PostToolUse',
    }),
  },
];

describe('every Codex capture site stamps the key of the checkout it ran in', () => {
  for (const site of CAPTURE_SITES) {
    it(`${site.hook} → its ${site.kind} row carries the canonical repo key`, () => {
      withTempHome((home) => {
        seedMonitor(home);
        const cwd = checkout(home, WORK_REMOTE);
        const run = runHook(site.hook, JSON.stringify(site.payload(cwd)), {
          env: tempHomeEnv(home),
        });
        expect(run.status, run.stderr).toBe(0);
        expectEveryCapture(home, { kind: site.kind, scopeKey: WORK_KEY });
      }, `aka-codex-scope-key-${site.hook}-`);
    });
  }

  it('a checkout with no remote stamps no key, and the capture is still recorded', () => {
    withTempHome((home) => {
      seedMonitor(home);
      const cwd = checkout(home, undefined);
      const run = runHook(PROMPT_SITE.hook, JSON.stringify(PROMPT_SITE.payload(cwd)), {
        env: tempHomeEnv(home),
      });
      expect(run.status, run.stderr).toBe(0);
      expectEveryCapture(home, { kind: 'prompt', scopeKey: null });
    }, 'aka-codex-scope-key-remoteless-');
  });

  it('post-tool-use → a response naming a file in a second checkout carries its key', () => {
    // Codex stamps a file only from `tool_input.file_path`, which none of its
    // built-in tools (Bash, apply_patch, webrun) names. An MCP tool may, and a
    // bare-string response is scanned for ANY tool, so this one stands in.
    withTempHome((home) => {
      seedMonitor(home);
      const cwd = checkout(home, WORK_REMOTE);
      const personal = checkout(home, PERSONAL_REMOTE, 'personal');
      const payload = {
        tool_name: 'mcp__files__read_file',
        tool_input: { file_path: join(personal, 'notes.md') },
        tool_response: `TWILIO_KEY=${SECRET}`,
        session_id: SESSION_ID,
        cwd,
        hook_event_name: 'PostToolUse',
      };
      const run = runHook('post-tool-use', JSON.stringify(payload), { env: tempHomeEnv(home) });
      expect(run.status, run.stderr).toBe(0);
      expectEveryCapture(home, { kind: 'response', scopeKey: PERSONAL_KEY });
    }, 'aka-codex-scope-key-file-');
  });

  // The same MCP-style call, naming its file relative to the session cwd. The
  // cwd's key is not the file's: a `..` leaves the checkout the session is in.
  function relativeRead(cwd: string, filePath: string): Record<string, unknown> {
    return {
      tool_name: 'mcp__files__read_file',
      tool_input: { file_path: filePath },
      tool_response: `TWILIO_KEY=${SECRET}`,
      session_id: SESSION_ID,
      cwd,
      hook_event_name: 'PostToolUse',
    };
  }

  it('post-tool-use → a relative file_path escaping into a second checkout carries its key', () => {
    withTempHome((home) => {
      seedMonitor(home);
      const cwd = checkout(home, WORK_REMOTE);
      checkout(home, PERSONAL_REMOTE, 'personal');
      const payload = relativeRead(cwd, join('..', 'personal', 'notes.md'));
      const run = runHook('post-tool-use', JSON.stringify(payload), { env: tempHomeEnv(home) });
      expect(run.status, run.stderr).toBe(0);
      expectEveryCapture(home, { kind: 'response', scopeKey: PERSONAL_KEY });
    }, 'aka-codex-scope-key-relative-sibling-');
  });

  it('post-tool-use → a relative file_path escaping into no checkout carries no key', () => {
    withTempHome((home) => {
      seedMonitor(home);
      const cwd = checkout(home, WORK_REMOTE);
      mkdirSync(join(home, 'loose'), { recursive: true });
      const payload = relativeRead(cwd, join('..', 'loose', 'notes.md'));
      const run = runHook('post-tool-use', JSON.stringify(payload), { env: tempHomeEnv(home) });
      expect(run.status, run.stderr).toBe(0);
      expectEveryCapture(home, { kind: 'response', scopeKey: null });
    }, 'aka-codex-scope-key-relative-outside-');
  });

  it('post-tool-use → a relative file_path inside the cwd checkout keeps the checkout key', () => {
    withTempHome((home) => {
      seedMonitor(home);
      const cwd = checkout(home, WORK_REMOTE);
      const payload = relativeRead(cwd, join('src', 'notes.md'));
      const run = runHook('post-tool-use', JSON.stringify(payload), { env: tempHomeEnv(home) });
      expect(run.status, run.stderr).toBe(0);
      expectEveryCapture(home, { kind: 'response', scopeKey: WORK_KEY });
    }, 'aka-codex-scope-key-relative-inside-');
  });

  it('pre-tool-use → an apply_patch code_change row carries no key, not the cwd key', () => {
    // An apply_patch is recorded whole (persist 'always') and names its files
    // inside the patch body, which the hook does not parse. The cwd's key could
    // name a checkout the patch never wrote, so it gets none.
    withTempHome((home) => {
      seedMonitor(home);
      const cwd = checkout(home, WORK_REMOTE);
      const personal = checkout(home, PERSONAL_REMOTE, 'personal');
      const payload = {
        ...RECORDED_PATCH_PRE,
        tool_input: {
          ...RECORDED_PATCH_PRE.tool_input,
          command: RECORDED_PATCH_PRE.tool_input.command.replace(
            RECORDED_PATCH_TARGET,
            join(personal, 'notes.md'),
          ),
        },
        session_id: SESSION_ID,
        cwd,
      };
      const run = runHook('pre-tool-use', JSON.stringify(payload), { env: tempHomeEnv(home) });
      expect(run.status, run.stderr).toBe(0);
      expectEveryCapture(home, { kind: 'code_change', scopeKey: null });
    }, 'aka-codex-scope-key-patch-pre-');
  });

  it('post-tool-use → an apply_patch result row carries no key, not the cwd key', () => {
    // The result names the patched paths, not their checkout's key. The secret
    // is there only because this site persists 'with-findings'.
    withTempHome((home) => {
      seedMonitor(home);
      const cwd = checkout(home, WORK_REMOTE);
      const payload = {
        ...RECORDED_PATCH_POST,
        tool_response: `Exit code: 0\nOutput:\nTWILIO_KEY=${SECRET}\n`,
        session_id: SESSION_ID,
        cwd,
      };
      const run = runHook('post-tool-use', JSON.stringify(payload), { env: tempHomeEnv(home) });
      expect(run.status, run.stderr).toBe(0);
      expectEveryCapture(home, { kind: 'response', scopeKey: null });
    }, 'aka-codex-scope-key-patch-post-');
  });
});
