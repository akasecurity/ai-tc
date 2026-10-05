/**
 * Every Claude Code capture site stamps the scope key of the checkout it ran
 * in, driven through the REAL built hooks against a throwaway store. The
 * property lives at the CALL SITE. A hook entry runs main() on import and can
 * never be imported by a test, so a capture that forgot to pass `scopeKey` is
 * visible only in the row it wrote.
 *
 * It is silent when it goes wrong. The key never leaves the machine: the local
 * writer stores it in `attributes.scope_key` (read back here through the
 * `scope_key` column) and every forward path strips it. So standalone mode
 * cannot tell a missing key from a present one, and a scoped attachment is meant
 * to keep an event with no key local, with nothing to say why.
 *
 * A capture that names an absolute file is keyed by THAT file's checkout, not
 * by the session's cwd. That too is decided at the call site (it must hand its
 * file path to captureScopeKey), so the file cases below drive the two sites
 * that name a file, Write before it runs and Read after, with the session in
 * one checkout and the file in another.
 *
 * A relative file is read against the session cwd, so a `..` that leaves the
 * session's checkout is keyed where it lands.
 *
 * A Grep names no file but the root it searched, and its output is what the
 * response site records. It is keyed by that root's checkout (a relative `path`
 * is read against the session cwd), and by the session cwd when it names none;
 * the last describe pins them.
 *
 * The secret comes from a bundled rule's own `examples`, so no secret-shaped
 * literal lives in this file. It is needed because the tool_use and response
 * sites persist `with-findings`, and without a finding they record no row at
 * all.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import { runHook, tempHomeEnv, withTempHome } from '../helpers/run-hook.ts';

const SESSION_ID = 'scope-key-e2e-session';
const WORK_REMOTE = 'git@GitHub.com:acme/work-repo.git';
// Scheme, userinfo and `.git` dropped and the host lowercased; path case kept.
const WORK_KEY = 'github.com/acme/work-repo';
// A second checkout the session is not in, for the file cases.
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

// Monitor records every finding and enforces none, so each site writes its row
// and the run stays an ordinary allow.
function seedMonitor(home: string): void {
  const db = openLocalDatabase(join(home, '.aka', 'data'));
  try {
    db.installedPacks.recordInventory(bundledDetections());
    db.installedPacks.setPolicy(SECRET_PACK.namespace, SECRET_PACK.packId, 'monitor');
  } finally {
    db.close();
  }
}

// A checkout at `home/<name>` whose git config names `remote` as origin, or no
// remote at all. The resolver reads files and never spawns git, so a config
// file is the whole fixture.
function checkout(home: string, remote: string | undefined, name = 'checkout'): string {
  const dir = join(home, name);
  mkdirSync(join(dir, '.git'), { recursive: true });
  writeFileSync(
    join(dir, '.git', 'config'),
    remote === undefined ? '[core]\n\tbare = false\n' : `[remote "origin"]\n\turl = ${remote}\n`,
  );
  return dir;
}

// `runHook` layers its env over the host's, so an inherited NODE_OPTIONS would
// put Node's own diagnostics in the stderr these assertions print. Blank it.
function hookEnv(home: string): Record<string, string> {
  return { ...tempHomeEnv(home), NODE_OPTIONS: '' };
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

// The file cases read `repo` too. The slug is wire metadata, so it stays the
// session's whichever checkout keyed the row.
interface FileCapturedRow extends CapturedRow {
  repo: string | null;
}

function fileCapturedRows(home: string): FileCapturedRow[] {
  const db = new DatabaseSync(join(home, '.aka', 'data', 'aka.db'), { readOnly: true });
  try {
    return db
      .prepare(
        `SELECT event_type AS kind, scope_key AS scopeKey, repo FROM audit_events
         WHERE event_type IN ('prompt', 'response', 'tool_use', 'code_change')`,
      )
      .all() as unknown as FileCapturedRow[];
  } finally {
    db.close();
  }
}

// Every row carries `expected`, and there is at least one. The count is the
// positive control: with no row, the key assertion would pass vacuously.
function expectEvery<T extends CapturedRow>(rows: readonly T[], expected: T): void {
  expect(rows.length, `no ${expected.kind} row was recorded`).toBeGreaterThan(0);
  expect(rows).toEqual(rows.map(() => expected));
}

function expectEveryCapture(home: string, expected: CapturedRow): void {
  expectEvery(capturedRows(home), expected);
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

describe('every Claude Code capture site stamps the key of the checkout it ran in', () => {
  for (const site of CAPTURE_SITES) {
    it(`${site.hook} → its ${site.kind} row carries the canonical repo key`, () => {
      withTempHome((home) => {
        seedMonitor(home);
        const cwd = checkout(home, WORK_REMOTE);
        const run = runHook(site.hook, JSON.stringify(site.payload(cwd)), { env: hookEnv(home) });
        expect(run.status, run.stderr).toBe(0);
        expectEveryCapture(home, { kind: site.kind, scopeKey: WORK_KEY });
      }, `aka-scope-key-${site.hook}-`);
    });
  }

  it('a checkout with no remote stamps no key, and the capture is still recorded', () => {
    withTempHome((home) => {
      seedMonitor(home);
      const cwd = checkout(home, undefined);
      const run = runHook(PROMPT_SITE.hook, JSON.stringify(PROMPT_SITE.payload(cwd)), {
        env: hookEnv(home),
      });
      expect(run.status, run.stderr).toBe(0);
      expectEveryCapture(home, { kind: 'prompt', scopeKey: null });
    }, 'aka-scope-key-remoteless-');
  });
});

interface FileSite {
  readonly hook: string;
  readonly kind: 'code_change' | 'response';
  readonly payload: (cwd: string, file: string) => Record<string, unknown>;
}

const WRITE_SITE: FileSite = {
  hook: 'pre-tool-use',
  kind: 'code_change',
  payload: (cwd, file) => ({
    tool_name: 'Write',
    tool_input: { file_path: file, content: `TWILIO_KEY=${SECRET}\n` },
    session_id: SESSION_ID,
    cwd,
    hook_event_name: 'PreToolUse',
  }),
};

const FILE_SITES: readonly FileSite[] = [
  WRITE_SITE,
  {
    hook: 'post-tool-use',
    kind: 'response',
    payload: (cwd, file) => ({
      tool_name: 'Read',
      tool_input: { file_path: file },
      tool_response: { type: 'text', file: { filePath: file, content: `TWILIO_KEY=${SECRET}\n` } },
      session_id: SESSION_ID,
      cwd,
      hook_event_name: 'PostToolUse',
    }),
  },
];

describe('a capture that names an absolute file is keyed by the checkout of that file', () => {
  for (const site of FILE_SITES) {
    it(`${site.hook} → a ${site.kind} row for a file in a second checkout carries its key`, () => {
      withTempHome((home) => {
        seedMonitor(home);
        const cwd = checkout(home, WORK_REMOTE);
        const personal = checkout(home, PERSONAL_REMOTE, 'personal');
        const payload = site.payload(cwd, join(personal, 'notes.md'));
        const run = runHook(site.hook, JSON.stringify(payload), { env: hookEnv(home) });
        expect(run.status, run.stderr).toBe(0);
        // Keyed by the file; the slug stays the session's.
        expectEvery(fileCapturedRows(home), {
          kind: site.kind,
          scopeKey: PERSONAL_KEY,
          repo: 'work-repo',
        });
      }, `aka-scope-key-file-${site.hook}-`);
    });
  }

  it('a file outside any checkout stamps no key, not the key of the session cwd', () => {
    withTempHome((home) => {
      seedMonitor(home);
      const cwd = checkout(home, WORK_REMOTE);
      const loose = join(home, 'loose');
      mkdirSync(loose, { recursive: true });
      const payload = WRITE_SITE.payload(cwd, join(loose, 'notes.md'));
      const run = runHook(WRITE_SITE.hook, JSON.stringify(payload), { env: hookEnv(home) });
      expect(run.status, run.stderr).toBe(0);
      expectEvery(fileCapturedRows(home), {
        kind: 'code_change',
        scopeKey: null,
        repo: 'work-repo',
      });
    }, 'aka-scope-key-file-outside-');
  });
});

describe('a capture that names a relative file is keyed by where the file resolves', () => {
  it('a Write into a sibling checkout, spelled relative to the cwd, carries that checkout key', () => {
    withTempHome((home) => {
      seedMonitor(home);
      const cwd = checkout(home, WORK_REMOTE);
      checkout(home, PERSONAL_REMOTE, 'personal');
      const payload = WRITE_SITE.payload(cwd, join('..', 'personal', 'notes.md'));
      const run = runHook(WRITE_SITE.hook, JSON.stringify(payload), { env: hookEnv(home) });
      expect(run.status, run.stderr).toBe(0);
      expectEvery(fileCapturedRows(home), {
        kind: 'code_change',
        scopeKey: PERSONAL_KEY,
        repo: 'work-repo',
      });
    }, 'aka-scope-key-relative-sibling-');
  });

  it('a Write that escapes into no checkout stamps no key, not the key of the session cwd', () => {
    withTempHome((home) => {
      seedMonitor(home);
      const cwd = checkout(home, WORK_REMOTE);
      mkdirSync(join(home, 'loose'), { recursive: true });
      const payload = WRITE_SITE.payload(cwd, join('..', 'loose', 'notes.md'));
      const run = runHook(WRITE_SITE.hook, JSON.stringify(payload), { env: hookEnv(home) });
      expect(run.status, run.stderr).toBe(0);
      expectEvery(fileCapturedRows(home), {
        kind: 'code_change',
        scopeKey: null,
        repo: 'work-repo',
      });
    }, 'aka-scope-key-relative-outside-');
  });

  it('a relative path inside the cwd checkout keeps the checkout key', () => {
    withTempHome((home) => {
      seedMonitor(home);
      const cwd = checkout(home, WORK_REMOTE);
      const payload = WRITE_SITE.payload(cwd, join('src', 'notes.md'));
      const run = runHook(WRITE_SITE.hook, JSON.stringify(payload), { env: hookEnv(home) });
      expect(run.status, run.stderr).toBe(0);
      expectEvery(fileCapturedRows(home), {
        kind: 'code_change',
        scopeKey: WORK_KEY,
        repo: 'work-repo',
      });
    }, 'aka-scope-key-relative-inside-');
  });
});

describe('a Grep capture is keyed by the search root it names, else by the session cwd', () => {
  // Grep's `path` is the root it searches: a directory or one file. Its output
  // is what the response site records, so the key follows the root. The root
  // that is another checkout's TOP LEVEL is the case a file-style walk, from
  // the root's parent, would miss.
  function grepPayload(cwd: string, toolInput: Record<string, unknown>): Record<string, unknown> {
    return {
      tool_name: 'Grep',
      tool_input: { pattern: 'TWILIO', output_mode: 'content', ...toolInput },
      tool_response: {
        mode: 'content',
        numFiles: 0,
        filenames: [],
        content: `notes.md:1:TWILIO_KEY=${SECRET}`,
        numLines: 1,
      },
      session_id: SESSION_ID,
      cwd,
      hook_event_name: 'PostToolUse',
    };
  }

  it.each([
    [
      'an absolute path that is the top level of another checkout',
      (home: string) => ({ path: checkout(home, PERSONAL_REMOTE, 'personal') }),
      PERSONAL_KEY,
    ],
    [
      'an absolute path inside another checkout',
      (home: string) => {
        const sub = join(checkout(home, PERSONAL_REMOTE, 'personal'), 'src');
        mkdirSync(sub, { recursive: true });
        return { path: sub };
      },
      PERSONAL_KEY,
    ],
    [
      'an absolute path outside any checkout',
      (home: string) => {
        const loose = join(home, 'loose');
        mkdirSync(loose, { recursive: true });
        return { path: loose };
      },
      null,
    ],
    ['no path', () => ({}), WORK_KEY],
    ['a relative path inside the cwd checkout', () => ({ path: 'src' }), WORK_KEY],
    [
      'a relative path that escapes into another checkout',
      (home: string) => {
        checkout(home, PERSONAL_REMOTE, 'personal');
        return { path: join('..', 'personal') };
      },
      PERSONAL_KEY,
    ],
    [
      'a relative path that escapes into no checkout',
      (home: string) => {
        mkdirSync(join(home, 'loose'), { recursive: true });
        return { path: join('..', 'loose') };
      },
      null,
    ],
  ])('%s', (_label, toolInput, expectedKey) => {
    withTempHome((home) => {
      seedMonitor(home);
      const cwd = checkout(home, WORK_REMOTE);
      const payload = grepPayload(cwd, toolInput(home));
      const run = runHook('post-tool-use', JSON.stringify(payload), { env: hookEnv(home) });
      expect(run.status, run.stderr).toBe(0);
      // The slug stays the session's whichever root keyed the row.
      expectEvery(fileCapturedRows(home), {
        kind: 'response',
        scopeKey: expectedKey,
        repo: 'work-repo',
      });
    }, 'aka-scope-key-grep-');
  });
});
