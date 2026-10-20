/**
 * The prompt handler, driven in-process against a real temp home.
 *
 * Nothing is mocked but stderr, which is captured rather than replaced in
 * behaviour: the store is a real `node:sqlite` file under a throwaway `akaHome`,
 * the config is the one the handler resolves itself, and every payload is a
 * RECORDED fixture with its prompt and `cwd` re-pointed.
 *
 * Every raw-value absence check runs AFTER a positive control on the same
 * bytes, because an empty notice satisfies every run-by-run absence check.
 */
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { openLocalDatabase } from '@akasecurity/persistence';
import {
  bundledDetections,
  createPluginRuntime,
  LARGE_INPUT_THRESHOLD_CHARS,
  loadConfig,
} from '@akasecurity/plugin-sdk';
import type { BuiltinPolicyId } from '@akasecurity/schema';
import { SOURCE_TOOL } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTrees } from '../../../../test/helpers/remove-tree.ts';
import {
  unscannedTooLargeMessage,
  unscannedWorkerUnavailableMessage,
} from '../../src/exception-guidance.ts';
import { HOOK_SCAN_DEADLINE_MS, largeInputBound } from '../../src/hooks/large-input.ts';
import { openGatewayOrNull } from '../../src/hooks/store-health.ts';
import { runUserPromptSubmit } from '../../src/hooks/user-prompt-submit-run.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';
import { ruleExample } from '../helpers/rule-example.ts';
import type { StderrCapture } from '../helpers/stderr-capture.ts';
import { captureStderr } from '../helpers/stderr-capture.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, '..', 'fixtures');

function fixture(dir: string, name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(FIXTURES, dir, name), 'utf8')) as Record<string, unknown>;
}

const RULE_ID = 'secrets/twilio-key';
const FIXTURE = ruleExample(RULE_ID);

// The userinfo in an scp-style remote reads as an email address to a scanner,
// so the remote is built from parts.
const AT = String.fromCharCode(64);
const WORK_REMOTE = `git${AT}GitHub.com:acme/work-repo.git`;
const WORK_KEY = 'github.com/acme/work-repo';

const DIALECTS = [
  {
    kind: 'cli',
    event: 'userPromptSubmitted',
    payload: (prompt: string, cwd: string) => ({
      ...fixture('cli', 'userPromptSubmitted.json'),
      prompt,
      cwd,
    }),
    sessionId: () => String(fixture('cli', 'userPromptSubmitted.json').sessionId),
  },
  {
    kind: 'vscode',
    event: 'UserPromptSubmit',
    payload: (prompt: string, cwd: string) => ({
      ...fixture('vscode-provisional', 'UserPromptSubmit.json'),
      prompt,
      cwd,
    }),
    sessionId: () => String(fixture('vscode-provisional', 'UserPromptSubmit.json').session_id),
  },
] as const;

let root: string;
let akaHome: string;
let cwd: string;
let stderr: StderrCapture;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-copilot-prompt-run-'));
  // Not created here: the handler's own config load creates it, so a case
  // that must not open the store can assert the directory never appeared.
  akaHome = join(root, 'aka-home');
  cwd = join(root, 'checkout');
  mkdirSync(join(cwd, '.git'), { recursive: true });
  writeFileSync(join(cwd, '.git', 'config'), `[remote "origin"]\n\turl = ${WORK_REMOTE}\n`);
  stderr = captureStderr();
});

afterEach(() => {
  vi.restoreAllMocks();
  removeTrees([root]);
});

function seedPolicy(policy: BuiltinPolicyId): void {
  const db = openLocalDatabase(join(akaHome, 'data'));
  try {
    db.installedPacks.recordInventory(bundledDetections());
    db.installedPacks.setPolicy(FIXTURE.namespace, FIXTURE.packId, policy);
  } finally {
    db.close();
  }
}

/** `config.onboarded` reads `onboardedAt`; set, a clean prompt carries no nudge. */
function markOnboarded(): void {
  const dir = join(akaHome, 'settings');
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, 'settings.json'),
    JSON.stringify({ onboardedAt: '2026-01-01T00:00:00Z' }),
  );
}

function rows(sql: string, ...params: string[]): Record<string, unknown>[] {
  const db = new DatabaseSync(join(akaHome, 'data', 'aka.db'), { readOnly: true });
  try {
    return db.prepare(sql).all(...params);
  } finally {
    db.close();
  }
}

function promptRows(): Record<string, unknown>[] {
  return rows(
    "SELECT id, content, scope_key, root_session_id, attributes FROM audit_events WHERE event_type = 'prompt'",
  );
}

function findingRows(): Record<string, unknown>[] {
  return rows(
    `SELECT d.rule_id, f.action_taken, e.root_session_id
       FROM inspection_findings f
       JOIN inspection_definitions d ON d.id = f.inspection_definition_id
       JOIN audit_events e ON e.id = f.audit_event_id`,
  );
}

describe.each(DIALECTS)('runUserPromptSubmit on the $kind dialect', (d) => {
  const isCli = d.kind === 'cli';

  /** The message this dialect's user sees, read from the channel it has one on. */
  function notice(output: unknown): string {
    if (isCli) {
      // The CLI documents no message field on this event: stdout stays empty.
      expect(output).toBeUndefined();
      // `writeNotice` terminates the line; the message itself does not.
      return stderr.filtered().trimEnd();
    }
    expect(stderr.filtered()).toBe('');
    return String((output as { systemMessage?: unknown } | undefined)?.systemMessage);
  }

  async function run(prompt: string, options: { scanWorkerUrl?: URL } = {}): Promise<unknown> {
    return runUserPromptSubmit(d.event, JSON.stringify(d.payload(prompt, cwd)), {
      akaHome,
      ...options,
    });
  }

  it('records a finding under the session and names its rule, echoing no run of it', async () => {
    seedPolicy('warn');
    const text = notice(await run(`deploy ${FIXTURE.example}`));

    // Positive control first: the notice is there and is about this finding.
    expect(text).toContain(RULE_ID);
    expect(text).toContain('sent unchanged');
    expect(findingRows()).toEqual([
      { rule_id: RULE_ID, action_taken: 'warn', root_session_id: d.sessionId() },
    ]);
    expectNoEchoOf(text, FIXTURE.example);
  });

  it('resolves a redact policy to the redactFallback, and says the prompt went out', async () => {
    seedPolicy('redact');
    const text = notice(await run(`deploy ${FIXTURE.example}`));

    // The shipped redactFallback is `warn`: what the ledger records and what
    // the user is told agree, and neither claims a masking that never happened.
    expect(findingRows().map((r) => r.action_taken)).toEqual(['warn']);
    expect(text).toContain(RULE_ID);
    expect(text).not.toMatch(/\bredacted\b|\bblocked\b/iu);
    expectNoEchoOf(text, FIXTURE.example);
  });

  it('stamps the scope key of the cwd the payload names', async () => {
    seedPolicy('monitor');
    await run('nothing to see here');
    expect(promptRows().map((r) => r.scope_key)).toEqual([WORK_KEY]);
  });

  it('records a clean prompt and says nothing once onboarded', async () => {
    markOnboarded();
    const output = await run('nothing to see here');
    expect(output).toBeUndefined();
    expect(stderr.filtered()).toBe('');
    // The row is the control: silence here is a decision, not a hook that
    // never ran.
    expect(promptRows()).toHaveLength(1);
  });

  // The worker is pointed at a location with nothing in it — an install that
  // never shipped one — so the bounded scan cannot run. Whether it reports
  // `unavailable` or (on a test process already past the hook deadline)
  // `timeout`, it is the same refusal, and it must not read as clean.
  it('reports a prompt too large to scan as unscanned, never as clean', async () => {
    seedPolicy('block');
    const filler = 'lorem ipsum dolor sit amet '.repeat(
      Math.ceil(LARGE_INPUT_THRESHOLD_CHARS / 27),
    );
    const prompt = `deploy ${FIXTURE.example} ${filler}`;
    expect(prompt.length).toBeGreaterThanOrEqual(LARGE_INPUT_THRESHOLD_CHARS);
    const absent = pathToFileURL(join(root, 'no-worker-here', 'scan-worker.js'));

    const text = notice(await run(prompt, { scanWorkerUrl: absent }));

    // Recorded, with the refusal on the row and none of the content in it.
    const [row] = promptRows();
    expect(row?.content).toBe('');
    const attrs = JSON.parse(String(row?.attributes)) as Record<string, unknown>;
    expect(['unavailable', 'timeout']).toContain(attrs.scan_incomplete);
    // Positive control: the sentence for the cause the row records, and
    // nothing about a block. The hook's deadline is measured from process
    // start, so a long-running test process can reach it before the missing
    // worker is noticed; a fresh hook process (the e2e no-worker rows) always
    // reports the missing worker.
    if (attrs.scan_incomplete === 'unavailable') {
      expect(text).toBe(
        unscannedWorkerUnavailableMessage('prompt', 'it was sent to the model unchanged'),
      );
      expect(text).not.toMatch(/shorten/iu);
    } else {
      expect(text).toBe(unscannedTooLargeMessage('prompt', 'it was sent to the model unchanged'));
    }
    expect(text).not.toMatch(/\bblocked\b/iu);
    expect(findingRows()).toEqual([]);
    expectNoEchoOf(text, FIXTURE.example);
    // Nothing on stderr claims the prompt was refused: this hook cannot refuse
    // it, so the SDK's refusal line is not written. The case below is the
    // control that the same bounded scan does write it for a refusing caller.
    expect(stderr.raw()).not.toMatch(/refus/iu);
  });

  it('writes the SDK refusal line for a refusing caller over the same absent worker', async () => {
    seedPolicy('block');
    const filler = 'lorem ipsum dolor sit amet '.repeat(
      Math.ceil(LARGE_INPUT_THRESHOLD_CHARS / 27),
    );
    const config = loadConfig(akaHome);
    const gateway = openGatewayOrNull(config);
    if (gateway === null) throw new Error('the test store did not open');
    const runtime = createPluginRuntime(gateway, config.settings, {
      dataDir: config.dataDir,
      largeInput: largeInputBound(HOOK_SCAN_DEADLINE_MS, true),
      scanIsolation: {
        workerUrl: pathToFileURL(join(root, 'no-worker-here', 'scan-worker.js')),
      },
    });
    try {
      const result = await runtime.capture({
        kind: 'prompt',
        sourceTool: SOURCE_TOOL.Copilot,
        text: `deploy ${FIXTURE.example} ${filler}`,
      });
      expect(result.scanIncomplete).toBeDefined();
    } finally {
      await runtime.close();
    }
    expect(stderr.raw()).toMatch(/\[aka\] a large input could not be scanned.* and was refused/u);
  });

  it('warns once per session when the store cannot be opened', async () => {
    const dataDir = join(akaHome, 'data');
    mkdirSync(dataDir, { recursive: true });
    writeFileSync(
      join(dataDir, 'aka.db'),
      'AKA corrupt-store fixture — not a database\n'.repeat(64),
    );

    const first = notice(await run('nothing to see here'));
    expect(first).toContain('could not open its local store');

    stderr.reset();
    const second = await run('nothing to see here');
    expect(second).toBeUndefined();
    expect(stderr.filtered()).toBe('');
  });

  it.skipIf(process.platform === 'win32')(
    'warns once per session that the store is redirected through a symlink',
    async () => {
      markOnboarded();
      const elsewhere = join(root, 'elsewhere');
      mkdirSync(elsewhere);
      mkdirSync(akaHome, { recursive: true });
      symlinkSync(elsewhere, join(akaHome, 'data'));

      expect(await run('first prompt')).toBeUndefined();
      const first = stderr.raw();
      expect(first).toContain(elsewhere);

      stderr.reset();
      expect(await run('second prompt')).toBeUndefined();
      expect(stderr.raw()).not.toContain(elsewhere);
      // Still captured through the redirect: the warning is a notice, not a stop.
      expect(promptRows()).toHaveLength(2);
    },
  );
});

describe('runUserPromptSubmit declines without opening the store', () => {
  const cli = (prompt: string): string =>
    JSON.stringify({ ...fixture('cli', 'userPromptSubmitted.json'), prompt, cwd });
  // The same payload with every key `detectDialect` reads removed, so neither
  // dialect can be told. The control below sends it WITH its session id.
  const noDialect = (prompt: string): string => {
    const payload: Record<string, unknown> = {
      ...fixture('cli', 'userPromptSubmitted.json'),
      prompt,
      cwd,
    };
    delete payload.sessionId;
    return JSON.stringify(payload);
  };

  it.each([
    ['a foreign event token', 'preToolUse', cli('hello')],
    ['an empty prompt', 'userPromptSubmitted', cli('')],
    ['empty stdin', 'userPromptSubmitted', ''],
    ['malformed JSON', 'userPromptSubmitted', '{not json'],
    ['a JSON array', 'userPromptSubmitted', '[]'],
    ['no event token', undefined, cli('hello')],
    ['a payload whose dialect cannot be told', 'userPromptSubmitted', noDialect('hello')],
  ])('on %s', async (_label, event, stdin) => {
    expect(await runUserPromptSubmit(event, stdin, { akaHome })).toBeUndefined();
    expect(existsSync(akaHome)).toBe(false);
    expect(stderr.filtered()).toBe('');
  });

  it('opens it for the same payload under its own token (the control)', async () => {
    markOnboarded();
    expect(
      await runUserPromptSubmit('userPromptSubmitted', cli('hello'), { akaHome }),
    ).toBeUndefined();
    expect(promptRows()).toHaveLength(1);
  });
});
