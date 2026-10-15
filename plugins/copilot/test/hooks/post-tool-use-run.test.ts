/**
 * The tool-result handler, driven in-process against a real temp home.
 *
 * Nothing is mocked but stderr, which is captured rather than replaced in
 * behaviour: the store is a real `node:sqlite` file under a throwaway `akaHome`,
 * the config is the one the handler resolves itself, and every payload is a
 * fixture with its result and `cwd` re-pointed — the CLI's RECORDED, the VS
 * Code one provisional.
 *
 * Every raw-value absence check runs AFTER a positive control on the same
 * bytes, because an empty notice satisfies every run-by-run absence check.
 */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
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
  unscannedPastWalkLimitsMessage,
  unscannedTooLargeMessage,
} from '../../src/exception-guidance.ts';
import { HOOK_SCAN_DEADLINE_MS, largeInputBound } from '../../src/hooks/large-input.ts';
import { runPostToolUse } from '../../src/hooks/post-tool-use-run.ts';
import { openGatewayOrNull } from '../../src/hooks/store-health.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, '..', 'fixtures');

function fixture(dir: string, name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(FIXTURES, dir, name), 'utf8')) as Record<string, unknown>;
}

const RULE_ID = 'secrets/twilio-key';
function secretFixture(): { namespace: string; packId: string; example: string } {
  // Taken from the rule's own examples rather than written here: this
  // repository is public, and a credential-shaped literal does not belong in it.
  const pack = bundledDetections().find((p) => p.rules.some((r) => r.id === RULE_ID));
  const example = pack?.rules.find((r) => r.id === RULE_ID)?.examples?.[0];
  if (pack === undefined || example === undefined) {
    throw new Error(`bundled rule ${RULE_ID} is missing from the pack registry or has no example`);
  }
  return { namespace: pack.namespace, packId: pack.packId, example };
}
const FIXTURE = secretFixture();

// The userinfo in an scp-style remote reads as an email address to a scanner,
// so the remote is built from parts.
const AT = String.fromCharCode(64);
const WORK_REMOTE = `git${AT}GitHub.com:acme/work-repo.git`;
const WORK_KEY = 'github.com/acme/work-repo';
const PERSONAL_REMOTE = 'https://github.com/someone/dotfiles.git';
const PERSONAL_KEY = 'github.com/someone/dotfiles';

const DELIVERED = 'the output already reached the model unchanged';

const DIALECTS = [
  {
    kind: 'cli',
    event: 'postToolUse',
    tool: 'bash',
    payload: (result: unknown, cwd: string): Record<string, unknown> => {
      const base = fixture('cli', 'postToolUse.json');
      return {
        ...base,
        cwd,
        toolResult: { ...(base.toolResult as object), textResultForLlm: result },
      };
    },
    sessionId: () => String(fixture('cli', 'postToolUse.json').sessionId),
  },
  {
    kind: 'vscode',
    event: 'PostToolUse',
    tool: 'run_in_terminal',
    payload: (result: unknown, cwd: string): Record<string, unknown> => ({
      ...fixture('vscode-provisional', 'PostToolUse.json'),
      cwd,
      tool_response: result,
    }),
    sessionId: () => String(fixture('vscode-provisional', 'PostToolUse.json').session_id),
  },
] as const;

let root: string;
let akaHome: string;
let cwd: string;
let stderr: string[];
// `(node:1234) ExperimentalWarning: …` and the `--trace-warnings` hint after it.
const NODE_WARNING = /^\(node:\d+\) |--trace-warnings/u;

function checkout(name: string, remote: string): string {
  const dir = join(root, name);
  mkdirSync(join(dir, '.git'), { recursive: true });
  writeFileSync(join(dir, '.git', 'config'), `[remote "origin"]\n\turl = ${remote}\n`);
  return dir;
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-copilot-result-run-'));
  // Not created here: the handler's own config load creates it, so a case
  // that must not open the store can assert the directory never appeared.
  akaHome = join(root, 'aka-home');
  cwd = checkout('checkout', WORK_REMOTE);
  stderr = [];
  vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
    stderr.push(String(chunk));
    return true;
  });
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

function rows(sql: string): Record<string, unknown>[] {
  const db = new DatabaseSync(join(akaHome, 'data', 'aka.db'), { readOnly: true });
  try {
    return db.prepare(sql).all();
  } finally {
    db.close();
  }
}

function responseRows(): Record<string, unknown>[] {
  return rows(
    "SELECT content, scope_key, root_session_id, attributes FROM audit_events WHERE event_type = 'response'",
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

/**
 * Everything written to stderr except node's own runtime warnings — the hook's
 * notices AND the SDK's `[aka]` lines, so a line the SDK writes on the hook's
 * behalf is read like any other.
 */
function akaStderr(): string {
  return stderr.filter((line) => !NODE_WARNING.test(line)).join('');
}

describe.each(DIALECTS)('runPostToolUse on the $kind dialect', (d) => {
  const isCli = d.kind === 'cli';

  /** The message this dialect's user sees, read from the channel it has one on. */
  function notice(output: unknown): string {
    if (isCli) {
      // The CLI documents no message field on this event: stdout stays empty.
      expect(output).toBeUndefined();
      return akaStderr().trimEnd();
    }
    expect(akaStderr()).toBe('');
    return String((output as { systemMessage?: unknown } | undefined)?.systemMessage);
  }

  async function run(
    payload: Record<string, unknown>,
    options: { scanWorkerUrl?: URL } = {},
  ): Promise<unknown> {
    return runPostToolUse(d.event, JSON.stringify(payload), { akaHome, ...options });
  }

  it('records a finding in the result under the session, echoing no run of it', async () => {
    seedPolicy('warn');
    const text = notice(await run(d.payload(`TWILIO=${FIXTURE.example}`, cwd)));

    // Positive control first: the notice is there and is about this finding.
    expect(text).toContain(RULE_ID);
    expect(text).toContain(`${d.tool} result`);
    expect(text).toContain('reached the model unchanged');
    expect(findingRows()).toEqual([
      { rule_id: RULE_ID, action_taken: 'warn', root_session_id: d.sessionId() },
    ]);
    expectNoEchoOf(text, FIXTURE.example);
  });

  it('resolves a redact policy to the redactFallback, and never claims a withhold', async () => {
    seedPolicy('redact');
    const text = notice(await run(d.payload(`TWILIO=${FIXTURE.example}`, cwd)));

    // The shipped redactFallback is `warn`: what the ledger records and what
    // the user is told agree, and neither claims a masking that never happened.
    expect(findingRows().map((r) => r.action_taken)).toEqual(['warn']);
    expect(text).toContain(RULE_ID);
    expect(text).not.toMatch(/\bredacted\b|\bwithheld\b|never reached/iu);
    expectNoEchoOf(text, FIXTURE.example);
  });

  it('stamps the scope key of the cwd the payload names', async () => {
    seedPolicy('monitor');
    await run(d.payload(`TWILIO=${FIXTURE.example}`, cwd));
    // The row is the control: a result with no finding records none.
    expect(responseRows().map((r) => r.scope_key)).toEqual([WORK_KEY]);
  });

  it('records nothing and says nothing for a clean result', async () => {
    seedPolicy('block');
    expect(await run(d.payload('nothing to see here', cwd))).toBeUndefined();
    expect(akaStderr()).toBe('');
    expect(responseRows()).toEqual([]);
    // The control: the store was opened, so the silence is a decision.
    expect(existsSync(join(akaHome, 'data', 'aka.db'))).toBe(true);
  });

  // The worker is pointed at a location with nothing in it — an install that
  // never shipped one — so the bounded scan cannot run. Whether it reports
  // `unavailable` or `timeout`, it is the same refusal, and it must not read
  // as clean.
  it('reports a result too large to scan as unscanned, never as clean', async () => {
    seedPolicy('block');
    const filler = 'lorem ipsum dolor sit amet '.repeat(
      Math.ceil(LARGE_INPUT_THRESHOLD_CHARS / 27),
    );
    const result = `TWILIO=${FIXTURE.example} ${filler}`;
    expect(result.length).toBeGreaterThanOrEqual(LARGE_INPUT_THRESHOLD_CHARS);
    const absent = pathToFileURL(join(root, 'no-worker-here', 'scan-worker.js'));

    const text = notice(await run(d.payload(result, cwd), { scanWorkerUrl: absent }));

    // Positive control: the unscanned sentence, and nothing about a block.
    expect(text).toBe(unscannedTooLargeMessage(`${d.tool} result`, DELIVERED));
    expect(text).not.toMatch(/\bblocked\b/iu);
    // Recorded, with the refusal on the row and none of the result in it.
    const [row] = responseRows();
    expect(row?.content).toBe('');
    const attrs = JSON.parse(String(row?.attributes)) as Record<string, unknown>;
    expect(['unavailable', 'timeout']).toContain(attrs.scan_incomplete);
    expect(findingRows()).toEqual([]);
    expectNoEchoOf(text, FIXTURE.example);
    // Nothing on stderr claims the result was refused: this hook cannot refuse
    // it, so the SDK's refusal line is not written. The case below is the
    // control that the same bounded scan does write it for a refusing caller.
    expect(stderr.join('')).not.toMatch(/refus/iu);
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
        text: `TWILIO=${FIXTURE.example} ${filler}`,
      });
      expect(result.scanIncomplete).toBeDefined();
    } finally {
      await runtime.close();
    }
    expect(stderr.join('')).toMatch(
      /\[aka\] a large input could not be scanned.* and was refused/u,
    );
  });

  it('warns once per session when the store cannot be opened', async () => {
    const dataDir = join(akaHome, 'data');
    mkdirSync(dataDir, { recursive: true });
    writeFileSync(
      join(dataDir, 'aka.db'),
      'AKA corrupt-store fixture — not a database\n'.repeat(64),
    );

    const first = notice(await run(d.payload('some output', cwd)));
    expect(first).toContain('could not open its local store');

    stderr = [];
    expect(await run(d.payload('some output', cwd))).toBeUndefined();
    expect(akaStderr()).toBe('');
  });
});

describe('runPostToolUse scope key matches the call', () => {
  // A VS Code single-file write is keyed by its target, so its RESULT carries
  // that key too — not the payload cwd's — exactly as preToolUse keyed the call.
  it('keys a VS Code file-writer result by the file it wrote', async () => {
    seedPolicy('monitor');
    const personal = checkout('personal', PERSONAL_REMOTE);
    const payload = {
      ...fixture('vscode-provisional', 'PostToolUse.json'),
      cwd,
      tool_name: 'create_file',
      tool_input: { filePath: join(personal, 'notes.ts'), content: 'x' },
      tool_response: `created with TWILIO=${FIXTURE.example}`,
    };
    await runPostToolUse('PostToolUse', JSON.stringify(payload), { akaHome });
    expect(responseRows().map((r) => r.scope_key)).toEqual([PERSONAL_KEY]);
  });

  it('gives a CLI apply_patch result no key, as preToolUse gives the call none', async () => {
    seedPolicy('monitor');
    const base = fixture('cli', 'postToolUse.json');
    const payload = {
      ...base,
      cwd,
      toolName: 'apply_patch',
      toolArgs: { input: '*** Begin Patch\n*** End Patch\n' },
      toolResult: { ...(base.toolResult as object), textResultForLlm: `TWILIO=${FIXTURE.example}` },
    };
    await runPostToolUse('postToolUse', JSON.stringify(payload), { akaHome });
    // The row is the control: present, and keyless.
    expect(responseRows().map((r) => r.scope_key)).toEqual([null]);
  });
});

describe('runPostToolUse on an object-shaped VS Code result', () => {
  function objectPayload(response: unknown): string {
    return JSON.stringify({
      ...fixture('vscode-provisional', 'PostToolUse.json'),
      cwd,
      tool_response: response,
    });
  }

  it('scans a secret in a nested string leaf instead of dropping the result', async () => {
    seedPolicy('warn');
    const output = await runPostToolUse(
      'PostToolUse',
      objectPayload({ content: [{ type: 'text', text: `TWILIO=${FIXTURE.example}` }] }),
      { akaHome },
    );
    const text = String((output as { systemMessage?: unknown } | undefined)?.systemMessage);
    expect(text).toContain(RULE_ID);
    expect(findingRows().map((r) => r.rule_id)).toEqual([RULE_ID]);
    expectNoEchoOf(text, FIXTURE.example);
  });

  it('says part of it went unscanned when the walk bounds cut a leaf out', async () => {
    seedPolicy('warn');
    let deep: unknown = `TWILIO=${FIXTURE.example}`;
    for (let i = 0; i < 10; i += 1) deep = { k: deep };
    const output = await runPostToolUse(
      'PostToolUse',
      objectPayload({ shallow: 'nothing here', deep }),
      { akaHome },
    );
    const text = String((output as { systemMessage?: unknown } | undefined)?.systemMessage);
    // Positive control: the walk-limits sentence, which is not the timeout one.
    expect(text).toBe(unscannedPastWalkLimitsMessage('run_in_terminal result', DELIVERED));
    expect(text).not.toContain('time limit');
    expect(text).not.toMatch(/\bblocked\b/iu);
    expectNoEchoOf(text, FIXTURE.example);
  });
});

// A CLI result without the recorded `textResultForLlm` string is a changed
// envelope or a structured result. It still reaches the model, so it is walked
// like a structured VS Code result rather than passed through unscanned.
describe('runPostToolUse on a CLI result without textResultForLlm', () => {
  function cliPayload(result: unknown): string {
    return JSON.stringify({ ...fixture('cli', 'postToolUse.json'), cwd, toolResult: result });
  }

  it('scans a secret in a structured result and records the finding', async () => {
    seedPolicy('warn');
    const output = await runPostToolUse(
      'postToolUse',
      cliPayload({ resultType: 'success', content: [{ text: `TWILIO=${FIXTURE.example}` }] }),
      { akaHome },
    );
    // The CLI has no message field on this event: the notice is on stderr.
    expect(output).toBeUndefined();
    const text = akaStderr();
    expect(text).toContain(RULE_ID);
    expect(findingRows().map((r) => r.rule_id)).toEqual([RULE_ID]);
    expect(responseRows()).toHaveLength(1);
    expectNoEchoOf(text, FIXTURE.example);
  });

  it('says part of it went unscanned when the walk bounds cut a leaf out', async () => {
    seedPolicy('warn');
    let deep: unknown = `TWILIO=${FIXTURE.example}`;
    for (let i = 0; i < 10; i += 1) deep = { k: deep };
    const output = await runPostToolUse(
      'postToolUse',
      cliPayload({ shallow: 'nothing here', deep }),
      { akaHome },
    );
    expect(output).toBeUndefined();
    const text = akaStderr().trimEnd();
    // Positive control: the walk-limits sentence, which is not the timeout one.
    expect(text).toBe(unscannedPastWalkLimitsMessage('bash result', DELIVERED));
    expect(findingRows()).toEqual([]);
    expectNoEchoOf(text, FIXTURE.example);
  });
});

describe('runPostToolUse declines without opening the store', () => {
  const cli = (result: unknown): string =>
    JSON.stringify({
      ...fixture('cli', 'postToolUse.json'),
      cwd,
      toolResult: result,
    });
  const vscode = (result: unknown): string =>
    JSON.stringify({
      ...fixture('vscode-provisional', 'PostToolUse.json'),
      cwd,
      tool_response: result,
    });

  it.each([
    ['a foreign event token', 'preToolUse', cli({ textResultForLlm: 'hello' })],
    ['an empty CLI result', 'postToolUse', cli({ textResultForLlm: '' })],
    ['a CLI result with no string anywhere', 'postToolUse', cli({ textResultForLlm: 42 })],
    ['an empty VS Code result', 'PostToolUse', vscode('')],
    ['a VS Code object with no string leaf', 'PostToolUse', vscode({ n: 1, a: [], o: {} })],
    ['empty stdin', 'postToolUse', ''],
    ['malformed JSON', 'postToolUse', '{not json'],
    ['a payload with no tool name', 'postToolUse', JSON.stringify({ sessionId: 's', cwd })],
  ])('on %s', async (_label, event, stdin) => {
    expect(await runPostToolUse(event, stdin, { akaHome })).toBeUndefined();
    expect(existsSync(akaHome)).toBe(false);
    expect(akaStderr()).toBe('');
  });

  it('opens it for a result with text under its own token (the control)', async () => {
    expect(
      await runPostToolUse('postToolUse', cli({ textResultForLlm: 'hello' }), { akaHome }),
    ).toBeUndefined();
    expect(existsSync(join(akaHome, 'data', 'aka.db'))).toBe(true);
  });
});
