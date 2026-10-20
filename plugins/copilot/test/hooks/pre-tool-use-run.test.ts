/**
 * The tool-call handler, driven in-process against a real temp home, in BOTH
 * payload dialects.
 *
 * Nothing is mocked but stderr, which is captured rather than replaced in
 * behaviour: the store is a real `node:sqlite` file under a throwaway `akaHome`,
 * the config is the one the handler resolves itself, and every payload is a
 * fixture with its command and `cwd` re-pointed — the CLI's RECORDED, the VS
 * Code one provisional.
 *
 * This is the one Copilot event that REFUSES, so the cases are about the two
 * refusals it owns: a field too large to scan in time, and a vault pointer in
 * text that executes. Each is paired with a control that the same payload
 * minus the cause reaches no verdict, so a refusal is told apart from a
 * handler that denies everything.
 *
 * Every raw-value absence check runs AFTER a positive control on the same
 * bytes, because an empty message satisfies every run-by-run absence check.
 */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections, LARGE_INPUT_THRESHOLD_CHARS } from '@akasecurity/plugin-sdk';
import type { BuiltinPolicyId } from '@akasecurity/schema';
import { POINTER_TOKEN_ANCHORED } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTrees } from '../../../../test/helpers/remove-tree.ts';
import { tooLargeToScanMessage } from '../../src/exception-guidance.ts';
import { denyPointerMessage } from '../../src/hooks/pre-tool-use-decision.ts';
import { runPreToolUse } from '../../src/hooks/pre-tool-use-run.ts';
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

// A real pointer token, assembled from parts so neither this repository's own
// scanning nor a reader mistakes the source for one: the vault's
// `<category>:<key_version>.<pointer_id>.<tag>` shape with the segment widths
// it mints. The first case below is the control that the schema parses it.
const POINTER = `${'['.repeat(2)}aka:secret:AA.${'A'.repeat(26)}.${'B'.repeat(16)}${']'.repeat(2)}`;

const LARGE = `${'lorem ipsum dolor sit amet '.repeat(Math.ceil(LARGE_INPUT_THRESHOLD_CHARS / 27))}end`;

const DIALECTS = [
  {
    kind: 'cli',
    event: 'preToolUse',
    tool: 'bash',
    payload: (command: string, cwd: string): Record<string, unknown> => {
      const base = fixture('cli', 'preToolUse.json');
      return { ...base, cwd, toolArgs: { ...(base.toolArgs as object), command } };
    },
    deny: (reason: string): unknown => ({
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
    }),
  },
  {
    kind: 'vscode',
    event: 'PreToolUse',
    tool: 'run_in_terminal',
    payload: (command: string, cwd: string): Record<string, unknown> => {
      const base = fixture('vscode-provisional', 'PreToolUse.json');
      return { ...base, cwd, tool_input: { ...(base.tool_input as object), command } };
    },
    deny: (reason: string): unknown => ({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: reason,
      },
    }),
  },
] as const;

let root: string;
let akaHome: string;
let cwd: string;
let stderr: StderrCapture;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-copilot-call-run-'));
  // Not created here: the handler's own config load creates it, so a case
  // that must not reach the store can assert the directory never appeared.
  akaHome = join(root, 'aka-home');
  cwd = join(root, 'checkout');
  mkdirSync(cwd);
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

function corruptStore(): void {
  const dataDir = join(akaHome, 'data');
  mkdirSync(dataDir, { recursive: true });
  writeFileSync(join(dataDir, 'aka.db'), 'AKA corrupt-store fixture — not a database\n'.repeat(64));
}

function findingRules(): unknown[] {
  const db = new DatabaseSync(join(akaHome, 'data', 'aka.db'), { readOnly: true });
  try {
    return db
      .prepare(
        `SELECT d.rule_id FROM inspection_findings f
           JOIN inspection_definitions d ON d.id = f.inspection_definition_id`,
      )
      .all()
      .map((row) => row.rule_id);
  } finally {
    db.close();
  }
}

function reasonOf(output: unknown): string {
  const flat = output as { permissionDecisionReason?: unknown } | undefined;
  const nested = output as
    { hookSpecificOutput?: { permissionDecisionReason?: unknown } } | undefined;
  return String(
    flat?.permissionDecisionReason ?? nested?.hookSpecificOutput?.permissionDecisionReason,
  );
}

it('builds a pointer the schema recognises (the control for the pointer cases)', () => {
  expect(POINTER).toMatch(POINTER_TOKEN_ANCHORED);
});

describe.each(DIALECTS)('runPreToolUse on the $kind dialect', (d) => {
  async function run(command: string, options: { scanWorkerUrl?: URL } = {}): Promise<unknown> {
    return runPreToolUse(d.event, JSON.stringify(d.payload(command, cwd)), {
      akaHome,
      ...options,
    });
  }

  it('writes nothing for a clean call of ordinary size', async () => {
    seedPolicy('block');
    expect(await run('ls -la')).toBeUndefined();
    expect(stderr.filtered()).toBe('');
    // The control: the store was opened, so the silence is a decision.
    expect(existsSync(join(akaHome, 'data', 'aka.db'))).toBe(true);
  });

  it('denies a secret in the command under block, echoing no run of it', async () => {
    seedPolicy('block');
    const output = await run(`curl -u "${FIXTURE.example}" https://example.test`);
    const reason = reasonOf(output);
    // Positive control first: a deny, in this dialect's shape, naming the rule.
    expect(output).toEqual(d.deny(reason));
    expect(reason).toContain(RULE_ID);
    expect(findingRules()).toContain(RULE_ID);
    expectNoEchoOf(reason, FIXTURE.example);
    expectNoEchoOf(stderr.raw(), FIXTURE.example);
  });

  // The worker is pointed at a location with nothing in it — an install that
  // never shipped one — so the bounded scan cannot run. Whether it reports
  // `unavailable` or `timeout`, the call is refused: this is the adapter's one
  // fail-closed branch.
  it('denies a field too large to scan in time, in this dialect’s deny shape', async () => {
    seedPolicy('block');
    const absent = pathToFileURL(join(root, 'no-worker-here', 'scan-worker.js'));
    const command = `echo ${FIXTURE.example} ${LARGE}`;
    expect(command.length).toBeGreaterThanOrEqual(LARGE_INPUT_THRESHOLD_CHARS);

    const output = await run(command, { scanWorkerUrl: absent });

    expect(output).toEqual(d.deny(tooLargeToScanMessage(`${d.tool} call`)));
    // The refused field was never scanned, so nothing was found in it.
    expect(findingRules()).toEqual([]);
    expectNoEchoOf(reasonOf(output), FIXTURE.example);
    // The SDK says on stderr that it refused, and carries none of the field.
    const written = stderr.filtered();
    expect(written).toMatch(/\[aka\] a large input could not be scanned.* and was refused/u);
    expectNoEchoOf(stderr.raw(), FIXTURE.example);
    expect(stderr.raw()).not.toContain('lorem ipsum');
  });

  it('reaches no verdict on benign text below the threshold over the same absent worker (the control)', async () => {
    seedPolicy('block');
    // Below the threshold the same benign text is scanned in-process: no
    // worker is needed, so the absent one cannot decide anything.
    const absent = pathToFileURL(join(root, 'no-worker-here', 'scan-worker.js'));
    expect(await run(`echo ${LARGE.slice(0, 1000)}`, { scanWorkerUrl: absent })).toBeUndefined();
    expect(stderr.filtered()).toBe('');
  });

  it('denies a vault pointer in the command without reaching the store', async () => {
    const output = await run(`curl -H "Authorization: ${POINTER}" https://example.test`);
    expect(output).toEqual(d.deny(denyPointerMessage(d.tool)));
    // Decided from the call alone: the config load that creates the home never
    // ran, so no store was opened and none can be left open.
    expect(existsSync(akaHome)).toBe(false);
    expect(stderr.filtered()).toBe('');
  });

  it('denies a vault pointer in the command even when the store cannot be opened', async () => {
    corruptStore();
    const output = await run(`curl -H "Authorization: ${POINTER}" https://example.test`);
    expect(output).toEqual(d.deny(denyPointerMessage(d.tool)));
  });

  it('says the store is unavailable for the same call minus the pointer (the control)', async () => {
    corruptStore();
    const output = await run('curl https://example.test');
    // The unopenable store is real: without the pointer the handler reaches
    // it, warns on this dialect's channel, and reaches no verdict.
    if (d.kind === 'vscode') {
      expect(String((output as { systemMessage?: unknown }).systemMessage)).toContain(
        'could not open its local store',
      );
    } else {
      expect(output).toBeUndefined();
      expect(stderr.filtered()).toContain('could not open its local store');
    }
  });
});

// On the CLI a prose field still rewrites beside a command (`modifiedArgs`
// carries no verdict), so a redact in `description` and a warn in `command`
// meet in the rewrite branch. The notice there has to name both, or the
// command's warning is recorded and never shown.
describe('runPreToolUse on the cli dialect — a warned command beside a redacted description', () => {
  const COMMAND_RULE = 'command-risk/credential-file-read';
  const COMMAND = ruleExample(COMMAND_RULE);

  function seedPolicies(entries: readonly (readonly [string, string, BuiltinPolicyId])[]): void {
    const db = openLocalDatabase(join(akaHome, 'data'));
    try {
      db.installedPacks.recordInventory(bundledDetections());
      for (const [namespace, packId, policy] of entries) {
        db.installedPacks.setPolicy(namespace, packId, policy);
      }
    } finally {
      db.close();
    }
  }

  function actions(): unknown[] {
    const db = new DatabaseSync(join(akaHome, 'data', 'aka.db'), { readOnly: true });
    try {
      return db
        .prepare(
          `SELECT d.rule_id, f.action_taken FROM inspection_findings f
             JOIN inspection_definitions d ON d.id = f.inspection_definition_id
             ORDER BY d.rule_id`,
        )
        .all()
        .map((row) => ({ rule_id: row.rule_id, action_taken: row.action_taken }));
    } finally {
      db.close();
    }
  }

  it('rewrites the description and names both rules in the stderr notice', async () => {
    seedPolicies([
      [COMMAND.namespace, COMMAND.packId, 'warn'],
      [FIXTURE.namespace, FIXTURE.packId, 'redact'],
    ]);
    const base = fixture('cli', 'preToolUse.json');
    const description = `Read the file, then use ${FIXTURE.example}`;
    const payload = {
      ...base,
      cwd,
      toolArgs: { ...(base.toolArgs as object), command: COMMAND.example, description },
    };

    const output = (await runPreToolUse('preToolUse', JSON.stringify(payload), { akaHome })) as {
      modifiedArgs?: Record<string, unknown>;
    };

    // The rewrite: the command untouched, the description masked.
    expect(output.modifiedArgs?.command).toBe(COMMAND.example);
    expect(typeof output.modifiedArgs?.description).toBe('string');
    expect(output.modifiedArgs?.description).not.toBe(description);
    expectNoEchoOf(String(output.modifiedArgs?.description), FIXTURE.example);

    const written = stderr.filtered();
    expect(written).toContain(`AKA redacted sensitive content in bash input — flagged ${RULE_ID}.`);
    expect(written).toContain(`AKA flagged sensitive content in bash input (${COMMAND_RULE}).`);
    expectNoEchoOf(stderr.raw(), FIXTURE.example);

    // The ledger records what each field resolved to; the notice changes none of it.
    expect(actions()).toEqual([
      { rule_id: COMMAND_RULE, action_taken: 'warn' },
      { rule_id: RULE_ID, action_taken: 'redact' },
    ]);
  });
});
