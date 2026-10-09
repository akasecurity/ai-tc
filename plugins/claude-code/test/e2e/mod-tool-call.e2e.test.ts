/**
 * The tool.call mod's helper (scripts/mod-tool-call.js) and the PreToolUse
 * command hook, driven as processes against a throwaway store: JSON in, JSON out.
 *
 * Every case in test/mod/tool-call-scenarios.ts runs three ways, and the outcome
 * each names must hold for all of them:
 *   - the helper alone decides the call the way the mod relays it;
 *   - the PreToolUse hook alone, as it runs with no mod installed;
 *   - the mod's chain, where the helper decides first and the hook is then shown
 *     the input the tool will run with.
 * The chain and the hook alone must agree: PreToolUse behaves the same with and
 * without the mod, and a call the mod decided is not recorded or decided twice.
 */
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { applyOnboarding, openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections, createVaultGlue } from '@akasecurity/plugin-sdk';
import { VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { recordToolHandoff } from '../../src/mod/handoff.ts';
import { runHook, tempHomeEnv } from '../helpers/run-hook.ts';
import type { Outcome, Scenario, Values } from '../mod/tool-call-scenarios.ts';
import { fill, RULE_IDS, SCENARIOS } from '../mod/tool-call-scenarios.ts';

const SESSION_ID = 'mod-tool-call-e2e';

// withTempHome is synchronous; the cases here await the vault, so the home must
// outlive the promise.
async function inHome<T>(fn: (home: string) => Promise<T>): Promise<T> {
  const home = mkdtempSync(join(tmpdir(), 'aka-mod-tool-call-'));
  try {
    return await fn(home);
  } finally {
    removeTree(home);
  }
}

function exampleOf(ruleId: string): string {
  const pack = bundledDetections().find((p) => p.rules.some((r) => r.id === ruleId));
  const example = pack?.rules.find((r) => r.id === ruleId)?.examples?.[0];
  if (pack === undefined || example === undefined) {
    throw new Error(`bundled rule ${ruleId} is missing or has no example`);
  }
  return example;
}

// Spelled by joining so no pointer-shaped literal sits in the source.
const UNGRANTED = ['[[aka:secret:', 'AB.', 'C'.repeat(26), '.', 'D'.repeat(16), ']]'].join('');

function env(home: string): Record<string, string> {
  return { ...tempHomeEnv(home), NODE_OPTIONS: '' };
}

function packOf(rule: keyof typeof RULE_IDS): ReturnType<typeof bundledDetections>[number] {
  const pack = bundledDetections().find((p) => p.rules.some((r) => r.id === RULE_IDS[rule]));
  if (pack === undefined) throw new Error(`no pack carries ${RULE_IDS[rule]}`);
  return pack;
}

async function seed(home: string, scenario: Scenario): Promise<Values> {
  const base = join(home, '.aka');
  const dataDir = join(base, 'data');
  const db = openLocalDatabase(dataDir);
  try {
    db.installedPacks.recordInventory(bundledDetections());
    for (const [rule, archetype] of Object.entries(scenario.policy)) {
      const pack = packOf(rule as keyof typeof RULE_IDS);
      db.installedPacks.setPolicy(pack.namespace, pack.packId, archetype);
    }
  } finally {
    db.close();
  }

  const secret = exampleOf(RULE_IDS.secret);
  const values: Values = {
    SECRET: secret,
    IP: ['45', '79', '142', '6'].join('.'),
    EMAIL: ['user1', 'example.com'].join('@'),
    GRANTED: UNGRANTED,
    UNGRANTED,
  };
  const needsVault = JSON.stringify(scenario.input).includes('{{GRANTED}}');
  if (needsVault) {
    applyOnboarding(
      {
        vaultConsent: { acknowledgedAt: new Date().toISOString(), version: VAULT_CONSENT_VERSION },
      },
      base,
    );
  } else {
    const dir = join(home, '.aka', 'settings');
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, 'settings.json'),
      JSON.stringify({
        onboardedAt: '2026-01-01T00:00:00Z',
        ...(scenario.fallback === undefined ? {} : { redactFallback: scenario.fallback }),
      }),
    );
  }
  if (!needsVault) return values;

  // A pointer the vault holds and the user granted a reveal of.
  const glue = createVaultGlue({ base });
  try {
    const minted = await glue.tokenizeText(secret, {
      findings: [
        {
          ruleId: RULE_IDS.secret,
          category: 'secret',
          severity: 'critical',
          span: { start: 0, end: secret.length },
          rawMatch: secret,
          confidence: 0.9,
        },
      ],
    });
    const pointer = minted.pointers[0];
    if (pointer === undefined) throw new Error('expected a pointer');
    values.GRANTED = pointer;
  } finally {
    glue.close();
  }
  const grants = openLocalDatabase(dataDir);
  try {
    const row = grants.secretVault.listAll()[0];
    if (row === undefined) throw new Error('expected the vault row');
    await grants.exceptions.create({
      ruleId: row.ruleId,
      category: 'secret',
      valueFingerprint: row.valueIdentityFingerprint,
      keyVersion: row.fingerprintKeyVersion,
      maskedValue: 'T******5',
      capability: 'reveal_to_model',
      scope: 'permanent',
      expiresAt: null,
      maxUses: null,
      justification: 'mod tool-call e2e',
      conditions: null,
      createdBy: 'tester',
      createdVia: 'cli-approve',
    });
  } finally {
    grants.close();
  }
  return values;
}

interface HelperAnswer {
  v: number;
  deny: string | null;
  input: Record<string, unknown> | null;
  context: string | null;
  message: string | null;
}

function helper(
  home: string,
  tool: string,
  input: Record<string, unknown>,
): HelperAnswer | 'no-decision' {
  const cwd = join(home, 'project');
  mkdirSync(cwd, { recursive: true });
  const run = runHook(
    'mod-tool-call',
    JSON.stringify({ v: 1, tool, input, sessionId: SESSION_ID, cwd }),
    {
      env: env(home),
    },
  );
  if (run.status !== 0) {
    expect(run.stdout).toBe('');
    return 'no-decision';
  }
  return JSON.parse(run.stdout) as HelperAnswer;
}

// What the PreToolUse hook says about a call, as an outcome over `input`.
function hook(home: string, tool: string, input: Record<string, unknown>): Outcome {
  const cwd = join(home, 'project');
  mkdirSync(cwd, { recursive: true });
  const run = runHook(
    'pre-tool-use',
    JSON.stringify({
      tool_name: tool,
      tool_input: input,
      session_id: SESSION_ID,
      cwd,
      hook_event_name: 'PreToolUse',
    }),
    { env: env(home) },
  );
  expect(run.status).toBe(0);
  if (run.stdout === '') return { kind: 'pass' };
  const out = JSON.parse(run.stdout) as {
    hookSpecificOutput?: {
      permissionDecision?: string;
      permissionDecisionReason?: string;
      updatedInput?: Record<string, unknown>;
    };
  };
  const specific = out.hookSpecificOutput;
  if (specific?.permissionDecision === 'deny') {
    return { kind: 'deny', reasonIncludes: [specific.permissionDecisionReason ?? ''] };
  }
  if (specific?.updatedInput !== undefined)
    return { kind: 'rewrite', input: specific.updatedInput };
  return { kind: 'pass' };
}

function expectOutcome(got: Outcome, want: Outcome): void {
  expect(got.kind).toBe(want.kind);
  if (got.kind === 'deny' && want.kind === 'deny') {
    for (const part of want.reasonIncludes) expect(got.reasonIncludes.join(' ')).toContain(part);
  }
  if (got.kind === 'rewrite' && want.kind === 'rewrite') expect(got.input).toEqual(want.input);
}

function eventRows(home: string): number {
  const db = new DatabaseSync(join(home, '.aka', 'data', 'aka.db'), { readOnly: true });
  try {
    const row = db
      .prepare(
        `SELECT count(*) AS n FROM audit_events WHERE event_type IN ('tool_use','code_change')`,
      )
      .get() as { n: number };
    return row.n;
  } finally {
    db.close();
  }
}

function filled(scenario: Scenario, values: Values): Outcome {
  const want = scenario.outcome;
  return want.kind === 'rewrite' ? { kind: 'rewrite', input: fill(want.input, values) } : want;
}

describe('mod-tool-call helper and PreToolUse', () => {
  for (const scenario of SCENARIOS) {
    describe(scenario.name, () => {
      it('the helper decides what the table says', async () => {
        await inHome(async (home) => {
          const values = await seed(home, scenario);
          const input = fill(scenario.input, values);
          const answer = helper(home, scenario.tool, input);
          if (!scenario.helper) {
            // Not a call the mod hands over; whatever the helper did with it, it
            // must not refuse or rewrite what the hook would let through.
            if (answer !== 'no-decision') {
              expect(answer.deny).toBeNull();
              expect(answer.input).toBeNull();
            }
            return;
          }
          expect(answer).not.toBe('no-decision');
          if (answer === 'no-decision') return;
          const want = filled(scenario, values);
          if (want.kind === 'deny') {
            expect(answer.deny).not.toBeNull();
            for (const part of want.reasonIncludes) expect(answer.deny).toContain(part);
          } else if (want.kind === 'rewrite') {
            expect(answer.deny).toBeNull();
            expect(answer.input).toEqual(want.input);
          } else {
            expect(answer.deny).toBeNull();
            expect(answer.input).toBeNull();
          }
        });
      });

      it('PreToolUse decides the same alone and behind the mod, and nothing is decided twice', async () => {
        const alone = await inHome(async (home) => {
          const values = await seed(home, scenario);
          const outcome = hook(home, scenario.tool, fill(scenario.input, values));
          expectOutcome(outcome, filled(scenario, values));
          return { outcome, events: eventRows(home) };
        });

        await inHome(async (home) => {
          const values = await seed(home, scenario);
          const input = fill(scenario.input, values);
          const answer = scenario.helper ? helper(home, scenario.tool, input) : 'no-decision';
          let chained: Outcome;
          if (answer === 'no-decision') {
            chained = hook(home, scenario.tool, input);
          } else if (answer.deny !== null) {
            chained = { kind: 'deny', reasonIncludes: [answer.deny] };
          } else {
            const effective = answer.input ?? input;
            const after = hook(home, scenario.tool, effective);
            // The helper decided this call and left a note: the hook has nothing to add.
            expect(after).toEqual({ kind: 'pass' });
            chained =
              answer.input === null ? { kind: 'pass' } : { kind: 'rewrite', input: answer.input };
          }
          // The same verdict, and the same rewrite where there is one. A deny's
          // reason carries a per-store reference, so it is checked against the
          // table rather than against the other store's wording.
          expectOutcome(chained, filled(scenario, values));
          expect(chained.kind).toBe(alone.outcome.kind);
          if (alone.outcome.kind === 'rewrite' && chained.kind === 'rewrite') {
            expect(chained.input).toEqual(alone.outcome.input);
          }
          // One decision, one set of rows.
          expect(eventRows(home)).toBe(alone.events);
        });
      });
    });
  }

  // A note is a file in the data directory, so anything able to write there could
  // leave one for a call the helper never saw. The hook keeps judging the fields
  // that execute: a raw value it would block, or a pointer nothing decided, is
  // still refused with a note in place.
  describe.each([
    'a block on a Bash command denies',
    'an ungranted pointer in a Bash command denies',
  ])('a planted note for %s', (name) => {
    it('does not let the call through', async () => {
      const scenario = SCENARIOS.find((s) => s.name === name);
      if (scenario === undefined) throw new Error(`no scenario named ${name}`);
      await inHome(async (home) => {
        const values = await seed(home, scenario);
        const input = fill(scenario.input, values);
        recordToolHandoff(join(home, '.aka', 'data'), scenario.tool, input);

        expectOutcome(hook(home, scenario.tool, input), filled(scenario, values));
      });
    });
  });

  it('a note the helper left vouches for the raw value it let through, and only that', async () => {
    const scenario = SCENARIOS.find(
      (s) =>
        s.name ===
        'a redact on a Bash command goes through unmasked under the shipped warn fallback',
    );
    if (scenario === undefined) throw new Error('no warn-fallback Bash scenario');
    await inHome(async (home) => {
      const values = await seed(home, scenario);
      const input = fill(scenario.input, values);
      const answer = helper(home, scenario.tool, input);
      expect(answer).not.toBe('no-decision');
      const cwd = join(home, 'project');

      // The helper warned and recorded; the hook, shown the same input, says nothing.
      const same = runHook(
        'pre-tool-use',
        JSON.stringify({
          tool_name: scenario.tool,
          tool_input: input,
          session_id: SESSION_ID,
          cwd,
          hook_event_name: 'PreToolUse',
        }),
        { env: env(home) },
      );
      expect(same.status).toBe(0);
      expect(same.stdout).toBe('');

      // Another command with a blocked-by-policy value was never vouched for.
      const other = { command: `${String(input.command)} && echo ${values.IP}2` };
      recordToolHandoff(join(home, '.aka', 'data'), scenario.tool, other);
      const planted = runHook(
        'pre-tool-use',
        JSON.stringify({
          tool_name: scenario.tool,
          tool_input: other,
          session_id: SESSION_ID,
          cwd,
          hook_event_name: 'PreToolUse',
        }),
        { env: env(home) },
      );
      expect(planted.status).toBe(0);
      expect(planted.stdout).not.toBe('');
    });
  });

  it('without the helper having run, the hook decides a call as ever', async () => {
    const scenario = SCENARIOS.find((s) => s.tool === 'Write' && s.outcome.kind === 'rewrite');
    if (scenario === undefined) throw new Error('no Write rewrite scenario');
    await inHome(async (home) => {
      const values = await seed(home, scenario);
      const input = fill(scenario.input, values);
      expectOutcome(hook(home, scenario.tool, input), filled(scenario, values));
    });
  });
});
