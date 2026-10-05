/**
 * Replays a synthetic credential-leak corpus (test/helpers/leak-corpus.ts)
 * through the BUILT PreToolUse and PostToolUse hooks, under three policies,
 * and scores what the model would receive.
 *
 * For each call: PreToolUse runs when the shipped matcher selects the tool, and
 * a deny ends the call there. Otherwise PostToolUse runs when its matcher
 * selects the tool, and the model receives `updatedToolOutput` when the hook
 * rewrote the result, or the original result when it did not. A canary leaks
 * when any of its forms (an 8-character run, its hex, its base64) is still in
 * what the model receives.
 *
 * Policies, as a user would set them:
 * - default: whatever the first hook call on an empty store installs;
 * - block: command-risk, secrets and secrets-infra on Block;
 * - redact: secrets and secrets-infra on Redact, command-risk on Warn.
 */
import { mkdtempSync, readFileSync } from 'node:fs';
import { availableParallelism, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import type { BuiltinPolicyId } from '@akasecurity/schema';
import { afterAll, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import type { Canary, ToolCall } from '../helpers/leak-corpus.ts';
import { buildCorpus, leakForms } from '../helpers/leak-corpus.ts';
import { runHookAsync, tempHomeEnv } from '../helpers/run-hook.ts';

const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const hooksJson = JSON.parse(readFileSync(join(PLUGIN_ROOT, 'hooks', 'hooks.json'), 'utf8')) as {
  hooks: Record<string, { matcher?: string }[]>;
};
const matcherOf = (event: string): RegExp =>
  new RegExp(`^(?:${hooksJson.hooks[event]?.[0]?.matcher ?? '(?!)'})$`);
const PRE_MATCHER = matcherOf('PreToolUse');
const POST_MATCHER = matcherOf('PostToolUse');

type Policy = 'default' | 'block' | 'redact';
const POLICIES: Readonly<Record<Policy, Readonly<Record<string, BuiltinPolicyId>>>> = {
  default: {},
  block: { 'command-risk': 'block', secrets: 'block', 'secrets-infra': 'block' },
  redact: { 'command-risk': 'warn', secrets: 'redact', 'secrets-infra': 'redact' },
};

// The rules this change adds; no benign call may be flagged by one of them.
const NEW_RULES = ['command-risk/credential-file-access', 'secrets-infra/secret-config-value'];

interface CallOutcome {
  call: ToolCall;
  pre: 'deny' | 'rewrite' | 'warn' | 'none' | 'not-run';
  post: 'withheld' | 'redacted' | 'warn' | 'none' | 'not-run';
  rules: string[];
  /** Every string the model receives from the tool, joined. */
  received: string;
}

const RULE_IDS = new Set(bundledDetections().flatMap((p) => p.rules.map((r) => r.id)));
const rulesIn = (text: string): string[] =>
  [...text.matchAll(/[a-z][a-z0-9-]*\/[a-z][a-z0-9-]*/g)]
    .map((m) => m[0])
    .filter((id) => RULE_IDS.has(id));

function strings(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.flatMap(strings);
  if (typeof value === 'object' && value !== null) return Object.values(value).flatMap(strings);
  return [];
}

const homes: string[] = [];
afterAll(() => {
  for (const home of homes) removeTree(home);
});

function seededHome(policy: Policy): string {
  const home = mkdtempSync(join(tmpdir(), `aka-leak-${policy}-`));
  homes.push(home);
  const assignments = Object.entries(POLICIES[policy]);
  if (assignments.length === 0) return home;
  const db = openLocalDatabase(join(home, '.aka', 'data'));
  try {
    const packs = bundledDetections();
    db.installedPacks.recordInventory(packs);
    for (const [packId, action] of assignments) {
      const pack = packs.find((p) => p.packId === packId);
      if (pack === undefined) throw new Error(`bundled pack ${packId} is missing`);
      db.installedPacks.setPolicy(pack.namespace, pack.packId, action);
    }
  } finally {
    db.close();
  }
  return home;
}

async function replayCall(call: ToolCall, policy: Policy): Promise<CallOutcome> {
  const home = seededHome(policy);
  const base = { session_id: `leak-corpus-${policy}`, cwd: home, tool_name: call.tool };
  const outcome: CallOutcome = { call, pre: 'not-run', post: 'not-run', rules: [], received: '' };
  if (PRE_MATCHER.test(call.tool)) {
    const run = await runHookAsync(
      'pre-tool-use',
      JSON.stringify({ ...base, hook_event_name: 'PreToolUse', tool_input: call.input }),
      { env: tempHomeEnv(home) },
    );
    expect(run.status).toBe(0);
    outcome.pre = 'none';
    if (run.stdout !== '') {
      const out = JSON.parse(run.stdout) as {
        systemMessage?: string;
        hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string };
      };
      const decision = out.hookSpecificOutput?.permissionDecision;
      outcome.pre = decision === 'deny' ? 'deny' : decision === 'allow' ? 'rewrite' : 'warn';
      outcome.rules.push(
        ...rulesIn(
          `${out.systemMessage ?? ''} ${out.hookSpecificOutput?.permissionDecisionReason ?? ''}`,
        ),
      );
    }
    if (outcome.pre === 'deny') return outcome;
  }
  if (call.response === undefined) return outcome;
  let received: unknown = call.response;
  if (POST_MATCHER.test(call.tool)) {
    const run = await runHookAsync(
      'post-tool-use',
      JSON.stringify({
        ...base,
        hook_event_name: 'PostToolUse',
        tool_input: call.input,
        tool_response: call.response,
      }),
      { env: tempHomeEnv(home) },
    );
    expect(run.status).toBe(0);
    outcome.post = 'none';
    if (run.stdout !== '') {
      const out = JSON.parse(run.stdout) as {
        systemMessage?: string;
        hookSpecificOutput?: { updatedToolOutput?: unknown };
      };
      const message = out.systemMessage ?? '';
      outcome.rules.push(...rulesIn(message));
      if (out.hookSpecificOutput?.updatedToolOutput !== undefined) {
        received = out.hookSpecificOutput.updatedToolOutput;
        outcome.post = message.includes('withheld') ? 'withheld' : 'redacted';
      } else {
        outcome.post = 'warn';
      }
    }
  }
  outcome.received = strings(received).join('\n');
  return outcome;
}

async function replay(policy: Policy): Promise<CallOutcome[]> {
  const queue = [...corpus.calls];
  const results: CallOutcome[] = [];
  const worker = async (): Promise<void> => {
    for (let call = queue.shift(); call !== undefined; call = queue.shift()) {
      results.push(await replayCall(call, policy));
    }
  };
  await Promise.all(Array.from({ length: Math.min(8, availableParallelism()) }, worker));
  return corpus.calls.map((call) => {
    const found = results.find((r) => r.call === call);
    if (found === undefined) throw new Error(`no outcome for ${call.id}`);
    return found;
  });
}

const corpus = buildCorpus();
const FORMS = new Map(corpus.canaries.map((c) => [c.id, leakForms(c)]));
const flat = (text: string): string => text.replace(/\s+/g, '');
const carries = (text: string, canary: Canary): boolean => {
  const f = flat(text);
  return (FORMS.get(canary.id) ?? []).some((form) => f.includes(form));
};

interface Score {
  exposures: number;
  leaked: string[];
}

function score(outcomes: CallOutcome[]): Score {
  const result: Score = { exposures: 0, leaked: [] };
  for (const outcome of outcomes) {
    if (!outcome.call.task.startsWith('L')) continue;
    const original = strings(outcome.call.response).join('\n');
    for (const canary of corpus.canaries) {
      if (!carries(original, canary)) continue;
      result.exposures++;
      if (outcome.pre !== 'deny' && carries(outcome.received, canary)) {
        result.leaked.push(`${outcome.call.id}:${canary.id}`);
      }
    }
  }
  return result;
}

const benign = (outcomes: CallOutcome[]): CallOutcome[] =>
  outcomes.filter((o) => o.call.task.startsWith('B'));

// A path the credential guard covers, read with Read or searched with Grep.
const CREDENTIAL_PATH_CALLS = [
  'L2-read-zshenv',
  'L3-read-env',
  'L3-grep-env',
  'L4-read-auth-json',
  'L4-read-credentials-json',
  'L5-read-private-key',
];

const SHELL_RC_READ = 'B5-read-zshrc';

const TIMEOUT_MS = 180_000;

describe('credential-leak corpus replayed through the built hooks', () => {
  const runs = new Map<Policy, Promise<CallOutcome[]>>();
  const outcomesFor = (policy: Policy): Promise<CallOutcome[]> => {
    let run = runs.get(policy);
    if (run === undefined) {
      run = replay(policy);
      runs.set(policy, run);
    }
    return run;
  };

  it(
    'redact policy: no canary reaches the model, encoded and END-less key dumps included',
    async () => {
      const outcomes = await outcomesFor('redact');
      const { exposures, leaked } = score(outcomes);
      expect({ exposures, leaked }).toEqual({ exposures: 76, leaked: [] });
    },
    TIMEOUT_MS,
  );

  it(
    'block policy: no canary reaches the model, and credential paths are denied before the read',
    async () => {
      const outcomes = await outcomesFor('block');
      expect(score(outcomes).leaked).toEqual([]);
      const denied = outcomes.filter((o) => o.pre === 'deny').map((o) => o.call.id);
      expect(denied).toEqual(expect.arrayContaining(CREDENTIAL_PATH_CALLS));
    },
    TIMEOUT_MS,
  );

  it(
    'default policy: a read of a credential path is warned before it runs, never blocked',
    async () => {
      const outcomes = await outcomesFor('default');
      for (const id of CREDENTIAL_PATH_CALLS) {
        const outcome = outcomes.find((o) => o.call.id === id);
        expect({ id, pre: outcome?.pre, rules: outcome?.rules }).toEqual({
          id,
          pre: 'warn',
          rules: expect.arrayContaining(['command-risk/credential-file-access']) as unknown,
        });
      }
      expect(outcomes.filter((o) => o.pre === 'deny')).toEqual([]);
    },
    TIMEOUT_MS,
  );

  it(
    'benign tasks: the rules this change adds flag only the shell rc read, under any policy',
    async () => {
      // `~/.zshrc` is on the credential-file list for parity with
      // command-risk/credential-file-read, which already flags `cat ~/.zshrc`.
      for (const policy of ['default', 'block', 'redact'] as const) {
        const flagged = benign(await outcomesFor(policy))
          .filter((o) => NEW_RULES.some((rule) => o.rules.includes(rule)))
          .map((o) => o.call.id);
        expect({ policy, flagged }).toEqual({ policy, flagged: [SHELL_RC_READ] });
      }
    },
    TIMEOUT_MS,
  );

  it(
    'benign tasks: the default policy blocks and rewrites none, and warns only on the shell rc read',
    async () => {
      const touched = benign(await outcomesFor('default')).filter(
        (o) => o.pre !== 'none' && o.pre !== 'not-run',
      );
      expect(touched.map((o) => [o.call.id, o.pre])).toEqual([[SHELL_RC_READ, 'warn']]);
      const rewritten = benign(await outcomesFor('default')).filter(
        (o) => o.post === 'withheld' || o.post === 'redacted',
      );
      expect(rewritten.map((o) => o.call.id)).toEqual([]);
    },
    TIMEOUT_MS,
  );
});
