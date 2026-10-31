/**
 * Replays a set of synthetic tool calls through the BUILT PreToolUse hook, once
 * on a default install and once with the named packs set to block, and renders
 * what happened to each call as a markdown table.
 *
 * The two modes are the two things a user can run:
 * - default: whatever the first hook call on an empty store installs; a finding
 *   is recorded and the call goes through.
 * - strict: the packs a set names are on Block, as `setPolicy` leaves them when
 *   the user picks Block for a pack.
 *
 * Every call runs in its own empty home, so no outcome depends on another call
 * and the live store is never read.
 */
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { runHookAsync, tempHomeEnv } from './run-hook.ts';

// Per spawn, so a loaded box does not trip run-hook's 15 s default across the 24 parallel hooks.
const HOOK_TIMEOUT_MS = 90_000;

// Calls replayed at once; keeps the hook processes in flight near the 12 the sibling set runs.
const REPLAY_CONCURRENCY = 12;

export type ReplayMode = 'default' | 'strict';
export type Verdict = 'blocked' | 'warned' | 'allowed';

export interface ReplayCall {
  /** What the call does, in a few words; the first column of the table. */
  label: string;
  /** `attack` calls must be caught; `lookalike` calls must stay silent. */
  kind: 'attack' | 'lookalike';
  tool: 'Bash' | 'Write' | 'Edit' | 'WebFetch' | `mcp__${string}`;
  /**
   * Text an earlier tool returned into the session, replayed through the
   * PostToolUse hook in the same home before this call runs.
   */
  decoded?: { tool: string; input?: Record<string, unknown>; text: string };
  /** The tool input; `{home}` in a string stands for the call's own empty home. */
  input: Record<string, unknown>;
  cwd?: string;
  /** Rules of the set's packs the call is expected to trigger. */
  rules?: readonly string[];
  /**
   * Rules, of any pack, that warn on a default install. Set, the call's default
   * verdict is `warned` and these are the rules that warned; unset, it is `allowed`.
   */
  warnedBy?: readonly string[];
}

export interface ReplaySet {
  id: string;
  title: string;
  /** Packs set to Block in strict mode. */
  packs: readonly string[];
  calls: readonly ReplayCall[];
}

export interface ReplayOutcome {
  call: ReplayCall;
  verdict: Verdict;
  /** What PostToolUse did with the `decoded` text, when the call has one. */
  decodeVerdict?: Verdict | undefined;
  /** Every finding recorded for the call: rule id and the action taken. */
  findings: { ruleId: string; action: string }[];
}

function seededHome(set: ReplaySet, mode: ReplayMode): string {
  const home = mkdtempSync(join(tmpdir(), `aka-replay-${mode}-`));
  if (mode === 'default') return home;
  const db = openLocalDatabase(join(home, '.aka', 'data'));
  try {
    const packs = bundledDetections();
    db.installedPacks.recordInventory(packs);
    for (const packId of set.packs) {
      const pack = packs.find((p) => p.packId === packId);
      if (pack === undefined) throw new Error(`bundled pack ${packId} is missing`);
      db.installedPacks.setPolicy(pack.namespace, pack.packId, 'block');
    }
  } finally {
    db.close();
  }
  return home;
}

function withHome(value: unknown, home: string): Record<string, unknown> {
  const walk = (v: unknown): unknown => {
    if (typeof v === 'string') return v.replaceAll('{home}', home);
    if (Array.isArray(v)) return v.map(walk);
    if (typeof v === 'object' && v !== null) {
      return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x)]));
    }
    return v;
  };
  return walk(value) as Record<string, unknown>;
}

async function replayCall(
  set: ReplaySet,
  call: ReplayCall,
  mode: ReplayMode,
): Promise<ReplayOutcome> {
  const home = seededHome(set, mode);
  try {
    let decodeVerdict: Verdict | undefined;
    if (call.decoded !== undefined) {
      const post = await runHookAsync(
        'post-tool-use',
        JSON.stringify({
          session_id: `replay-${set.id}-${mode}`,
          cwd: call.cwd ?? home,
          hook_event_name: 'PostToolUse',
          tool_name: call.decoded.tool,
          tool_input: call.decoded.input ?? {},
          tool_response: [{ type: 'text', text: call.decoded.text }],
        }),
        { env: tempHomeEnv(home), timeoutMs: HOOK_TIMEOUT_MS },
      );
      if (post.status !== 0)
        throw new Error(`post-tool-use exited ${String(post.status)} for ${call.label}`);
      decodeVerdict = post.stdout === '' ? 'allowed' : 'warned';
    }
    const run = await runHookAsync(
      'pre-tool-use',
      JSON.stringify({
        session_id: `replay-${set.id}-${mode}`,
        cwd: call.cwd ?? home,
        hook_event_name: 'PreToolUse',
        tool_name: call.tool,
        tool_input: withHome(call.input, home),
      }),
      { env: tempHomeEnv(home), timeoutMs: HOOK_TIMEOUT_MS },
    );
    if (run.status !== 0)
      throw new Error(`pre-tool-use exited ${String(run.status)} for ${call.label}`);
    let verdict: Verdict = 'allowed';
    if (run.stdout !== '') {
      const out = JSON.parse(run.stdout) as {
        hookSpecificOutput?: { permissionDecision?: string };
      };
      verdict = out.hookSpecificOutput?.permissionDecision === 'deny' ? 'blocked' : 'warned';
    }
    const db = openLocalDatabase(join(home, '.aka', 'data'));
    try {
      const views = await db.findings.recentFindings({ limit: 100 });
      const findings = views.map((v) => ({ ruleId: v.ruleId, action: v.actionTaken }));
      return { call, verdict, decodeVerdict, findings };
    } finally {
      db.close();
    }
  } finally {
    removeTree(home);
  }
}

export async function replaySet(set: ReplaySet, mode: ReplayMode): Promise<ReplayOutcome[]> {
  // A bounded pool: each call spawns hook processes, and starting every call at
  // once loads a small runner enough to trip the per-spawn timeout.
  const outcomes: (ReplayOutcome | undefined)[] = set.calls.map(() => undefined);
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < set.calls.length) {
      const i = next++;
      const call = set.calls[i];
      if (call !== undefined) outcomes[i] = await replayCall(set, call, mode);
    }
  };
  await Promise.all(Array.from({ length: Math.min(REPLAY_CONCURRENCY, set.calls.length) }, worker));
  return outcomes.map((o) => {
    if (o === undefined) throw new Error('missing outcome');
    return o;
  });
}

/** Every rule that fired on a call, whichever pack it belongs to. */
export function allRules(outcome: ReplayOutcome): string[] {
  return [...new Set(outcome.findings.map((f) => f.ruleId))].sort();
}

/** The rules of the set's own packs among a call's findings. */
export function packRules(set: ReplaySet, outcome: ReplayOutcome): string[] {
  return [
    ...new Set(
      outcome.findings
        .map((f) => f.ruleId)
        .filter((id) => set.packs.some((pack) => id.startsWith(`${pack}/`))),
    ),
  ].sort();
}

/** The rules that recorded a `warn` on a call, whichever pack they belong to. */
export function warningRules(outcome: ReplayOutcome): string[] {
  return [
    ...new Set(outcome.findings.filter((f) => f.action === 'warn').map((f) => f.ruleId)),
  ].sort();
}

function cell(set: ReplaySet, outcome: ReplayOutcome): string {
  const fired = packRules(set, outcome);
  const rules = fired.map((r) => `\`${r}\``);
  if (outcome.verdict === 'blocked')
    return `blocked${rules.length > 0 ? `: ${rules.join(', ')}` : ''}`;
  const warnedBy = warningRules(outcome).map((r) => `\`${r}\``);
  const warned = warnedBy.length > 0 ? `warned by ${warnedBy.join(', ')}` : outcome.verdict;
  if (rules.length > 0) {
    return `${warned}, finding logged: ${rules.join(', ')}`;
  }
  return outcome.verdict === 'allowed' ? 'allowed, nothing flagged' : warned;
}

export function renderResults(
  set: ReplaySet,
  results: Readonly<Record<ReplayMode, ReplayOutcome[]>>,
  pluginVersion: string,
): string {
  const rows = set.calls.map((call, i) => {
    const d = results.default[i];
    const s = results.strict[i];
    if (d === undefined || s === undefined) throw new Error('missing outcome');
    return `| ${call.kind} | ${call.label} | ${cell(set, d)} | ${cell(set, s)} |`;
  });
  return [
    `# ${set.title}`,
    '',
    `Plugin build: ${pluginVersion}. Policies: **default** is a fresh install; **strict** sets ${set.packs.map((p) => `\`${p}\``).join(', ')} to block.`,
    '',
    '| kind | call | default | strict |',
    '| --- | --- | --- | --- |',
    ...rows,
    '',
  ].join('\n');
}

/** The folder of the eval whose cases a set was loaded from, under the repo's top-level `eval/`. */
export function evalDir(pluginRoot: string, folder: string): string {
  return join(pluginRoot, '..', '..', 'eval', folder);
}

/** A set is the `cases.json` of one eval folder. */
export function loadReplaySet(dir: string): ReplaySet {
  return JSON.parse(readFileSync(join(dir, 'cases.json'), 'utf8')) as ReplaySet;
}

export function writeResults(set: ReplaySet, markdown: string, dir: string): string {
  const file = join(dir, 'results', 'results.md');
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, markdown);
  return file;
}
