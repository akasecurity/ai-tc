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
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { runHookAsync, tempHomeEnv } from './run-hook.ts';

export type ReplayMode = 'default' | 'strict';
export type Verdict = 'blocked' | 'warned' | 'allowed';

export interface ReplayCall {
  /** What the call does, in a few words; the first column of the table. */
  label: string;
  /** `attack` calls must be caught; `lookalike` calls must stay silent. */
  kind: 'attack' | 'lookalike';
  tool: 'Bash' | 'Write' | 'Edit';
  /** The tool input, built against the call's own empty home. */
  input: (home: string) => Record<string, unknown>;
  cwd?: string;
  /** Rules of the set's packs the call is expected to trigger. */
  rules?: readonly string[];
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

async function replayCall(
  set: ReplaySet,
  call: ReplayCall,
  mode: ReplayMode,
): Promise<ReplayOutcome> {
  const home = seededHome(set, mode);
  try {
    const run = await runHookAsync(
      'pre-tool-use',
      JSON.stringify({
        session_id: `replay-${set.id}-${mode}`,
        cwd: call.cwd ?? home,
        hook_event_name: 'PreToolUse',
        tool_name: call.tool,
        tool_input: call.input(home),
      }),
      { env: tempHomeEnv(home) },
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
      return { call, verdict, findings };
    } finally {
      db.close();
    }
  } finally {
    removeTree(home);
  }
}

export async function replaySet(set: ReplaySet, mode: ReplayMode): Promise<ReplayOutcome[]> {
  return Promise.all(set.calls.map((call) => replayCall(set, call, mode)));
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

function cell(set: ReplaySet, outcome: ReplayOutcome): string {
  const rules = packRules(set, outcome).map((r) => `\`${r}\``);
  if (outcome.verdict === 'blocked')
    return `blocked${rules.length > 0 ? `: ${rules.join(', ')}` : ''}`;
  if (rules.length > 0) {
    return `${outcome.verdict}, finding logged: ${rules.join(', ')}`;
  }
  return outcome.verdict === 'allowed' ? 'allowed, nothing flagged' : 'warned';
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
    `Plugin build: ${pluginVersion}. Policies: **default** is a fresh install; **strict** sets ${set.packs
      .map((p) => `\`${p}\``)
      .join(', ')} to block.`,
    '',
    '| kind | call | default | strict |',
    '| --- | --- | --- | --- |',
    ...rows,
    '',
  ].join('\n');
}

export function writeResults(set: ReplaySet, markdown: string, pluginRoot: string): string {
  const file = join(pluginRoot, 'eval-results', `${set.id}.md`);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, markdown);
  return file;
}
