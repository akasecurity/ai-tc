/**
 * Replays the Downloads-folder attack chain (eval/2026-10-28-forever-downloads-agents-md/cases.json)
 * through the BUILT PreToolUse hook on a default install and with the
 * agent-harness-tamper pack on Block, and writes the table to
 * that folder's results/results.md. Run it on its own with `pnpm eval:replay`.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  allRules,
  evalDir,
  loadReplaySet,
  packRules,
  renderResults,
  type ReplayMode,
  type ReplayOutcome,
  replaySet,
  writeResults,
} from '../helpers/replay.ts';

const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const manifest = JSON.parse(
  readFileSync(join(PLUGIN_ROOT, '.claude-plugin', 'plugin.json'), 'utf8'),
) as { version: string };

const FOLDER = '2026-10-28-forever-downloads-agents-md';
const DIR = evalDir(PLUGIN_ROOT, FOLDER);
const FOREVER = loadReplaySet(DIR);

const TIMEOUT_MS = 180_000;

describe('Downloads-folder attack chain replayed through the built hook', () => {
  const runs = new Map<ReplayMode, Promise<ReplayOutcome[]>>();
  const outcomesFor = (mode: ReplayMode): Promise<ReplayOutcome[]> => {
    let run = runs.get(mode);
    if (run === undefined) {
      run = replaySet(FOREVER, mode);
      runs.set(mode, run);
    }
    return run;
  };

  it(
    'default install: every attack step is detected and logged, none is blocked',
    async () => {
      const outcomes = await outcomesFor('default');
      for (const o of outcomes.filter((x) => x.call.kind === 'attack')) {
        expect(o.verdict, o.call.label).toBe('allowed');
        expect(packRules(FOREVER, o), o.call.label).toEqual(
          expect.arrayContaining([...(o.call.rules ?? [])]),
        );
      }
    },
    TIMEOUT_MS,
  );

  it(
    'strict policy: every attack step is blocked',
    async () => {
      const outcomes = await outcomesFor('strict');
      for (const o of outcomes.filter((x) => x.call.kind === 'attack')) {
        expect(o.verdict, o.call.label).toBe('blocked');
        expect(packRules(FOREVER, o), o.call.label).toEqual(
          expect.arrayContaining([...(o.call.rules ?? [])]),
        );
      }
    },
    TIMEOUT_MS,
  );

  it(
    'look-alikes stay silent under both policies',
    async () => {
      for (const mode of ['default', 'strict'] as const) {
        const outcomes = await outcomesFor(mode);
        for (const o of outcomes.filter((x) => x.call.kind === 'lookalike')) {
          expect(o.verdict, `${mode}: ${o.call.label}`).toBe('allowed');
          expect(allRules(o), `${mode}: ${o.call.label}`).toEqual([]);
        }
      }
    },
    TIMEOUT_MS,
  );

  it(
    'writes the results table',
    async () => {
      const markdown = renderResults(
        FOREVER,
        { default: await outcomesFor('default'), strict: await outcomesFor('strict') },
        manifest.version,
      );
      const file = writeResults(FOREVER, markdown, DIR);
      expect(readFileSync(file, 'utf8')).toContain('| attack |');
    },
    TIMEOUT_MS,
  );
});
