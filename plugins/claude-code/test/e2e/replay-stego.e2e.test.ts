/**
 * Replays the steganographic-signature chains (eval/2026-10-29-arxiv-2610.31974-stego-mcp-injection/cases.json)
 * through the BUILT PostToolUse and PreToolUse hooks on a default install and with
 * every bundled pack on Block, and writes the table to that folder's
 * results/results.md. Run it on its own with `pnpm eval:replay:stego`.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  allRules,
  evalDir,
  loadReplaySet,
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

const FOLDER = '2026-10-29-arxiv-2610.31974-stego-mcp-injection';
const DIR = evalDir(PLUGIN_ROOT, FOLDER);
const STEGO = loadReplaySet(DIR);

const TIMEOUT_MS = 180_000;

describe('Steganographic-signature attack chains (arXiv 2610.31974) replayed through the built hook', () => {
  const runs = new Map<ReplayMode, Promise<ReplayOutcome[]>>();
  const outcomesFor = (mode: ReplayMode): Promise<ReplayOutcome[]> => {
    let run = runs.get(mode);
    if (run === undefined) {
      run = replaySet(STEGO, mode);
      runs.set(mode, run);
    }
    return run;
  };

  it(
    'default install: no attack chain is blocked',
    async () => {
      const outcomes = await outcomesFor('default');
      for (const o of outcomes.filter((x) => x.call.kind === 'attack')) {
        expect(o.verdict, o.call.label).toBe('allowed');
      }
    },
    TIMEOUT_MS,
  );

  it(
    'every pack on Block: every attack chain is blocked',
    async () => {
      const outcomes = await outcomesFor('strict');
      for (const o of outcomes.filter((x) => x.call.kind === 'attack')) {
        expect(o.verdict, o.call.label).toBe('blocked');
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
        STEGO,
        { default: await outcomesFor('default'), strict: await outcomesFor('strict') },
        manifest.version,
      );
      const file = writeResults(STEGO, markdown, DIR);
      expect(readFileSync(file, 'utf8')).toContain('| attack |');
    },
    TIMEOUT_MS,
  );
});
