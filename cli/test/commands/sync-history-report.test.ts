import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type * as PluginRuntime from '@akasecurity/plugin-runtime';
import type { HistorySyncPassReport } from '@akasecurity/plugin-runtime';
import { runHistorySyncPass } from '@akasecurity/plugin-runtime';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { runSyncHistory } from '../../src/commands/sync-history.ts';
import type { Prompter } from '../../src/lib/prompter.ts';

/**
 * The pass is MOCKED here, and only here.
 *
 * Most of these reports cannot be reached from a temp directory: `unreachable`,
 * `refused`, `credential-unusable` and `interrupted` all require a deployment to
 * have said something, and driving them for real would mean standing one up to
 * assert on a sentence. What is under test is the mapping — each report to the
 * one line a human reads — not the pass, which is covered in
 * `@akasecurity/plugin-runtime`.
 *
 * A separate FILE rather than a mock inside `sync-history.test.ts`, because a
 * module mock is file-scoped and that suite deliberately runs the real pass:
 * mocking there would quietly hollow out its two end-to-end report cases.
 *
 * `importOriginal` is spread rather than returning a bare object, so anything
 * else in the command's import graph that reaches this package keeps its real
 * implementation and only the pass is replaced.
 */
vi.mock('@akasecurity/plugin-runtime', async (importOriginal) => ({
  ...(await importOriginal<typeof PluginRuntime>()),
  runHistorySyncPass: vi.fn(),
}));

let base: string;
let exits: number[];

function recorder(): Prompter & { output: () => string } {
  const out: string[] = [];
  const unscripted = (): Promise<string> => Promise.reject(new Error('unscripted prompt'));
  return {
    output: () => out.join(''),
    out: (text) => {
      out.push(text);
    },
    err: () => {
      /* not asserted here */
    },
    isInteractive: true,
    ask: unscripted,
    askHidden: unscripted,
    readAllStdin: () => Promise.resolve(''),
  };
}

const deps = (io: ReturnType<typeof recorder>) => ({
  base,
  prompter: io,
  exit: (code: number) => exits.push(code),
});

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-sync-history-report-'));
  exits = [];
  vi.mocked(runHistorySyncPass).mockReset();
});

afterEach(() => {
  removeTree(base);
});

/**
 * Every report, and the line it must produce.
 *
 * Enumerated rather than derived from the source, which is the point: a table
 * built from the same switch it checks would agree with any wording, including a
 * wrong one. Two properties matter and both are asserted below — that each
 * report is DISTINGUISHABLE from the others, and that the ones with a remedy
 * name it, because "nothing happened" is the answer the user is trying to get
 * past.
 */
const REPORTS: readonly (readonly [HistorySyncPassReport, string])[] = [
  ['ok', 'This pass sent what was waiting.'],
  ['interrupted', 'This pass sent some of what was waiting; run it again to continue.'],
  ['unreachable', 'This pass could not reach the deployment. Nothing was sent; it stays queued.'],
  ['refused', 'This pass was refused by the deployment. Re-attach with `aka attach --url <url>`.'],
  ['not-attached', 'This pass did nothing: there is no deployment to send to.'],
  ['no-consent', 'This pass did nothing: sending existing activity is switched off.'],
  [
    'credential-unusable',
    'This pass did nothing: the stored credential cannot be used. Re-attach to repair it.',
  ],
  [
    'breaker-open',
    'This pass did nothing: forwarding is paused after repeated failures, and resumes on its own.',
  ],
  [
    'attachment-unreadable',
    'This pass did nothing: the recorded attachment time is unreadable. Re-attach to repair it.',
  ],
  ['already-running', 'This pass did nothing: another pass is already running.'],
  ['failed', 'This pass could not complete. Nothing was lost; it stays queued for the next one.'],
];

describe('aka sync-history --run reports every pass outcome', () => {
  it.each(REPORTS)('%s prints its own line', async (report, line) => {
    vi.mocked(runHistorySyncPass).mockResolvedValue(report);
    const io = recorder();

    await runSyncHistory(['--run'], deps(io));

    expect(exits).toEqual([]);
    expect(io.output()).toContain(line);
  });

  it('gives each report a DISTINCT line, so none is mistaken for another', () => {
    // The property the table exists for. Two reports sharing a sentence is the
    // failure this feature was written to remove — `no-consent` and
    // `not-attached` printed the same thing before it, and they are different
    // instructions to a human.
    const lines = REPORTS.map(([, line]) => line);
    expect(new Set(lines).size).toBe(lines.length);
  });

  // No runtime case for a report this build does not recognise: `reportLine`
  // is `REPORT_LINES[report]` against a table typed `satisfies
  // Record<HistorySyncPassReport, string>`, so a member added to the union
  // without a matching line is a COMPILE failure at the table, not a value
  // that reaches this test. The union is closed and this package owns both
  // halves of it, so there is no way to construct an unrecognised report
  // without lying to the type system — which is the property itself, and
  // needs no test beyond the typecheck CI already runs.

  it('prints the report ABOVE the consent sentence, not instead of it', async () => {
    // Both halves are load-bearing: the report says what this pass did, the
    // consent line says what the next one will do. An assertion on either alone
    // passes with the other deleted.
    vi.mocked(runHistorySyncPass).mockResolvedValue('ok');
    const io = recorder();

    await runSyncHistory(['--run'], deps(io));

    const out = io.output();
    expect(out).toContain('This pass sent what was waiting.');
    expect(out.indexOf('This pass sent what was waiting.')).toBeLessThan(
      out.indexOf('not attached'),
    );
  });
});
