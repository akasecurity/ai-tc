import type { ExceptionWriter } from '@akasecurity/plugin-sdk';
import type { ActionTaken, DetectionCategory } from '@akasecurity/schema';
import { runApply } from '@akasecurity/setup-wizard';
import { describe, expect, it, vi } from 'vitest';

import { adapterPresenter } from '../../src/triage/presenter.ts';

const PLAN_PATH = '/sentinel/plan/setup-plan.json';

// A fake store that records every write, so the refusal below is provably
// write-free rather than merely non-zero-exit.
function fakeDb() {
  const posture: Record<string, ActionTaken> = { secret: 'redact' };
  const created: unknown[] = [];
  const exceptions: ExceptionWriter = {
    create: (input) => {
      created.push(input);
      return Promise.resolve();
    },
  };
  return {
    posture,
    created,
    open: () => ({
      policies: {
        getCategoryAction: (c: DetectionCategory) => posture[c],
        upsertCategoryAction: (c: DetectionCategory, a: ActionTaken) => {
          posture[c] = a;
        },
      },
      exceptions,
      close: vi.fn(),
    }),
  };
}

describe('the Codex presenter supplies the stale-plan rerun hint', () => {
  it('names the aka-setup skill in the drift refusal, so the user is never left without a next step', async () => {
    const db = fakeDb();
    const err: string[] = [];
    // Previewed against `secret: 'warn'`; the store now holds 'redact', so the
    // plan is stale and confirm must refuse.
    const code = await runApply({
      present: adapterPresenter,
      argv: ['--confirmed', '--plan', PLAN_PATH],
      readStream: (): never => {
        throw new Error('confirm must not read the stream');
      },
      runJudge: (): never => {
        throw new Error('confirm must not run the judge');
      },
      modelJudgeConsent: () => true,
      openDb: db.open,
      now: () => 0,
      createdBy: () => 'tester',
      stdout: vi.fn(),
      stderr: (s) => err.push(s),
      planIO: {
        write: () => PLAN_PATH,
        read: () => ({
          version: 3 as const,
          posture: { secret: 'block' as const },
          entries: [],
          showcase: [],
          join: [],
          notes: '',
          current: { secret: 'warn' as const },
        }),
        delete: vi.fn(),
      },
    });

    expect(code).toBe(1);
    const refusal = err.join('');
    expect(refusal).toMatch(/store changed/i);
    // Codex has no slash commands, so the hint names the skill — and it is the
    // same name the re-tune hint uses elsewhere in this plugin.
    expect(refusal).toContain('re-run the aka-setup skill to review against the current store');
    // Fail loud, write nothing.
    expect(db.posture).toEqual({ secret: 'redact' });
    expect(db.created).toEqual([]);
  });
});
