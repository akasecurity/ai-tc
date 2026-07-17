import { existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';

import type { ExceptionWriter } from '@akasecurity/plugin-sdk';
import type {
  ActionTaken,
  DetectionCategory,
  TriageHit,
  TriageRecommendation,
} from '@akasecurity/schema';
import { CalibrationFrame, DetectionCategory as DetectionCategorySchema } from '@akasecurity/schema';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { readFrameJsonBlock } from '../../src/setup-frame-json.ts';
import { runApply } from '../../src/triage/adapter.ts';
import { readPlanFile, writePlanFile } from '../../src/triage/plan-file.ts';

const RAW = 'AKIAIOSFODNN7EXAMPLE';
const FP = 'ab'.repeat(32);

const hit = (over: Partial<TriageHit> = {}): TriageHit => ({
  ruleId: 'core-secret/aws',
  category: 'secret',
  severity: 'critical',
  maskedMatch: 'A***E',
  rawMatch: RAW,
  context: `export KEY=${RAW} # prod`,
  confidence: 0.9,
  id: '0',
  valueFingerprint: FP,
  keyVersion: 1,
  ...over,
});

const streamText = () =>
  JSON.stringify(hit()) +
  '\n' +
  JSON.stringify({ done: true, count: 1, status: 'complete' }) +
  '\n';

const verdict = () => ({
  perCategory: [
    {
      category: 'secret' as const,
      action: 'warn' as const,
      reasoning: 'canonical fake AWS example key',
      genuineCount: 0,
      fpCount: 1,
      fpIds: ['0'],
    },
  ],
  notes: 'looks routine',
});

// A fake store that records every write, so a test can prove the confirm path
// wrote (and the preview path did not).
function fakeDb() {
  const posture: Record<string, ActionTaken> = {};
  const created: unknown[] = [];
  let closed = 0;
  const exceptions: ExceptionWriter = {
    create: (input) => {
      created.push(input);
      return Promise.resolve();
    },
  };
  return {
    posture,
    created,
    get closed() {
      return closed;
    },
    open: () => ({
      policies: {
        getCategoryAction: (c: DetectionCategory) => posture[c],
        upsertCategoryAction: (c: DetectionCategory, a: ActionTaken) => {
          posture[c] = a;
        },
      },
      exceptions,
      close: () => {
        closed++;
      },
    }),
  };
}

// Pull the plan-file path the preview run printed.
function planPathFromStdout(out: string[]): string {
  const line = out
    .join('')
    .split('\n')
    .find((l) => l.startsWith('Plan saved to:'));
  if (!line) throw new Error('preview did not print a plan path');
  return line.replace('Plan saved to:', '').trim();
}

const written: string[] = [];
afterEach(() => {
  for (const p of written.splice(0)) rmSync(join(p, '..'), { recursive: true, force: true });
  vi.restoreAllMocks();
});

describe('runApply — preview persists a plan and writes nothing', () => {
  it('renders the gate, persists the plan, prints its path, and touches no store row', async () => {
    const db = fakeDb();
    const out: string[] = [];
    const code = await runApply({
      argv: [],
      readStream: () => streamText(),
      runJudge: () => verdict(),
      openDb: db.open,
      now: () => 0,
      createdBy: () => 'tester',
      stdout: (s) => out.push(s),
      stderr: vi.fn(),
    });
    expect(code).toBe(0);
    const path = planPathFromStdout(out);
    written.push(path);
    expect(existsSync(path)).toBe(true);
    // preview is read-only: no posture upsert, no exception created
    expect(db.posture).toEqual({});
    expect(db.created).toEqual([]);
    // the showcase renders in the preview: per-category counts + reasoning
    const blob = out.join('');
    expect(blob).toContain('1 false-positive');
    expect(blob).toContain('canonical fake AWS example key');
  });
});

describe('runApply — preview is a raw-free egress boundary by construction', () => {
  const previewThrowing = async (runJudge: () => never): Promise<unknown> => {
    const db = fakeDb();
    try {
      await runApply({
        argv: [],
        readStream: () => streamText(),
        runJudge,
        openDb: db.open,
        now: () => 0,
        createdBy: () => 'tester',
        stdout: vi.fn(),
        stderr: vi.fn(),
      });
    } catch (e) {
      return e;
    }
    return undefined;
  };

  it('withholds a raw value that a downstream throw interpolated into its message', async () => {
    const thrown = await previewThrowing(() => {
      // A future/unexpected throw that echoes a raw hit value — the exact leak the
      // boundary must contain regardless of which throw site produced it.
      throw new Error(`judge blew up near ${RAW} — export KEY=${RAW}`);
    });
    expect(thrown).toBeInstanceOf(Error);
    expect((thrown as Error).message).not.toContain(RAW);
    expect((thrown as Error).message).toMatch(/withheld/i);
  });

  it('passes a raw-free error message through unchanged (keeps useful diagnostics)', async () => {
    const thrown = await previewThrowing(() => {
      throw new Error('claude -p judge subprocess failed (exit 1)');
    });
    expect((thrown as Error).message).toBe('claude -p judge subprocess failed (exit 1)');
  });
});

describe('runApply — confirm applies the persisted plan without re-judging', () => {
  it('applies exactly the previewed posture + entries and never reads the stream or judge', async () => {
    // 1. Preview writes a real plan file.
    const previewDb = fakeDb();
    const previewOut: string[] = [];
    await runApply({
      argv: [],
      readStream: () => streamText(),
      runJudge: () => verdict(),
      openDb: previewDb.open,
      now: () => 0,
      createdBy: () => 'tester',
      stdout: (s) => previewOut.push(s),
      stderr: vi.fn(),
    });
    const path = planPathFromStdout(previewOut);
    written.push(path);

    // 2. Confirm applies it. runJudge + readStream are wired to THROW, so a green
    // run proves the confirm path re-derives nothing.
    const runJudge = vi.fn(() => {
      throw new Error('judge must not run on confirm');
    });
    const readStream = vi.fn(() => {
      throw new Error('stream must not be read on confirm');
    });
    const confirmDb = fakeDb();
    const out: string[] = [];
    const code = await runApply({
      argv: ['--confirmed', '--plan', path],
      readStream,
      runJudge,
      openDb: confirmDb.open,
      now: () => 0,
      createdBy: () => 'tester',
      stdout: (s) => out.push(s),
      stderr: vi.fn(),
    });

    expect(code).toBe(0);
    expect(runJudge).not.toHaveBeenCalled();
    expect(readStream).not.toHaveBeenCalled();
    // applied exactly the previewed plan: the full recommended 8-pack (evidence
    // secret->warn, floor for the rest) plus one suppression
    expect(Object.keys(confirmDb.posture)).toHaveLength(8);
    expect(confirmDb.posture.secret).toBe('warn');
    expect(confirmDb.created).toHaveLength(1);
    expect(confirmDb.created[0]).toMatchObject({
      ruleId: 'core-secret/aws',
      category: 'secret',
      valueFingerprint: FP,
      createdVia: 'setup-triage',
      createdBy: 'tester',
    });
    // plan file deleted after a successful apply
    expect(existsSync(path)).toBe(false);
    // The confirm path emits the applying confirmation, threading the
    // real writeback counts: all 8 packs tuned, one routine suppression dismissed.
    const applied = out.join('');
    expect(applied).toContain('✓ 8 categories tuned');
    expect(applied).toContain('✓ 1 routine dismissed');
    expect(applied).toMatch(/Ready:/);
  });
});

describe('runApply — confirm persists the full recommended 8-pack posture', () => {
  it('writes all 8 packs (severity floor overlaid with evidence) and reports "8 categories tuned"', async () => {
    // Evidence action that DIFFERS from the severity floor (secret floors to warn;
    // the judge here says redact) so the overlay precedence is observable end-to-end.
    const v: TriageRecommendation = {
      perCategory: [
        {
          category: 'secret',
          action: 'redact',
          reasoning: 'canonical fake AWS example key',
          genuineCount: 0,
          fpCount: 1,
          fpIds: ['0'],
        },
      ],
      notes: 'looks routine',
    };
    const path = await previewPlan(streamText(), v);
    const confirmDb = fakeDb();
    const out: string[] = [];
    const code = await runApply({
      argv: ['--confirmed', '--plan', path],
      readStream: () => {
        throw new Error('stream must not be read');
      },
      runJudge: () => {
        throw new Error('judge must not run');
      },
      openDb: confirmDb.open,
      now: () => 0,
      createdBy: () => 'tester',
      stdout: (s) => out.push(s),
      stderr: vi.fn(),
    });

    expect(code).toBe(0);
    // The whole 8-pack lands — not just the evidence-derived category. This is
    // the "recommended posture" the user confirmed, persisted verbatim.
    expect(Object.keys(confirmDb.posture).sort()).toEqual([...DetectionCategorySchema.options].sort());
    // Evidence overrides the floor for its category; the floor fills every other pack.
    expect(confirmDb.posture.secret).toBe('redact');
    expect(confirmDb.posture.code_context).toBe('log'); // monitor floor -> log action
    expect(confirmDb.posture.config).toBe('log');
    // The applying-confirmation copy holds end-to-end: all 8 categories tuned, not the survivor subset.
    expect(out.join('')).toContain('✓ 8 categories tuned');
  });
});

// A store whose confirm write is atomic (snapshot/restore transaction) and whose
// exceptions.create can be made to throw on the Nth call — for the rollback +
// double-close tests.
function fakeAtomicDb(opts: { failOnCall?: number } = {}) {
  const posture: Record<string, ActionTaken> = {};
  const created: unknown[] = [];
  let closed = 0;
  let calls = 0;
  const inner = {
    policies: {
      getCategoryAction: (c: DetectionCategory) => posture[c],
      upsertCategoryAction: (c: DetectionCategory, a: ActionTaken) => {
        posture[c] = a;
      },
    },
    exceptions: {
      create: (input: unknown) => {
        calls++;
        if (opts.failOnCall !== undefined && calls === opts.failOnCall) {
          return Promise.reject(new Error('disk full mid-batch'));
        }
        created.push(input);
        return Promise.resolve();
      },
    } as ExceptionWriter,
    transaction: async <T>(fn: () => Promise<T>): Promise<T> => {
      const snapshot = { ...posture };
      const createdMark = created.length;
      try {
        return await fn();
      } catch (err) {
        for (const k of Object.keys(posture)) Reflect.deleteProperty(posture, k);
        Object.assign(posture, snapshot);
        created.length = createdMark;
        throw err;
      }
    },
    close: () => {
      closed++;
    },
  };
  return {
    posture,
    created,
    get closed() {
      return closed;
    },
    open: () => inner,
  };
}

// Run a preview to mint a real plan file, returning its path.
function previewPlan(stream: string, v: TriageRecommendation): Promise<string> {
  const out: string[] = [];
  return runApply({
    argv: [],
    readStream: () => stream,
    runJudge: () => v,
    openDb: fakeDb().open,
    now: () => 0,
    createdBy: () => 'tester',
    stdout: (s) => out.push(s),
    stderr: vi.fn(),
  }).then((code) => {
    expect(code).toBe(0);
    const path = planPathFromStdout(out);
    written.push(path);
    return path;
  });
}

describe('runApply — confirm is atomic and reports what actually persisted', () => {
  it('a post-success plan-file delete throw still reports success (exit 0) and closes once', async () => {
    const path = await previewPlan(streamText(), verdict());
    const db = fakeAtomicDb();
    const code = await runApply({
      argv: ['--confirmed', '--plan', path],
      readStream: vi.fn(),
      runJudge: vi.fn(),
      openDb: db.open,
      now: () => 0,
      createdBy: () => 'tester',
      stdout: vi.fn(),
      stderr: vi.fn(),
      planIO: {
        write: writePlanFile,
        read: readPlanFile,
        delete: () => {
          throw new Error('unlink raced');
        },
      },
    });
    expect(code).toBe(0); // the write persisted; a delete throw must not flip it
    expect(Object.keys(db.posture)).toHaveLength(8); // the full recommended 8-pack landed
    expect(db.posture.secret).toBe('warn');
    expect(db.created).toHaveLength(1);
    expect(db.closed).toBe(1); // closed exactly once, no double-close
  });

  it('a post-success stdout throw still reports success (exit 0) and does not double-close', async () => {
    const path = await previewPlan(streamText(), verdict());
    const db = fakeAtomicDb();
    const code = await runApply({
      argv: ['--confirmed', '--plan', path],
      readStream: vi.fn(),
      runJudge: vi.fn(),
      openDb: db.open,
      now: () => 0,
      createdBy: () => 'tester',
      stdout: () => {
        throw new Error('stdout closed (EPIPE)');
      },
      stderr: vi.fn(),
    });
    expect(code).toBe(0);
    expect(Object.keys(db.posture)).toHaveLength(8); // the full recommended 8-pack landed
    expect(db.posture.secret).toBe('warn');
    expect(db.closed).toBe(1);
  });

  it('a mid-batch suppression failure rolls back the posture too and reports failure', async () => {
    // Two entries; the second create throws. The transaction must undo the
    // posture overwrite and the first insert — no partial state, exit 1.
    const stream =
      JSON.stringify(hit({ id: '0' })) +
      '\n' +
      JSON.stringify(hit({ id: '1', valueFingerprint: 'cd'.repeat(32) })) +
      '\n' +
      JSON.stringify({ done: true, count: 2, status: 'complete' }) +
      '\n';
    const v = {
      perCategory: [
        {
          category: 'secret' as const,
          action: 'redact' as const,
          reasoning: 'canonical fake AWS example key',
          genuineCount: 0,
          fpCount: 2,
          fpIds: ['0', '1'],
        },
      ],
      notes: 'looks routine',
    };
    const path = await previewPlan(stream, v);
    const db = fakeAtomicDb({ failOnCall: 2 });
    const err: string[] = [];
    const code = await runApply({
      argv: ['--confirmed', '--plan', path],
      readStream: vi.fn(),
      runJudge: vi.fn(),
      openDb: db.open,
      now: () => 0,
      createdBy: () => 'tester',
      stdout: vi.fn(),
      stderr: (s) => err.push(s),
    });
    expect(code).toBe(1);
    // rolled back: no posture, no surviving exception row
    expect(db.posture).toEqual({});
    expect(db.created).toEqual([]);
    expect(db.closed).toBe(1);
    expect(err.join('')).toMatch(/failed/i);
  });
});

describe('runApply — confirm rejects a plan stale against the current store (drift gate)', () => {
  const previewWith = async (posture: Record<string, ActionTaken>): Promise<string> => {
    const db = fakeDb();
    Object.assign(db.posture, posture);
    const out: string[] = [];
    await runApply({
      argv: [],
      readStream: () => streamText(),
      runJudge: () => verdict(),
      openDb: db.open,
      now: () => 0,
      createdBy: () => 'tester',
      stdout: (s) => out.push(s),
      stderr: vi.fn(),
    });
    const path = planPathFromStdout(out);
    written.push(path);
    return path;
  };

  it('exits non-zero and writes NOTHING when a planned category drifted since preview', async () => {
    // Preview snapshots `secret: block`; between preview and confirm the store
    // changes it to `redact` (a CLI/web-ui edit) — applying the stale plan would
    // silently act against a store the user never reviewed.
    const path = await previewWith({ secret: 'block' });
    const confirmDb = fakeDb();
    confirmDb.posture.secret = 'redact';
    const err: string[] = [];
    const code = await runApply({
      argv: ['--confirmed', '--plan', path],
      readStream: () => {
        throw new Error('stream must not be read');
      },
      runJudge: () => {
        throw new Error('judge must not run');
      },
      openDb: confirmDb.open,
      now: () => 0,
      createdBy: () => 'tester',
      stdout: vi.fn(),
      stderr: (s) => err.push(s),
    });
    expect(code).toBe(1);
    expect(err.join('')).toMatch(/store changed/i);
    expect(err.join('')).toContain('secret');
    // fail loud, NO write, handle closed exactly once
    expect(confirmDb.posture).toEqual({ secret: 'redact' });
    expect(confirmDb.created).toEqual([]);
    expect(confirmDb.closed).toBe(1);
  });

  it('applies the plan when the store still matches the preview snapshot', async () => {
    const path = await previewWith({ secret: 'block' });
    const confirmDb = fakeDb();
    confirmDb.posture.secret = 'block'; // unchanged since preview
    const out: string[] = [];
    const code = await runApply({
      argv: ['--confirmed', '--plan', path],
      readStream: () => {
        throw new Error('stream must not be read');
      },
      runJudge: () => {
        throw new Error('judge must not run');
      },
      openDb: confirmDb.open,
      now: () => 0,
      createdBy: () => 'tester',
      stdout: (s) => out.push(s),
      stderr: vi.fn(),
    });
    expect(code).toBe(0);
    // The applying confirmation on the real confirm path: all 8 packs tuned, one
    // routine suppression dismissed.
    expect(out.join('')).toContain('✓ 8 categories tuned');
    expect(out.join('')).toContain('✓ 1 routine dismissed');
    // no drift → the write proceeded: one suppression row AND the full 8-pack
    // posture overwrite (the evidence category kept its judged action)
    expect(confirmDb.created).toHaveLength(1);
    expect(Object.keys(confirmDb.posture)).toHaveLength(8);
    expect(confirmDb.posture.secret).toBe('warn');
  });

  it('never downgrades a pre-existing stronger posture on an UNREVIEWED floor pack', async () => {
    // The judge only produces `secret` evidence, so `code_context` is a floor pack
    // the wizard never reviewed and the drift gate never checks. The user had
    // already hardened it to `block` out-of-band. Establishing the full 8-pack must
    // NOT reset that stronger setting to the weak severity floor — the floor packs
    // fill gaps only. (The preview shows a recommended posture for all 8, but the
    // confirm write overwrites only the reviewed evidence and fills gaps for the rest.)
    const path = await previewWith({ code_context: 'block' });
    const confirmDb = fakeDb();
    confirmDb.posture.code_context = 'block'; // still hardened at confirm — no drift
    const out: string[] = [];
    const code = await runApply({
      argv: ['--confirmed', '--plan', path],
      readStream: () => {
        throw new Error('stream must not be read');
      },
      runJudge: () => {
        throw new Error('judge must not run');
      },
      openDb: confirmDb.open,
      now: () => 0,
      createdBy: () => 'tester',
      stdout: (s) => out.push(s),
      stderr: vi.fn(),
    });
    expect(code).toBe(0);
    // The hardened floor pack is PRESERVED, not silently reset to the floor.
    expect(confirmDb.posture.code_context).toBe('block');
    // The reviewed evidence pack took its judged action; the rest sit at the floor.
    expect(confirmDb.posture.secret).toBe('warn');
    // All 8 packs hold a posture and the tuned count stays honest.
    expect(Object.keys(confirmDb.posture)).toHaveLength(8);
    expect(out.join('')).toContain('✓ 8 categories tuned');
  });

  it('treats a category ADDED to the store since preview as drift (undefined → value)', async () => {
    // Preview saw NO row for `secret` (plan.current omits it); by confirm a row
    // exists. This is the asymmetric case: current[secret] is undefined, the store
    // now returns a value — it must count as drift, not be silently overwritten.
    const path = await previewWith({});
    const confirmDb = fakeDb();
    confirmDb.posture.secret = 'block'; // row added after preview
    const err: string[] = [];
    const code = await runApply({
      argv: ['--confirmed', '--plan', path],
      readStream: () => {
        throw new Error('stream must not be read');
      },
      runJudge: () => {
        throw new Error('judge must not run');
      },
      openDb: confirmDb.open,
      now: () => 0,
      createdBy: () => 'tester',
      stdout: vi.fn(),
      stderr: (s) => err.push(s),
    });
    expect(code).toBe(1);
    expect(err.join('')).toMatch(/store changed/i);
    expect(confirmDb.created).toEqual([]);
    expect(confirmDb.posture).toEqual({ secret: 'block' }); // untouched
  });

  it('fails loud (no write) if the drift read itself throws', async () => {
    const path = await previewWith({ secret: 'block' });
    // A store whose getCategoryAction throws — the drift gate must fail closed,
    // not fall through to the write.
    const created: unknown[] = [];
    let closed = 0;
    const code = await runApply({
      argv: ['--confirmed', '--plan', path],
      readStream: () => {
        throw new Error('stream must not be read');
      },
      runJudge: () => {
        throw new Error('judge must not run');
      },
      openDb: () => ({
        policies: {
          getCategoryAction: () => {
            throw new Error('db read blew up');
          },
          upsertCategoryAction: () => {
            created.push('posture');
          },
        },
        exceptions: {
          create: () => {
            created.push('exception');
            return Promise.resolve();
          },
        },
        close: () => {
          closed++;
        },
      }),
      now: () => 0,
      createdBy: () => 'tester',
      stdout: vi.fn(),
      stderr: vi.fn(),
    });
    expect(code).toBe(1);
    expect(created).toEqual([]);
    expect(closed).toBe(1);
  });
});

describe('runApply — confirm fails loud on a bad --plan', () => {
  it('exits non-zero and writes nothing when --plan is missing', async () => {
    const db = fakeDb();
    const err: string[] = [];
    const runJudge = vi.fn(() => verdict());
    const code = await runApply({
      argv: ['--confirmed'],
      readStream: () => streamText(),
      runJudge,
      openDb: db.open,
      now: () => 0,
      createdBy: () => 'tester',
      stdout: vi.fn(),
      stderr: (s) => err.push(s),
    });
    expect(code).toBe(1);
    expect(err.join('')).toMatch(/--plan/);
    // never fell back to re-judging, never wrote
    expect(runJudge).not.toHaveBeenCalled();
    expect(db.posture).toEqual({});
    expect(db.created).toEqual([]);
  });

  it('exits non-zero and writes nothing when --plan points at a missing file', async () => {
    const db = fakeDb();
    const err: string[] = [];
    const code = await runApply({
      argv: ['--confirmed', '--plan', '/no/such/aka-plan-xyz.json'],
      readStream: () => streamText(),
      runJudge: () => verdict(),
      openDb: db.open,
      now: () => 0,
      createdBy: () => 'tester',
      stdout: vi.fn(),
      stderr: (s) => err.push(s),
    });
    expect(code).toBe(1);
    expect(err.join('')).toMatch(/plan file/i);
    expect(db.posture).toEqual({});
    expect(db.created).toEqual([]);
  });
});

describe('runApply — preview emits the calibration frame JSON alongside the human gate', () => {
  // A verdict with a surfaced (genuine) count so `important` is provably non-zero
  // and tracks it, not just the suppressed FPs.
  const genuineVerdict = (): TriageRecommendation => ({
    perCategory: [
      {
        category: 'secret',
        action: 'warn',
        reasoning: 'canonical fake AWS example key',
        genuineCount: 2,
        fpCount: 1,
        fpIds: ['0'],
      },
    ],
    notes: 'looks routine',
  });

  it('emits a valid CalibrationFrame whose counts come from the plan (genuine vs suppressed)', async () => {
    const db = fakeDb();
    const out: string[] = [];
    const code = await runApply({
      argv: [],
      readStream: () => streamText(),
      runJudge: () => genuineVerdict(),
      openDb: db.open,
      now: () => 0,
      createdBy: () => 'tester',
      stdout: (s) => out.push(s),
      stderr: vi.fn(),
    });
    expect(code).toBe(0);
    const blob = out.join('');

    // Additive: the human gate render is still present (not replaced).
    expect(blob).toContain('false-positive');

    // The calibrated-result card the wizard leads with: the real-count
    // headline over this run's genuine/suppressed split, then the condensed
    // one-row-per-pack recommended posture.
    expect(blob).toContain('Calibrated. 3 notifications, 2 important.');
    expect(blob).toMatch(/secret\s+warn/);

    const frame = readFrameJsonBlock(blob);
    const parsed = CalibrationFrame.safeParse(frame);
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;

    // important = surfaced (genuine) count, routine = suppressed (fp) count.
    expect(parsed.data.counts).toEqual({ total: 3, important: 2, routine: 1 });
    expect(parsed.data.surfacedCategories).toEqual(['secret']);
    expect(parsed.data.routineCategories).toEqual(['secret']);
    // The retroactive scan reads at-rest history, so every kind is at-rest.
    expect(parsed.data.findingKinds).toContainEqual({
      category: 'secret',
      count: 3,
      egress: false,
    });
    // The posture map is the full recommended view (all 8 packs), with the
    // evidence-derived action overriding secret.
    expect(Object.keys(parsed.data.posture).sort()).toEqual(
      [...DetectionCategorySchema.options].sort(),
    );
    expect(parsed.data.posture.secret).toBe('warn');
  });

  it('carries no raw detected value into the frame JSON (masked/enum/count only)', async () => {
    const db = fakeDb();
    const out: string[] = [];
    await runApply({
      argv: [],
      readStream: () => streamText(),
      runJudge: () => genuineVerdict(),
      openDb: db.open,
      now: () => 0,
      createdBy: () => 'tester',
      stdout: (s) => out.push(s),
      stderr: vi.fn(),
    });
    const blob = out.join('');
    // The frame block itself never echoes the raw hit value.
    expect(blob).toContain('<<<AKA_FRAME_JSON');
    expect(JSON.stringify(readFrameJsonBlock(blob))).not.toContain(RAW);
  });
});

describe('runApply — preview degrades fail-open when the local store is unreadable', () => {
  it('substitutes the store-unavailable note instead of throwing, and never fabricates a count', async () => {
    const out: string[] = [];
    let code: number | undefined;
    let threw: unknown;
    try {
      code = await runApply({
        argv: [],
        readStream: () => streamText(),
        runJudge: () => verdict(),
        // A store that cannot be opened mid-preview (missing / corrupt / locked db):
        // the calibration step's only store read is the current-posture downgrade
        // view, and it must degrade rather than break the wizard.
        openDb: () => {
          throw new Error('SQLITE_CANTOPEN: unable to open database file');
        },
        now: () => 0,
        createdBy: () => 'tester',
        stdout: (s) => out.push(s),
        stderr: vi.fn(),
      });
    } catch (e) {
      threw = e;
    }
    const blob = out.join('');

    // Fail-open: no thrown error escaped the calibration preview, and it completed.
    expect(threw).toBeUndefined();
    expect(code).toBe(0);

    // The honest store-unavailable note stands in for the store-derived downgrade
    // comparison — the store-read-failure path, not the found-nothing/empty copy.
    expect(blob).toContain("I couldn't read the local store");

    // The real calibration count (from the scan/plan, not the store) still renders —
    // a store-read failure never fabricates or zeroes the calibrated headline.
    expect(blob).toContain('Calibrated. 1 notifications');
  });
});
