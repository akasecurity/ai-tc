import { existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';

import { type ExceptionWriter, safeMaskedMatch } from '@akasecurity/plugin-sdk';
import type {
  ActionTaken,
  DetectionCategory,
  TriageHit,
  TriageRecommendation,
} from '@akasecurity/schema';
import {
  CalibrationFrame,
  DetectionCategory as DetectionCategorySchema,
} from '@akasecurity/schema';
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

describe('runApply — preview renders the honest empty state on a clean scan', () => {
  it('prints the scan-ran-clean copy and a zero-count frame when the scan completes with no hits', async () => {
    const db = fakeDb();
    const out: string[] = [];
    const code = await runApply({
      argv: [],
      readStream: () => `${JSON.stringify({ done: true, count: 0, status: 'complete' })}\n`,
      runJudge: () => verdict(),
      openDb: db.open,
      now: () => 0,
      createdBy: () => 'tester',
      stdout: (s) => out.push(s),
      stderr: vi.fn(),
    });
    expect(code).toBe(0);
    const blob = out.join('');
    // The honest scan-ran-clean empty state, not the bare "No triage hits" line.
    expect(blob).toContain('nothing needs your attention');
    expect(blob).not.toContain('No triage hits to review');
    // A zero-count CalibrationFrame is still emitted for downstream consumers.
    const frame = CalibrationFrame.parse(readFrameJsonBlock(blob));
    expect(frame.counts).toEqual({ total: 0, important: 0, routine: 0 });
    // Preview stays read-only: no posture upsert, no exception created.
    expect(db.posture).toEqual({});
    expect(db.created).toEqual([]);
  });
});

describe('runApply — preview renders the no-history empty state on an empty-history scan', () => {
  it('prints the no-history copy and a zero-count frame when the scan completes over no history', async () => {
    const db = fakeDb();
    const out: string[] = [];
    const code = await runApply({
      argv: [],
      readStream: () =>
        `${JSON.stringify({ done: true, count: 0, status: 'complete:no-history' })}\n`,
      runJudge: () => verdict(),
      openDb: db.open,
      now: () => 0,
      createdBy: () => 'tester',
      stdout: (s) => out.push(s),
      stderr: vi.fn(),
    });
    expect(code).toBe(0);
    const blob = out.join('');
    // The honest no-history empty state, distinct from the scan-clean copy.
    expect(blob).toContain('Nothing to learn from yet');
    expect(blob).not.toContain('nothing needs your attention');
    expect(blob).not.toContain('No triage hits to review');
    // A zero-count CalibrationFrame is still emitted for downstream consumers.
    const frame = CalibrationFrame.parse(readFrameJsonBlock(blob));
    expect(frame.counts).toEqual({ total: 0, important: 0, routine: 0 });
    // Preview stays read-only: no posture upsert, no exception created.
    expect(db.posture).toEqual({});
    expect(db.created).toEqual([]);
  });
});

describe('runApply — preview renders the skipped-scan copy when triage was skipped', () => {
  it('prints the warm empty-review copy and drops the internal status token', async () => {
    const db = fakeDb();
    const out: string[] = [];
    const code = await runApply({
      argv: [],
      readStream: () =>
        `${JSON.stringify({ done: true, count: 0, status: 'skipped:no-consent' })}\n`,
      runJudge: () => verdict(),
      openDb: db.open,
      now: () => 0,
      createdBy: () => 'tester',
      stdout: (s) => out.push(s),
      stderr: vi.fn(),
    });
    expect(code).toBe(0);
    const blob = out.join('');
    expect(blob).toContain("I didn't find anything to review — nothing to tune.");
    // The internal status token never reaches user-facing copy.
    expect(blob).not.toContain('skipped:no-consent');
    expect(blob).not.toContain('No triage hits to review');
    // Preview stays read-only: no posture upsert, no exception created.
    expect(db.posture).toEqual({});
    expect(db.created).toEqual([]);
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
    // real writeback counts: all 8 detection categories set, one routine
    // suppression set aside.
    const applied = out.join('');
    expect(applied).toContain('✓ Set all 8 detection categories');
    expect(applied).toContain('set aside 1 routine result');
    expect(applied).toMatch(/Ready:/);
  });
});

describe('runApply — confirm persists the full recommended 8-pack posture', () => {
  it('writes all 8 packs (severity floor overlaid with evidence) and reports "Set all 8 detection categories"', async () => {
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
    expect(Object.keys(confirmDb.posture).sort()).toEqual(
      [...DetectionCategorySchema.options].sort(),
    );
    // Evidence overrides the floor for its category; the floor fills every other pack.
    expect(confirmDb.posture.secret).toBe('redact');
    expect(confirmDb.posture.code_context).toBe('log'); // monitor floor -> log action
    expect(confirmDb.posture.config).toBe('log');
    // The applying-confirmation copy holds end-to-end: all 8 detection categories set, not the survivor subset.
    expect(out.join('')).toContain('✓ Set all 8 detection categories');
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
    // The applying confirmation on the real confirm path: all 8 detection
    // categories set, one routine result set aside.
    expect(out.join('')).toContain('✓ Set all 8 detection categories');
    expect(out.join('')).toContain('set aside 1 routine result');
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
    expect(out.join('')).toContain('✓ Set all 8 detection categories');
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
    expect(blob).toContain(
      "I went through Claude's recent work — 3 detections, 2 results worth a look.",
    );
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

describe('runApply — preview derives surfaced secret findings into the frame', () => {
  // A verdict that keeps the secret hit GENUINE (not a false positive), so the
  // hit surfaces as a MaskedSecretFinding instead of being suppressed.
  const surfacedVerdict = (): TriageRecommendation => ({
    perCategory: [
      {
        category: 'secret',
        action: 'warn',
        reasoning: 'a genuine live key in an old transcript',
        genuineCount: 1,
        fpCount: 0,
        fpIds: [],
      },
    ],
    notes: 'looks routine',
  });

  const previewFrame = async (h: TriageHit, v = surfacedVerdict()) => {
    const db = fakeDb();
    const out: string[] = [];
    const code = await runApply({
      argv: [],
      readStream: () =>
        `${JSON.stringify(h)}\n${JSON.stringify({ done: true, count: 1, status: 'complete' })}\n`,
      runJudge: () => v,
      openDb: db.open,
      now: () => 0,
      createdBy: () => 'tester',
      stdout: (s) => out.push(s),
      stderr: vi.fn(),
    });
    expect(code).toBe(0);
    const blob = out.join('');
    const parsed = CalibrationFrame.safeParse(readFrameJsonBlock(blob));
    if (!parsed.success) throw new Error('emitted frame did not validate');
    return { frame: parsed.data, blob };
  };

  it('emits the genuine secret leak as a masked per-finding summary the finding table reads', async () => {
    const { frame } = await previewFrame(
      hit({ id: '0', filePath: '~/.claude/transcripts/2026-07-01.jsonl' }),
    );
    // The frame the loader reads carries the REAL surfaced secret summary, derived
    // from the hit — provider from the ruleId, masked token, where-found, and the
    // honest 'unknown' validity state (no network to check a key on this machine).
    expect(frame.maskedFindings).toEqual([
      {
        provider: 'aws',
        maskedToken: safeMaskedMatch(RAW),
        where: { filePath: '~/.claude/transcripts/2026-07-01.jsonl' },
        state: 'unknown',
      },
    ]);
  });

  it('derives the summary from the hit, never a hardcoded value', async () => {
    const a = await previewFrame(
      hit({ id: '0', ruleId: 'secrets/stripe-live-key', filePath: '/tmp/a.txt' }),
    );
    expect(a.frame.maskedFindings?.[0]).toMatchObject({
      provider: 'stripe',
      where: { filePath: '/tmp/a.txt' },
    });
    // Change the input hit ⇒ the emitted summary follows it (no hardcode).
    const b = await previewFrame(
      hit({ id: '0', ruleId: 'secrets/github-pat', filePath: '/tmp/b.txt' }),
    );
    expect(b.frame.maskedFindings?.[0]).toMatchObject({
      provider: 'github',
      where: { filePath: '/tmp/b.txt' },
    });
  });

  it('omits maskedFindings when the secret hit was suppressed as a false positive', async () => {
    const suppressed = (): TriageRecommendation => ({
      perCategory: [
        {
          category: 'secret',
          action: 'warn',
          reasoning: 'canonical fake AWS example key',
          genuineCount: 0,
          fpCount: 1,
          fpIds: ['0'],
        },
      ],
      notes: 'looks routine',
    });
    const { frame } = await previewFrame(hit({ id: '0' }), suppressed());
    // Nothing genuine surfaced ⇒ the optional field is omitted, not an empty theatre.
    expect(frame.maskedFindings).toBeUndefined();
  });

  it('carries no raw secret value into the emitted summaries (masked only)', async () => {
    const { frame } = await previewFrame(
      hit({ id: '0', filePath: '~/.claude/transcripts/2026-07-01.jsonl' }),
    );
    expect(JSON.stringify(frame.maskedFindings)).not.toContain(RAW);
  });

  it('surfaces only the genuine hit on a mixed stream — the FP stays dismissed and counts stay coherent', async () => {
    // Two hits over the real preview seam: one genuine, one model-dismissed FP.
    // The emitted frame must surface exactly the genuine hit and its maskedFindings
    // length must equal the frame's important (genuine) count — no dismissed example
    // key smuggled into the finding table, no count/finding divergence.
    // Assembled at runtime so the source carries no contiguous key-shaped literal.
    const OTHER = ['sk', 'live', '51H8xEXAMPLErawstripesecretVALUE0000'].join('_');
    const genuine = hit({
      id: '0',
      ruleId: 'secrets/stripe-live-key',
      rawMatch: OTHER,
      context: `token=${OTHER}`,
      valueFingerprint: 'cd'.repeat(32),
      filePath: '~/.claude/transcripts/2026-07-01.jsonl',
    });
    const falsePositive = hit({ id: '1', filePath: '/tmp/agent-dump.txt' });
    const db = fakeDb();
    const out: string[] = [];
    const code = await runApply({
      argv: [],
      readStream: () =>
        `${JSON.stringify(genuine)}\n${JSON.stringify(falsePositive)}\n${JSON.stringify({ done: true, count: 2, status: 'complete' })}\n`,
      runJudge: (): TriageRecommendation => ({
        perCategory: [
          {
            category: 'secret',
            action: 'warn',
            reasoning: 'one genuine live key, one canonical fake AWS example key',
            genuineCount: 1,
            fpCount: 1,
            fpIds: ['1'],
          },
        ],
        notes: 'looks routine',
      }),
      openDb: db.open,
      now: () => 0,
      createdBy: () => 'tester',
      stdout: (s) => out.push(s),
      stderr: vi.fn(),
    });
    expect(code).toBe(0);
    const parsed = CalibrationFrame.safeParse(readFrameJsonBlock(out.join('')));
    if (!parsed.success) throw new Error('emitted frame did not validate');
    const frame = parsed.data;
    // Exactly the genuine hit surfaces — the dismissed example key never does.
    expect(frame.maskedFindings).toEqual([
      {
        provider: 'stripe',
        maskedToken: safeMaskedMatch(OTHER),
        where: { filePath: '~/.claude/transcripts/2026-07-01.jsonl' },
        state: 'unknown',
      },
    ]);
    // The remediation count and the frame's important (genuine) count agree.
    expect(frame.maskedFindings).toHaveLength(frame.counts.important);
    // No raw value from either hit rides into the emitted summaries.
    expect(JSON.stringify(frame.maskedFindings)).not.toContain(RAW);
    expect(JSON.stringify(frame.maskedFindings)).not.toContain(OTHER);
  });
});

describe('runApply — preview derives the masked false-positive pattern signal into the frame', () => {
  it('carries the masked FP-pattern group when a hit is marked a false positive', async () => {
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
    const parsed = CalibrationFrame.safeParse(readFrameJsonBlock(out.join('')));
    if (!parsed.success) throw new Error('emitted frame did not validate');
    const frame = parsed.data;
    // The group's pattern is re-derived from the raw value (never the streamed
    // maskedMatch), and it carries the marked hit's exact value identity so a
    // later exception offer can key its written grant on it.
    expect(frame.falsePositivePatterns).toEqual([
      {
        pattern: safeMaskedMatch(RAW),
        count: 1,
        values: [
          { ruleId: 'core-secret/aws', category: 'secret', valueFingerprint: FP, keyVersion: 1 },
        ],
      },
    ]);
    expect(JSON.stringify(frame.falsePositivePatterns)).not.toContain(RAW);
  });

  it('omits falsePositivePatterns when nothing was marked a false positive', async () => {
    const surfacedVerdict = (): TriageRecommendation => ({
      perCategory: [
        {
          category: 'secret',
          action: 'warn',
          reasoning: 'a genuine live key in an old transcript',
          genuineCount: 1,
          fpCount: 0,
          fpIds: [],
        },
      ],
      notes: 'looks routine',
    });
    const db = fakeDb();
    const out: string[] = [];
    const code = await runApply({
      argv: [],
      readStream: () => streamText(),
      runJudge: () => surfacedVerdict(),
      openDb: db.open,
      now: () => 0,
      createdBy: () => 'tester',
      stdout: (s) => out.push(s),
      stderr: vi.fn(),
    });
    expect(code).toBe(0);
    const parsed = CalibrationFrame.safeParse(readFrameJsonBlock(out.join('')));
    if (!parsed.success) throw new Error('emitted frame did not validate');
    // Fail-open: the optional field is entirely absent, not an empty array.
    expect(parsed.data.falsePositivePatterns).toBeUndefined();
    const emitted = readFrameJsonBlock(out.join('')) as Record<string, unknown>;
    expect('falsePositivePatterns' in emitted).toBe(false);
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
    expect(blob).toContain("I couldn't check my records just now");

    // The real calibration count (from the scan/plan, not the store) still renders —
    // a store-read failure never fabricates or zeroes the calibrated headline.
    expect(blob).toContain("I went through Claude's recent work — 1 detection,");
  });
});

describe('runApply — dedups repeated hits before the judge and before the writeback plan', () => {
  it('feeds the judge and the plan/frame derivations the SAME deduped representative set', async () => {
    const FP1 = 'ab'.repeat(32);
    const FP2 = 'cd'.repeat(32);
    const OTHER = ['sk', 'live', '51H8xEXAMPLErawstripesecretVALUE0000'].join('_');

    // Three occurrences of the SAME value (fp1) plus one distinct value (fp2).
    const dup = (id: string, tag: string): TriageHit =>
      hit({ id, valueFingerprint: FP1, rawMatch: RAW, context: `export KEY=${RAW} ${tag}` });
    const h0 = dup('0', 'first');
    const h1 = dup('1', 'second');
    const h2 = dup('2', 'third');
    const h3 = hit({
      id: '3',
      ruleId: 'secrets/stripe-live-key',
      valueFingerprint: FP2,
      rawMatch: OTHER,
      context: `token=${OTHER}`,
    });
    const stream =
      [h0, h1, h2, h3].map((h) => JSON.stringify(h)).join('\n') +
      '\n' +
      JSON.stringify({ done: true, count: 4, status: 'complete' }) +
      '\n';

    // Echoes how many hits it saw, and dismisses only id '0' as a false positive —
    // so if dedup did NOT happen, the duplicate occurrences h1/h2 (never listed in
    // fpIds) would wrongly surface as extra "genuine" findings alongside h3.
    const runJudge = vi.fn((hits: readonly TriageHit[]): TriageRecommendation => ({
      perCategory: [
        {
          category: 'secret',
          action: 'warn',
          reasoning: 'one dismissed as a duplicate example value',
          genuineCount: hits.length - 1,
          fpCount: 1,
          fpIds: ['0'],
        },
      ],
      notes: 'looks routine',
    }));

    const db = fakeDb();
    const out: string[] = [];
    const code = await runApply({
      argv: [],
      readStream: () => stream,
      runJudge,
      openDb: db.open,
      now: () => 0,
      createdBy: () => 'tester',
      stdout: (s) => out.push(s),
      stderr: vi.fn(),
    });
    expect(code).toBe(0);

    // The judge saw the deduped representative set (2), not all 4 raw occurrences.
    expect(runJudge).toHaveBeenCalledTimes(1);
    const [call] = runJudge.mock.calls;
    if (call === undefined) throw new Error('runJudge was not called');
    const [seenByJudge] = call;
    expect(seenByJudge).toHaveLength(2);
    expect(seenByJudge.map((h) => h.id)).toEqual(['0', '3']);

    // The writeback plan / calibration derivations were fed the SAME representative
    // set: only h3 is genuine (h0 was dismissed) — the duplicate occurrences h1/h2
    // must not reappear as extra surfaced findings.
    const parsed = CalibrationFrame.safeParse(readFrameJsonBlock(out.join('')));
    if (!parsed.success) throw new Error('emitted frame did not validate');
    expect(parsed.data.maskedFindings).toHaveLength(1);
    expect(parsed.data.maskedFindings?.[0]?.maskedToken).toBe(safeMaskedMatch(OTHER));
  });
});
