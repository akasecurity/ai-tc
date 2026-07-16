import { existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';

import type { ExceptionWriter } from '@akasecurity/plugin-sdk';
import type {
  ActionTaken,
  DetectionCategory,
  TriageHit,
  TriageRecommendation,
} from '@akasecurity/schema';
import { afterEach, describe, expect, it, vi } from 'vitest';

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
    // applied exactly the previewed plan: posture secret->warn, one suppression
    expect(confirmDb.posture).toEqual({ secret: 'warn' });
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
    expect(out.join('')).toMatch(/suppressions applied/i);
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
    expect(db.posture).toEqual({ secret: 'warn' });
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
    expect(db.posture).toEqual({ secret: 'warn' });
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
    expect(out.join('')).toMatch(/applied/i);
    // no drift → the write proceeded: one suppression row AND the posture overwrite
    expect(confirmDb.created).toHaveLength(1);
    expect(confirmDb.posture).toEqual({ secret: 'warn' });
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
