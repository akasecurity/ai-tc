import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { reconcileSessionTail } = vi.hoisted(() => ({
  reconcileSessionTail: vi.fn(() => Promise.resolve({ llmCalls: 0, skipped: 0, toolCalls: 0 })),
}));
vi.mock('../../src/history/usage.ts', () => ({ reconcileSessionTail }));

import { runReconcileWorker } from '../../src/history/reconcile-worker.ts';

const CONFIG = { dataDir: '/data' } as PluginConfig;
const NOW = 1_700_000_000_000;

describe('runReconcileWorker', () => {
  const sleep = vi.fn<(ms: number) => Promise<void>>(() => Promise.resolve());
  const run = (args: readonly string[]) =>
    runReconcileWorker(args, { sleep, now: () => NOW, config: () => CONFIG });

  beforeEach(() => {
    reconcileSessionTail.mockClear();
    sleep.mockClear();
  });

  it('runs one pass at once for a session and a transcript', async () => {
    await run(['sess-A', '/t/a.jsonl']);
    expect(sleep).not.toHaveBeenCalled();
    expect(reconcileSessionTail).toHaveBeenCalledTimes(1);
    expect(reconcileSessionTail).toHaveBeenCalledWith(
      CONFIG,
      'sess-A',
      '/t/a.jsonl',
      expect.any(Function),
    );
  });

  it.each([[[]], [['sess-A']], [['', '/t/a.jsonl']], [['sess-A', '']]])(
    'runs no pass without both a session and a transcript (%j)',
    async (args) => {
      await run(args);
      expect(reconcileSessionTail).not.toHaveBeenCalled();
      expect(sleep).not.toHaveBeenCalled();
    },
  );

  it('waits until the due time it is given, then runs the pass as that follow-up', async () => {
    const order: string[] = [];
    sleep.mockImplementationOnce(() => {
      order.push('slept');
      return Promise.resolve();
    });
    reconcileSessionTail.mockImplementationOnce(() => {
      order.push('ran');
      return Promise.resolve({ llmCalls: 0, skipped: 0, toolCalls: 0 });
    });
    await run(['sess-A', '/t/a.jsonl', String(NOW + 120_000)]);
    expect(sleep).toHaveBeenCalledWith(120_000);
    expect(order).toEqual(['slept', 'ran']);
    expect(reconcileSessionTail).toHaveBeenCalledWith(
      CONFIG,
      'sess-A',
      '/t/a.jsonl',
      expect.any(Function),
      NOW + 120_000,
    );
  });

  it('waits until the window closes for a trailing pass, then runs a pass that is the follow-up of no hold', async () => {
    const order: string[] = [];
    sleep.mockImplementationOnce(() => {
      order.push('slept');
      return Promise.resolve();
    });
    reconcileSessionTail.mockImplementationOnce(() => {
      order.push('ran');
      return Promise.resolve({ llmCalls: 0, skipped: 0, toolCalls: 0 });
    });
    await run(['sess-A', '/t/a.jsonl', String(NOW + 20_000), 'trailing']);
    expect(sleep).toHaveBeenCalledWith(20_000);
    expect(order).toEqual(['slept', 'ran']);
    expect(reconcileSessionTail).toHaveBeenCalledTimes(1);
    // Four arguments: a fifth would name a follow-up due time, and a pass given
    // one does nothing unless a hold asked for it.
    expect(reconcileSessionTail.mock.calls[0]).toHaveLength(4);
    expect(reconcileSessionTail).toHaveBeenCalledWith(
      CONFIG,
      'sess-A',
      '/t/a.jsonl',
      expect.any(Function),
    );
  });

  it('runs a trailing pass at once when its window has already closed', async () => {
    await run(['sess-A', '/t/a.jsonl', String(NOW - 5_000), 'trailing']);
    expect(sleep).toHaveBeenCalledWith(0);
    expect(reconcileSessionTail).toHaveBeenCalledTimes(1);
  });

  it.each([['follow-up'], [''], ['TRAILING']])(
    'runs no pass for a fourth argument that is not "trailing" (%j)',
    async (mode) => {
      await run(['sess-A', '/t/a.jsonl', String(NOW + 1_000), mode]);
      expect(reconcileSessionTail).not.toHaveBeenCalled();
      expect(sleep).not.toHaveBeenCalled();
    },
  );

  it('does not wait for a due time that has passed, and still runs the pass', async () => {
    await run(['sess-A', '/t/a.jsonl', String(NOW - 5_000)]);
    expect(sleep).toHaveBeenCalledWith(0);
    expect(reconcileSessionTail).toHaveBeenCalledTimes(1);
  });

  it.each([['abc'], ['-1'], ['1.5'], [''], ['Infinity'], ['1e3x']])(
    'runs no pass for a due time that is not a whole number of milliseconds (%j)',
    async (due) => {
      await run(['sess-A', '/t/a.jsonl', due]);
      expect(reconcileSessionTail).not.toHaveBeenCalled();
      expect(sleep).not.toHaveBeenCalled();
    },
  );
});
