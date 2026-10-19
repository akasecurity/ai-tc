import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { runAttachedSync } from '../../src/attached/sync-entry.ts';

// The order of the sync child's jobs, each replaced by a recorder: the policy
// pull, then the identity refresh, then the command channel, and no refresh
// after the deployment refused the key.
const order = vi.hoisted(
  (): { calls: string[]; policy: string | null; refreshThrows: boolean } => ({
    calls: [],
    policy: 'ok',
    refreshThrows: false,
  }),
);

vi.mock('../../src/attached/policy-sync.ts', () => ({
  runPolicySync: () => {
    order.calls.push('policy');
    return Promise.resolve(order.policy === null ? null : { outcome: order.policy });
  },
}));
vi.mock('../../src/attached/sync-state.ts', () => ({ writeSyncState: () => undefined }));
vi.mock('../../src/attached/identity-refresh.ts', () => ({
  refreshAttachedIdentity: () => {
    order.calls.push('identity');
    return order.refreshThrows
      ? Promise.reject(new Error('refresh failed'))
      : Promise.resolve('skipped');
  },
}));
vi.mock('../../src/attached/sighting-key-sync.ts', () => ({
  runSightingKeySync: () => Promise.resolve(null),
}));
vi.mock('../../src/attached/command-sync.ts', () => ({
  runCommandSync: () => {
    order.calls.push('commands');
    return Promise.resolve(null);
  },
}));

let base: string;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-sync-entry-identity-'));
  order.calls = [];
  order.policy = 'ok';
  order.refreshThrows = false;
});

afterEach(() => {
  removeTree(base);
});

describe('runAttachedSync — the identity refresh', () => {
  it('asks who attached the machine after the policy pull and before the command channel', async () => {
    await runAttachedSync(base);
    expect(order.calls).toEqual(['policy', 'identity', 'commands']);
  });

  it('never asks after the deployment refused the key', async () => {
    order.policy = 'unauthorized';
    await runAttachedSync(base);
    expect(order.calls).toEqual(['policy']);
  });

  it.each(['forbidden', 'unreachable', null])(
    'still asks after a pull that ended %s',
    async (outcome) => {
      order.policy = outcome;
      await runAttachedSync(base);
      expect(order.calls).toEqual(['policy', 'identity', 'commands']);
    },
  );

  it('still runs the command channel when the refresh throws', async () => {
    order.refreshThrows = true;
    await expect(runAttachedSync(base)).resolves.toBeUndefined();
    expect(order.calls).toEqual(['policy', 'identity', 'commands']);
  });
});
