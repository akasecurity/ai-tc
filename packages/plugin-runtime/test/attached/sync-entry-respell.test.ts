// The sweep that re-keys stored enrolments has to be WIRED, and nothing else
// here can tell: it lives in `@akasecurity/persistence` and is self-gating, so
// deleting the call leaves every other suite green while a repository enrolled
// under a pre-change spelling goes on forwarding nothing. This file is the only
// thing that would notice.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type * as Persistence from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { runAttachedSync } from '../../src/attached/sync-entry.ts';

const order = vi.hoisted((): { calls: string[]; policy: string | null } => ({
  calls: [],
  policy: 'ok',
}));

vi.mock('@akasecurity/persistence', async (importOriginal) => ({
  ...(await importOriginal<typeof Persistence>()),
  respellStoredEnrolments: () => {
    order.calls.push('respell');
    return 'skipped';
  },
}));
vi.mock('../../src/attached/policy-sync.ts', () => ({
  runPolicySync: () => {
    order.calls.push('policy');
    return Promise.resolve(order.policy === null ? null : { outcome: order.policy });
  },
}));
vi.mock('../../src/attached/sync-state.ts', () => ({ writeSyncState: () => undefined }));
vi.mock('../../src/attached/identity-refresh.ts', () => ({
  refreshAttachedIdentity: () => Promise.resolve('skipped'),
}));
vi.mock('../../src/attached/sighting-key-sync.ts', () => ({
  runSightingKeySync: () => Promise.resolve(null),
}));
vi.mock('../../src/attached/label-sync.ts', () => ({ runLabelSync: () => Promise.resolve(null) }));
vi.mock('../../src/attached/command-sync.ts', () => ({
  runCommandSync: () => Promise.resolve(null),
}));
vi.mock('../../src/attached/config-inventory-sync.ts', () => ({
  runConfigInventorySync: () => Promise.resolve(null),
}));

let base: string;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-sync-entry-respell-'));
  order.calls = [];
  order.policy = 'ok';
});

afterEach(() => {
  removeTree(base);
});

describe('runAttachedSync — the stored-enrolment sweep', () => {
  it('re-keys stored enrolments before anything asks the deployment', async () => {
    await runAttachedSync(base);
    expect(order.calls.slice(0, 2)).toEqual(['respell', 'policy']);
  });

  it('still re-keys them when the deployment refuses the key', async () => {
    // The early return on `unauthorized` skips every job that would ask the
    // deployment again. This one asks nothing, and a machine whose key was
    // revoked still has its own file to put right.
    order.policy = 'unauthorized';
    await runAttachedSync(base);
    expect(order.calls).toEqual(['respell', 'policy']);
  });
});
