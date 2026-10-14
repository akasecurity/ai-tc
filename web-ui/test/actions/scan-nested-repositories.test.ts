import { join } from 'node:path';

import type * as LocalOps from '@akasecurity/local-ops';
import { forwardProjectEgress } from '@akasecurity/local-ops';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { runScan } from '../../app/(app)/scan/actions.ts';
import { tempHomes } from '../helpers/temp-home.ts';

// The Scan page hands the Data Shares forward the nested repositories its walk
// reported, so a scoped attachment can hold the register to them. What the
// forward then decides is pinned in packages/local-ops; this is the wiring.
// The scan, the store and the forward are stand-ins, so nothing is walked,
// recorded or sent.
const seams = vi.hoisted(() => ({
  nestedRepositories: [] as string[],
  register: {
    projectKey: 'git:https://github.com/acme/payments-api.git',
    project: 'payments-api',
    projectId: null,
    reconcile: { mode: 'walk' as const, walkedPrefix: '' },
    hits: [],
  },
}));

vi.mock('@akasecurity/local-ops', async (importActual) => {
  const actual = await importActual<typeof LocalOps>();
  return {
    ...actual,
    createGuardedFileScanner: vi.fn(() =>
      Promise.resolve({
        scanText: () => Promise.resolve([]),
        dropped: () => ({ quarantined: 0, unmeasured: 0, bound: 0, isolated: true }),
        close: () => Promise.resolve(),
      }),
    ),
    scanPathIntoStore: vi.fn(() =>
      Promise.resolve({
        scanned: 1,
        findings: 0,
        files: [],
        egress: { files: [] },
        nestedRepositories: seams.nestedRepositories,
      }),
    ),
    recordProjectInventory: vi.fn(() => null),
    recordProjectEgress: vi.fn(() => ({
      destinations: 0,
      endpoints: 0,
      callSites: 0,
      truncated: false,
      droppedFiles: [],
      project: 'payments-api',
      input: seams.register,
    })),
    forwardProjectEgress: vi.fn(() => Promise.resolve({ status: 'not-attached' })),
  };
});

vi.mock('../../app/lib/db.ts', () => ({
  db: () => ({
    installedPacks: {
      installedRuleset: () => ({
        rules: [{ id: 'stub-rule' }],
        ruleActions: new Map(),
        installedPacks: 1,
        enabledPacks: 1,
      }),
    },
    ruleProbeCache: { countQuarantined: () => 0 },
  }),
  // What tempHomes()'s teardown releases before it removes the directories.
  // There is no store behind this stand-in, so there is nothing to let go of.
  closeStore: () => undefined,
}));

vi.mock('../../app/lib/scan-worker.ts', () => ({ scanWorkerUrl: () => undefined }));
vi.mock('next/cache', () => ({ revalidatePath: () => undefined }));

// Removed when the file finishes, through the one helper that releases the
// store first (see test/helpers/temp-home.ts). Every test still gets its own.
const newTarget = tempHomes('aka-scan-nested-');
let target: string;

beforeEach(() => {
  vi.clearAllMocks();
  target = newTarget();
});

describe('runScan — the forward is told what the walk found nested', () => {
  it('hands forwardProjectEgress exactly the list the scan reported', async () => {
    seams.nestedRepositories = [join(target, 'tools', 'mine'), join(target, 'lib')];

    await runScan(target);

    expect(forwardProjectEgress).toHaveBeenCalledTimes(1);
    expect(vi.mocked(forwardProjectEgress).mock.calls[0]?.[2].nestedRepositories).toEqual([
      join(target, 'tools', 'mine'),
      join(target, 'lib'),
    ]);
  });

  it('hands it an empty list, never none, when the walk found nothing nested', async () => {
    seams.nestedRepositories = [];

    await runScan(target);

    expect(vi.mocked(forwardProjectEgress).mock.calls[0]?.[2].nestedRepositories).toEqual([]);
  });
});
