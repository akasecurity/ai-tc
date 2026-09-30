import type { PolicyBundle } from '@akasecurity/schema';
import { SQLITE_MIGRATIONS, StorePosturePlugin } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  createPluginBlock,
  INSTALL_RECORD_READ_TIMEOUT_MS,
} from '../../src/attached/plugin-block.ts';
import type { PolicyStore } from '../../src/attached/policy-store.ts';
import { createPostureReporter } from '../../src/attached/posture-reporter.ts';
import { REQUEST_TIMEOUT_MS } from '../../src/attached/with-timeout.ts';

// The install record reader is replaced for the whole file, which is why these
// cases live apart from plugin-block.test.ts: that file drives the real reader
// against a real layout. Here the reader is whatever the case says — one that
// never settles, one that rejects, one that is slow — so the block's own bound
// on it is the only thing under test.
const installRead = vi.hoisted(() => ({
  read: vi.fn<(installRoot: string) => Promise<string | null>>(),
}));
vi.mock('../../src/attached/install-record.ts', () => ({
  readInstalledVersion: installRead.read,
}));

const bundle = (version: string): PolicyBundle => ({
  version,
  policies: [],
  rules: [],
  customKeywords: [],
  fetchedAt: '2026-08-19T00:00:00.000Z',
});

// The policy cache held in memory, so nothing but the install record reader can
// stall and every step below settles on faked timers alone.
const cache: Pick<PolicyStore, 'read'> = {
  read: () => Promise.resolve({ bundle: bundle('sha256:abc123'), fetchedAtMs: 1_779_500_000_000 }),
};

const build = {
  package: '@akasecurity/ai-tc-claude-code',
  version: '0.9.8',
  installRoot: '/plugins/cache/akasecurity/ai-tc/0.9.14',
};

// Everything the block reports apart from the install record: what a stalled or
// failed read must leave standing.
const everythingElse = {
  package: '@akasecurity/ai-tc-claude-code',
  version: '0.9.8',
  ossVersion: null,
  policyBundleVersion: 'sha256:abc123',
  policyFetchedAt: 1_779_500_000_000,
  buildSchemaVersion: SQLITE_MIGRATIONS.length,
};

const neverSettles = (): Promise<never> => new Promise<never>(() => undefined);

// Faked setTimeout/clearTimeout only: the bound is a timer race, and every
// promise the block awaits here resolves without real I/O.
beforeEach(() => {
  installRead.read.mockReset();
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
});

afterEach(() => {
  vi.useRealTimers();
});

describe('createPluginBlock — the install record read is bounded on its own', () => {
  it('bounds the read under the time the reporter gives the whole block', () => {
    // Were the read's bound the block's, a stall would drop the block whole
    // instead of costing installedVersion alone.
    expect(INSTALL_RECORD_READ_TIMEOUT_MS).toBeGreaterThan(0);
    expect(INSTALL_RECORD_READ_TIMEOUT_MS).toBeLessThan(REQUEST_TIMEOUT_MS);
  });

  it('a read that never settles costs installedVersion alone, before the block bound', async () => {
    installRead.read.mockImplementation(neverSettles);
    let outcome: unknown = 'pending';
    void createPluginBlock(build, cache)().then((block) => {
      outcome = block;
    });

    // The whole block's bound is REQUEST_TIMEOUT_MS: by a millisecond short of
    // it the block must already have its answer, not still be waiting on the
    // read.
    await vi.advanceTimersByTimeAsync(REQUEST_TIMEOUT_MS - 1);

    expect(outcome).toEqual({ ...everythingElse, installedVersion: null });
    expect(() => StorePosturePlugin.parse(outcome)).not.toThrow();
  });

  it('gives up on the read at its own bound, not before', async () => {
    installRead.read.mockImplementation(neverSettles);
    let outcome: unknown = 'pending';
    void createPluginBlock(build, cache)().then((block) => {
      outcome = block;
    });

    await vi.advanceTimersByTimeAsync(INSTALL_RECORD_READ_TIMEOUT_MS - 1);
    expect(outcome).toBe('pending');
    await vi.advanceTimersByTimeAsync(1);
    expect(outcome).toEqual({ ...everythingElse, installedVersion: null });
  });

  it('a read that rejects costs installedVersion alone', async () => {
    installRead.read.mockRejectedValue(new Error('EIO'));
    const block = await createPluginBlock(build, cache)();
    expect(block).toEqual({ ...everythingElse, installedVersion: null });
  });

  it('a slow read that lands inside the bound still reports its version', async () => {
    installRead.read.mockImplementation(
      () =>
        new Promise((resolve) => {
          setTimeout(() => {
            resolve('0.9.15');
          }, INSTALL_RECORD_READ_TIMEOUT_MS - 1);
        }),
    );
    const producing = createPluginBlock(build, cache)();

    await vi.advanceTimersByTimeAsync(INSTALL_RECORD_READ_TIMEOUT_MS - 1);

    expect(await producing).toEqual({ ...everythingElse, installedVersion: '0.9.15' });
  });

  it('asks the reader for the root the adapter named, and only that', async () => {
    installRead.read.mockResolvedValue('0.9.15');
    await createPluginBlock(build, cache)();
    expect(installRead.read).toHaveBeenCalledExactlyOnceWith(build.installRoot);

    installRead.read.mockClear();
    const block = await createPluginBlock(
      { package: build.package, version: build.version },
      cache,
    )();
    expect(installRead.read).not.toHaveBeenCalled();
    expect(block).not.toHaveProperty('installedVersion');
  });
});

describe('the posture reporter with a stalled install record read', () => {
  it('still sends a snapshot, with the plugin block minus installedVersion', async () => {
    installRead.read.mockImplementation(neverSettles);
    const reporter = createPostureReporter({
      report: () => Promise.resolve({ ok: true, value: undefined }),
      store: {
        read: () =>
          Promise.resolve({
            deviceId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
            lastAttemptedAtMs: 0,
          }),
        markAttempted: () => Promise.resolve(),
        file: '/tmp/posture-state.json',
      },
      readStore: () => ({
        storePresent: false,
        schemaVersion: null,
        findingsTotal: 0,
        findingsFirstAt: null,
        findingsLastAt: null,
        packs: [],
        policyCounts: {
          total: 0,
          disabled: 0,
          byAction: { warn: 0, redact: 0, block: 0, allow: 0, log: 0 },
        },
        readError: false,
      }),
      hostname: () => 'DevMac-01',
      now: () => 1_780_000_000_000,
      pluginBlock: createPluginBlock(build, cache),
    });

    let snapshot: unknown = 'pending';
    void reporter.prepare().then((prepared) => {
      snapshot = prepared;
    });
    // Past the read's bound, and a millisecond short of the reporter's bound on
    // the whole block: nothing here is allowed to lean on that second timer.
    await vi.advanceTimersByTimeAsync(REQUEST_TIMEOUT_MS - 1);

    expect(snapshot).toMatchObject({
      deviceId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
      plugin: { ...everythingElse, installedVersion: null },
    });
  });
});
