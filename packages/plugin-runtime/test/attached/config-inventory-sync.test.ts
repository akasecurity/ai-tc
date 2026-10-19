import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  dataDir as dataDirOf,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type * as Remote from '@akasecurity/remote';
import {
  RemoteRequestError,
  RemoteResponseInvalid,
  RemoteRouteAbsent,
  RemoteTransportError,
} from '@akasecurity/remote';
import type {
  AttachedCredentialAny,
  ConfigInventoryAck,
  ConfigInventoryRequest,
  ConfigScanRecord,
  ControlPlaneConnection,
} from '@akasecurity/schema';
import { CONFIG_INVENTORY_BATCH_MAX } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  CONFIG_INVENTORY_RESEND_MS,
  CONFIG_INVENTORY_STAGED_MAX,
  CONFIG_INVENTORY_STAGED_MAX_AGE_MS,
  CONFIG_INVENTORY_STAGED_MAX_BYTES,
  configInventoryStatePath,
  runConfigInventorySync,
  stageConfigInventory,
  stagedConfigInventoryPath,
} from '../../src/attached/config-inventory-sync.ts';

const recordConfigInventory =
  vi.fn<(request: ConfigInventoryRequest) => Promise<ConfigInventoryAck>>();

vi.mock('@akasecurity/remote', async (importActual) => ({
  ...(await importActual<typeof Remote>()),
  createRemoteClient: () => ({ recordConfigInventory }),
}));

const NOW = 1_766_000_000_000;

const CONNECTION: ControlPlaneConnection = {
  endpoint: 'https://aka.example-org.internal',
  attachedAt: '2026-10-01T10:00:00.000Z',
};

const OTHER: ControlPlaneConnection = {
  endpoint: 'https://aka.other-org.internal',
  attachedAt: '2026-10-02T10:00:00.000Z',
};

const HARNESS = {
  objectType: 'harness' as const,
  identityKey: 'claude-code',
  title: 'claude-code',
  attributes: {},
};

const WIDGETS = 'https://github.com/acme/widgets.git';
const GADGETS = 'https://github.com/acme/gadgets.git';

let base: string;
let data: string;

function credential(mode: 'machine' | 'scoped', endpoint: string): AttachedCredentialAny {
  const common = { endpoint, apiKey: ['plugin', 'test', 'cred'].join('-') };
  return mode === 'machine'
    ? { specVersion: 1, ...common }
    : { specVersion: 2, mode: 'scoped', ...common };
}

function attach(mode: 'machine' | 'scoped' = 'machine', connection = CONNECTION): void {
  applyOnboarding({ runMode: 'attached', controlPlane: connection }, base, null);
  writeControlPlaneCredential(settingsDirOf(base), credential(mode, connection.endpoint));
}

function server(name: string, scope = 'user') {
  return {
    objectType: 'mcp_server' as const,
    identityKey: `${name}|${scope}`,
    title: name,
    attributes: { scope, transport: 'http', url: `https://${name}.example.test/mcp` },
  };
}

function scan(projectKey: string, overrides: Partial<ConfigScanRecord> = {}): ConfigScanRecord {
  return {
    items: [server('linear'), server(`repo-${projectKey}`, `project:${projectKey}`)],
    scanEvent: {
      id: `scan-${projectKey}`,
      eventType: 'config_scan',
      startedAt: '2026-10-19T09:00:00.000Z',
      attributes: {},
    },
    harness: HARNESS,
    projectKey,
    complete: true,
    ...overrides,
  };
}

const stage = (record: ConfigScanRecord, atMs: number, maxBytes?: number) => {
  stageConfigInventory(data, record, atMs, maxBytes);
};

const run = (now = NOW) =>
  runConfigInventorySync({
    base,
    settingsDir: settingsDirOf(base),
    dataDir: data,
    now: () => now,
  });

/** The project key of each request sent, in order. */
const sentProjects = () => recordConfigInventory.mock.calls.map(([request]) => request.projectKey);

function stagedReports(): { stagedAtMs: number; requests: ConfigInventoryRequest[] }[] {
  const staged = JSON.parse(readFileSync(stagedConfigInventoryPath(data), 'utf8')) as {
    reports: { stagedAtMs: number; requests: ConfigInventoryRequest[] }[];
  };
  return staged.reports;
}

beforeEach(() => {
  recordConfigInventory.mockReset();
  recordConfigInventory.mockImplementation((request) =>
    Promise.resolve({ accepted: request.items.length }),
  );
  base = mkdtempSync(join(tmpdir(), 'aka-config-inventory-'));
  data = dataDirOf(base);
  mkdirSync(data, { recursive: true });
});

afterEach(() => {
  rmSync(base, { recursive: true, force: true });
});

describe('stageConfigInventory', () => {
  it('stages the requests a scan builds', () => {
    const record = scan(WIDGETS);
    stage(record, NOW);

    expect(stagedReports()).toEqual([
      {
        key: expect.any(String) as string,
        stagedAtMs: NOW,
        requests: [{ harness: HARNESS, items: record.items, projectKey: WIDGETS, complete: true }],
      },
    ]);
  });

  it('keeps one report per project, replacing the earlier one for the same project', () => {
    stage(scan(WIDGETS), NOW - 2);
    stage(scan(GADGETS), NOW - 1);
    stage(scan(WIDGETS, { items: [server('linear')] }), NOW);

    expect(
      stagedReports().map((report) => [report.stagedAtMs, report.requests[0]?.projectKey]),
    ).toEqual([
      [NOW - 1, GADGETS],
      [NOW, WIDGETS],
    ]);
    expect(stagedReports()[1]?.requests[0]?.items).toEqual([server('linear')]);
  });

  it('stages nothing for a record that names no harness', () => {
    const record = scan(WIDGETS);
    delete record.harness;

    stage(record, NOW);

    expect(() => readFileSync(stagedConfigInventoryPath(data))).toThrow();
  });

  it('drops a report staged before the age limit', () => {
    stage(scan('expired'), NOW - CONFIG_INVENTORY_STAGED_MAX_AGE_MS);
    stage(scan('recent'), NOW - CONFIG_INVENTORY_STAGED_MAX_AGE_MS + 1);
    stage(scan(WIDGETS), NOW);

    expect(stagedReports().map((report) => report.requests[0]?.projectKey)).toEqual([
      'recent',
      WIDGETS,
    ]);
  });

  it('keeps the newest reports up to the count limit', () => {
    for (let i = 0; i <= CONFIG_INVENTORY_STAGED_MAX; i += 1) {
      stage(scan(`project-${String(i)}`), NOW - 100 + i);
    }

    const projects = stagedReports().map((report) => report.requests[0]?.projectKey);
    expect(projects).toHaveLength(CONFIG_INVENTORY_STAGED_MAX);
    expect(projects).not.toContain('project-0');
    expect(projects.at(-1)).toBe(`project-${String(CONFIG_INVENTORY_STAGED_MAX)}`);
  });

  it('drops the oldest reports to stay under the size limit, and always keeps the new one', () => {
    stage(scan(GADGETS), NOW - 20);
    stage(scan(WIDGETS), NOW - 10, 10_000);
    expect(stagedReports()).toHaveLength(2);

    const oneReport = Buffer.byteLength(readFileSync(stagedConfigInventoryPath(data), 'utf8')) / 2;
    stage(scan('third'), NOW, oneReport + 200);
    expect(stagedReports().map((report) => report.requests[0]?.projectKey)).toEqual(['third']);

    stage(scan('fourth'), NOW + 10, 1);
    expect(stagedReports().map((report) => report.requests[0]?.projectKey)).toEqual(['fourth']);
    expect(CONFIG_INVENTORY_STAGED_MAX_BYTES).toBeGreaterThan(4 * 1024 * 1024);
  });

  it('replaces a staged file it cannot read', () => {
    writeFileSync(stagedConfigInventoryPath(data), '{not json');

    stage(scan(WIDGETS), NOW);

    expect(stagedReports()).toHaveLength(1);
  });

  it('does not throw when the file cannot be written', () => {
    mkdirSync(stagedConfigInventoryPath(data));
    writeFileSync(join(stagedConfigInventoryPath(data), 'occupied'), '');

    expect(() => {
      stage(scan(WIDGETS), NOW);
    }).not.toThrow();
  });
});

describe('runConfigInventorySync', () => {
  it('sends a staged report once, and skips it while it is unchanged', async () => {
    attach();
    stage(scan(WIDGETS), NOW - 10);

    await expect(run()).resolves.toEqual({ sent: 1, unchanged: 0, failed: 0 });
    expect(recordConfigInventory).toHaveBeenCalledTimes(1);
    expect(recordConfigInventory.mock.calls[0]?.[0]).toEqual({
      harness: HARNESS,
      items: scan(WIDGETS).items,
      projectKey: WIDGETS,
      complete: true,
    });

    stage(scan(WIDGETS), NOW + 10);
    await expect(run(NOW + 20)).resolves.toEqual({ sent: 0, unchanged: 1, failed: 0 });
    expect(recordConfigInventory).toHaveBeenCalledTimes(1);
  });

  it('sends a changed report straight away', async () => {
    attach();
    stage(scan(WIDGETS), NOW - 10);
    await run();

    stage(scan(WIDGETS, { items: [server('linear'), server('sentry')] }), NOW + 10);
    await expect(run(NOW + 20)).resolves.toEqual({ sent: 1, unchanged: 0, failed: 0 });

    expect(recordConfigInventory).toHaveBeenCalledTimes(2);
    expect(recordConfigInventory.mock.calls[1]?.[0].items).toContainEqual(server('sentry'));
  });

  it('sends an unchanged report again once the last delivery is an hour old and a session start staged it since', async () => {
    attach();
    stage(scan(WIDGETS), NOW - 10);
    await run();

    stage(scan(WIDGETS), NOW + CONFIG_INVENTORY_RESEND_MS - 10);
    await expect(run(NOW + CONFIG_INVENTORY_RESEND_MS - 1)).resolves.toMatchObject({ sent: 0 });

    await expect(run(NOW + CONFIG_INVENTORY_RESEND_MS)).resolves.toEqual({
      sent: 1,
      unchanged: 0,
      failed: 0,
    });
    expect(recordConfigInventory).toHaveBeenCalledTimes(2);
  });

  it('does not send an unchanged report again when no session start staged it since', async () => {
    attach();
    stage(scan(WIDGETS), NOW - 10);
    await run();

    await expect(run(NOW + 2 * CONFIG_INVENTORY_RESEND_MS)).resolves.toEqual({
      sent: 0,
      unchanged: 1,
      failed: 0,
    });
    expect(recordConfigInventory).toHaveBeenCalledTimes(1);
  });

  it("sends an unchanged report again when another project's report changed the machine-wide items", async () => {
    attach();
    stage(scan(WIDGETS), NOW - 10);
    await run();

    // Another project's scan, taken after a machine-wide server was removed.
    stage(scan(GADGETS, { items: [server('repo-gadgets', `project:${GADGETS}`)] }), NOW + 10);
    await run(NOW + 20);
    // The widgets scan, after the server came back: unchanged for widgets, but
    // the deployment last heard the machine has no such server.
    stage(scan(WIDGETS), NOW + 30);
    await expect(run(NOW + 40)).resolves.toEqual({ sent: 1, unchanged: 1, failed: 0 });

    expect(sentProjects()).toEqual([WIDGETS, GADGETS, WIDGETS]);

    // The older gadgets report is not sent again for its machine-wide items.
    await expect(run(NOW + 50)).resolves.toEqual({ sent: 0, unchanged: 2, failed: 0 });
  });

  it('sends the staged reports oldest first', async () => {
    attach();
    stage(scan(GADGETS), NOW - 20);
    stage(scan(WIDGETS), NOW - 10);

    await expect(run()).resolves.toEqual({ sent: 2, unchanged: 0, failed: 0 });

    expect(sentProjects()).toEqual([GADGETS, WIDGETS]);
  });

  it('sends every part of a report over the batch cap', async () => {
    attach();
    const items = Array.from({ length: CONFIG_INVENTORY_BATCH_MAX + 1 }, (_, i) =>
      server(`server-${String(i)}`),
    );
    stage(scan(WIDGETS, { items }), NOW - 10);

    await expect(run()).resolves.toEqual({ sent: 1, unchanged: 0, failed: 0 });

    expect(recordConfigInventory.mock.calls.map(([request]) => request.items.length)).toEqual([
      CONFIG_INVENTORY_BATCH_MAX,
      1,
    ]);
  });

  it('keeps a report it could not deliver, ends the pass, and sends it next time', async () => {
    attach();
    stage(scan(GADGETS), NOW - 20);
    stage(scan(WIDGETS), NOW - 10);
    recordConfigInventory.mockRejectedValueOnce(new RemoteTransportError('reset'));

    await expect(run()).resolves.toEqual({ sent: 0, unchanged: 0, failed: 1 });
    expect(sentProjects()).toEqual([GADGETS]);

    await expect(run(NOW + 10)).resolves.toEqual({ sent: 2, unchanged: 0, failed: 0 });
    expect(sentProjects()).toEqual([GADGETS, GADGETS, WIDGETS]);
  });

  it('records a report as delivered only when every part was taken', async () => {
    attach();
    const items = Array.from({ length: CONFIG_INVENTORY_BATCH_MAX + 1 }, (_, i) =>
      server(`server-${String(i)}`),
    );
    stage(scan(WIDGETS, { items }), NOW - 10);
    recordConfigInventory
      .mockResolvedValueOnce({ accepted: CONFIG_INVENTORY_BATCH_MAX })
      .mockRejectedValueOnce(new RemoteTransportError('reset'));

    await expect(run()).resolves.toEqual({ sent: 0, unchanged: 0, failed: 1 });
    await expect(run(NOW + 10)).resolves.toEqual({ sent: 1, unchanged: 0, failed: 0 });

    expect(recordConfigInventory).toHaveBeenCalledTimes(4);
  });

  it('moves on past a report the deployment refuses', async () => {
    attach();
    stage(scan(GADGETS), NOW - 20);
    stage(scan(WIDGETS), NOW - 10);
    recordConfigInventory.mockRejectedValueOnce(new RemoteRequestError(400));

    await expect(run()).resolves.toEqual({ sent: 1, unchanged: 0, failed: 1 });

    expect(sentProjects()).toEqual([GADGETS, WIDGETS]);
  });

  it('ends the pass on a deployment that predates the route', async () => {
    attach();
    stage(scan(GADGETS), NOW - 20);
    stage(scan(WIDGETS), NOW - 10);
    recordConfigInventory.mockRejectedValue(new RemoteRouteAbsent('/v1/inventory/config-items'));

    await expect(run()).resolves.toEqual({ sent: 0, unchanged: 0, failed: 1 });

    expect(recordConfigInventory).toHaveBeenCalledTimes(1);
  });

  it('counts a report answered with an unreadable acknowledgement as delivered', async () => {
    attach();
    stage(scan(WIDGETS), NOW - 10);
    recordConfigInventory.mockRejectedValueOnce(
      new RemoteResponseInvalid('/v1/inventory/config-items', 'an unreadable body'),
    );

    await expect(run()).resolves.toEqual({ sent: 1, unchanged: 0, failed: 0 });
    await expect(run(NOW + 10)).resolves.toEqual({ sent: 0, unchanged: 1, failed: 0 });
  });

  it('sends again after the machine attaches to the same deployment anew', async () => {
    attach();
    stage(scan(WIDGETS), NOW - 10);
    await run();

    attach('machine', { ...CONNECTION, attachedAt: '2026-10-19T12:00:00.000Z' });
    stage(scan(WIDGETS), NOW + 10);
    await expect(run(NOW + 20)).resolves.toEqual({ sent: 1, unchanged: 0, failed: 0 });
  });

  it('sends again after the machine attaches to another deployment', async () => {
    attach();
    stage(scan(WIDGETS), NOW - 10);
    await run();

    attach('machine', OTHER);
    stage(scan(WIDGETS), NOW + 10);
    await expect(run(NOW + 20)).resolves.toEqual({ sent: 1, unchanged: 0, failed: 0 });
  });

  it('skips a staged report whose requests are not valid, and sends the rest', async () => {
    attach();
    stage(scan(WIDGETS), NOW - 10);
    const staged = JSON.parse(readFileSync(stagedConfigInventoryPath(data), 'utf8')) as {
      reports: unknown[];
    };
    writeFileSync(
      stagedConfigInventoryPath(data),
      JSON.stringify({
        reports: [
          { key: 'broken', stagedAtMs: NOW - 20, requests: [{ items: 'x' }] },
          ...staged.reports,
        ],
      }),
    );

    await expect(run()).resolves.toEqual({ sent: 1, unchanged: 0, failed: 0 });

    expect(sentProjects()).toEqual([WIDGETS]);
  });

  it('sends when the delivered state cannot be read', async () => {
    attach();
    writeFileSync(configInventoryStatePath(data), '{not json');
    stage(scan(WIDGETS), NOW - 10);

    await expect(run()).resolves.toEqual({ sent: 1, unchanged: 0, failed: 0 });
  });

  it('sends nothing, and makes no attempt, on a standalone machine', async () => {
    stage(scan(WIDGETS), NOW - 10);

    await expect(run()).resolves.toBeNull();

    expect(recordConfigInventory).not.toHaveBeenCalled();
  });

  it('sends nothing, and makes no attempt, on a scoped attachment', async () => {
    attach('scoped');
    stage(scan(WIDGETS), NOW - 10);

    await expect(run()).resolves.toBeNull();

    expect(recordConfigInventory).not.toHaveBeenCalled();
  });

  it('sends nothing when the credential was minted for another deployment', async () => {
    applyOnboarding({ runMode: 'attached', controlPlane: CONNECTION }, base, null);
    writeControlPlaneCredential(settingsDirOf(base), credential('machine', OTHER.endpoint));
    stage(scan(WIDGETS), NOW - 10);

    await expect(run()).resolves.toBeNull();

    expect(recordConfigInventory).not.toHaveBeenCalled();
  });

  it('reports nothing to do when nothing is staged', async () => {
    attach();

    await expect(run()).resolves.toEqual({ sent: 0, unchanged: 0, failed: 0 });

    expect(recordConfigInventory).not.toHaveBeenCalled();
  });
});
