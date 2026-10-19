import { mkdirSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { CreateExceptionInput } from '@akasecurity/persistence';
import {
  applyOnboarding,
  dataDir as dataDirOf,
  openLocalDatabase,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type * as Remote from '@akasecurity/remote';
import { RemoteRouteAbsent } from '@akasecurity/remote';
import type { ControlPlaneConnection, LabelReportRequest } from '@akasecurity/schema';
import { HISTORY_SYNC_PAYLOAD_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { runLabelSync } from '../../src/attached/label-sync.ts';

const reportLabels = vi.fn();

vi.mock('@akasecurity/remote', async (importActual) => ({
  ...(await importActual<typeof Remote>()),
  createRemoteClient: () => ({ reportLabels }),
}));

const CONNECTION: ControlPlaneConnection = {
  endpoint: 'https://aka.example-org.internal',
  attachedAt: '2026-10-01T10:00:00.000Z',
};
const AT = '2026-10-01T10:00:00.000Z';

let base: string;

function attach(opts: { mode?: 'machine' | 'scoped'; consentVersion?: number | null } = {}): void {
  const { mode = 'machine', consentVersion = HISTORY_SYNC_PAYLOAD_VERSION } = opts;
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: CONNECTION,
      ...(consentVersion === null
        ? {}
        : {
            historySyncConsent: {
              acknowledgedAt: AT,
              payloadVersion: consentVersion,
              endpoint: CONNECTION.endpoint,
            },
          }),
    },
    base,
    null,
  );
  const common = { endpoint: CONNECTION.endpoint, apiKey: ['plugin', 'test', 'cred'].join('-') };
  writeControlPlaneCredential(
    settingsDirOf(base),
    mode === 'machine'
      ? { specVersion: 1, ...common }
      : { specVersion: 2, mode: 'scoped', ...common },
  );
}

let seq = 0;
function grantInput(over: Partial<CreateExceptionInput> = {}): CreateExceptionInput {
  seq += 1;
  return {
    ruleId: 'secrets/aws-access-key',
    category: 'secret',
    valueFingerprint: seq.toString(16).padStart(64, '0'),
    keyVersion: 1,
    maskedValue: 'A••••Q',
    scope: 'permanent',
    expiresAt: null,
    maxUses: null,
    justification: 'typed by the developer',
    conditions: null,
    createdBy: 'local-os-user',
    createdVia: 'cli-add',
    method: 'test-or-example',
    ...over,
  };
}

async function seed(): Promise<{ grantId: string }> {
  const db = openLocalDatabase(dataDirOf(base));
  try {
    const grant = await db.exceptions.create(grantInput());
    db.resolutions.insertResolution({
      findingKey: 'fk-person',
      status: 'dismissed',
      method: 'false-positive',
      resolvedAt: 1000,
      evidence: 'typed by a person',
    });
    db.resolutions.insertResolution({
      findingKey: 'fk-machine',
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: 1000,
      evidence: '',
    });
    return { grantId: grant.id };
  } finally {
    db.close();
  }
}

const run = () => runLabelSync({ base, settingsDir: settingsDirOf(base) });

beforeEach(() => {
  reportLabels.mockReset();
  reportLabels.mockResolvedValue({ grants: 1, dismissals: 1 });
  base = mkdtempSync(join(tmpdir(), 'aka-label-sync-'));
  mkdirSync(dataDirOf(base), { recursive: true });
});

afterEach(() => {
  removeTree(base);
});

describe('runLabelSync', () => {
  it('reports grants and dismissals with their labels, and nothing a person typed', async () => {
    attach();
    const { grantId } = await seed();

    await expect(run()).resolves.toBe('reported');

    expect(reportLabels).toHaveBeenCalledTimes(1);
    const sent = reportLabels.mock.calls[0]?.[0] as LabelReportRequest;
    expect(sent.grants.map((g) => [g.id, g.method, g.confirmedBy])).toEqual([
      [grantId, 'test-or-example', 'user'],
    ]);
    expect(sent.dismissals.map((d) => [d.findingKey, d.method, d.confirmedBy])).toEqual([
      ['fk-person', 'false-positive', 'user'],
    ]);
    const wire = JSON.stringify(sent);
    expect(wire).not.toContain('typed by');
    expect(wire).not.toContain('local-os-user');
    expect(wire).not.toContain('fk-machine');
  });

  it('does not report the same labels twice', async () => {
    attach();
    await seed();
    await run();
    reportLabels.mockClear();

    await expect(run()).resolves.toBe('nothing');
    expect(reportLabels).not.toHaveBeenCalled();
  });

  it('keeps the labels to report again when the deployment does not take them', async () => {
    attach();
    await seed();
    reportLabels.mockRejectedValueOnce(new Error('connection reset'));
    await expect(run()).resolves.toBe('failed');

    await expect(run()).resolves.toBe('reported');
    expect(reportLabels).toHaveBeenCalledTimes(2);
  });

  it('stops quietly on a deployment that predates the route', async () => {
    attach();
    await seed();
    reportLabels.mockRejectedValueOnce(new RemoteRouteAbsent('/v1/plugin/labels'));
    await expect(run()).resolves.toBe('route-absent');
  });

  it.each([
    ['no grant', { consentVersion: null }],
    [
      'a grant given before labels were named',
      { consentVersion: HISTORY_SYNC_PAYLOAD_VERSION - 1 },
    ],
  ])('sends nothing with %s', async (_, opts) => {
    attach(opts);
    await seed();
    await expect(run()).resolves.toBe('no-consent');
    expect(reportLabels).not.toHaveBeenCalled();
  });

  it('sends nothing from a scoped attachment', async () => {
    attach({ mode: 'scoped' });
    await seed();
    await expect(run()).resolves.toBe('scoped');
    expect(reportLabels).not.toHaveBeenCalled();
  });

  it('does nothing on a machine that is not attached', async () => {
    await seed();
    await expect(run()).resolves.toBeNull();
    expect(reportLabels).not.toHaveBeenCalled();
  });
});
