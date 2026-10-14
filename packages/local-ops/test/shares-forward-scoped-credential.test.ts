import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  settingsDir,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { EgressIngestRequest, RecordProjectEgressInput } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTrees } from '../../../test/helpers/remove-tree.ts';
import type { SharesForwardConnection } from '../src/shares-forward.ts';
import { forwardProjectEgress } from '../src/shares-forward.ts';

// The Data Shares forward on a machine whose credential file really is a scoped
// (v2) one, read by the real reader — no stand-in anywhere in this file. The
// scope cases beside it decide the verdict with the mode supplied for them;
// this one is what fails if the reader stops accepting a scoped credential,
// because then the forward never gets as far as the verdict and reports
// `no-credential` instead.

const ENDPOINT = 'https://aka.acme.test';
const TEST_KEY = 'not-a-real-key';
const WORK_REPO = 'github.com/acme/payments-api';

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-shares-scoped-cred-'));
});

afterEach(() => {
  removeTrees([home]);
});

function attachScoped(enrolledRepo: string): void {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, attachedAt: '2026-09-01T10:00:00.000Z' },
    },
    home,
    null,
  );
  writeControlPlaneCredential(settingsDir(home), {
    specVersion: 2,
    mode: 'scoped',
    endpoint: ENDPOINT,
    apiKey: TEST_KEY,
  });
  const file = join(settingsDir(home), 'settings.json');
  const settings = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
  writeFileSync(
    file,
    JSON.stringify({
      ...settings,
      attachmentScope: {
        endpoint: ENDPOINT,
        entries: [{ kind: 'repo', identity: enrolledRepo, enrolledAt: '2026-09-02T10:00:00.000Z' }],
      },
    }),
  );
}

const input = (projectKey: string): RecordProjectEgressInput => ({
  projectKey,
  project: 'payments-api',
  projectId: 'source-project-1',
  reconcile: { mode: 'walk', walkedPrefix: 'src' },
  hits: [],
});

describe('forwardProjectEgress — a scoped credential read from disk', () => {
  it('forwards the enrolled repository and keeps every other project local', async () => {
    attachScoped(WORK_REPO);
    const sent: EgressIngestRequest[] = [];
    const send = (_connection: SharesForwardConnection, request: EgressIngestRequest) => {
      sent.push(request);
      return Promise.resolve({ ok: true as const });
    };

    // A walk that found nothing nested says so with an empty list. On a scoped
    // attachment an absent list keeps the register local, so leaving it out
    // would read `not-enrolled` for the enrolled repository too.
    const deps = { send, nestedRepositories: [] };

    await expect(
      forwardProjectEgress(home, input('git:https://github.com/acme/payments-api.git'), deps),
    ).resolves.toEqual({ status: 'forwarded', endpoint: ENDPOINT, callSites: 0 });
    await expect(
      forwardProjectEgress(home, input('git:https://github.com/someone/side-project.git'), deps),
    ).resolves.toEqual({ status: 'not-enrolled', endpoint: ENDPOINT });
    expect(sent).toHaveLength(1);
  });
});
