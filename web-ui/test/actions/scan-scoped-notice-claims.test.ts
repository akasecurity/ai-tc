import { randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { join } from 'node:path';

import { forwardProjectEgress } from '@akasecurity/local-ops';
import {
  applyOnboarding,
  defaultDataDir,
  settingsDir,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { EgressIngestRequest, RecordProjectEgressInput } from '@akasecurity/schema';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { tempHomes } from '../helpers/temp-home.ts';

// The Scan page's notice on a scoped machine says the Data Shares register goes
// only when the project is an enrolled repository and every repository nested in
// it is enrolled too. These cases call `forwardProjectEgress` the way `runScan`
// does (the default home, and the nested repositories the walk reported;
// `scan-nested-repositories.test.ts` pins that wiring), so the sentence is held to
// what the forward decides. What it decides in every other case is pinned in
// `packages/local-ops`.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});

// Homes are removed when this FILE finishes, not after each test. See the helper.
const newHome = tempHomes('aka-scan-scoped-claims-');

/** A high-entropy key made at run time, so no key-shaped literal sits in the tree. */
const KEY = randomBytes(24).toString('base64url');
const ENDPOINT = 'https://aka.example.com';
const ENROLLED_AT = '2026-10-01T00:00:00.000Z';
const PROJECT = 'github.com/acme/payments-api';
const NESTED = 'github.com/someone/side-project';
const NESTED_URL = 'https://github.com/someone/side-project.git';

let home: string;

beforeEach(() => {
  home = newHome();
  osHome.dir = home;
});

/** Attach this machine to `ENDPOINT` in a mode, with the given repositories enrolled when scoped. */
function attach(mode: 'scoped' | 'machine', ...enrolled: string[]): void {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, attachedAt: ENROLLED_AT },
      ...(mode === 'scoped'
        ? {
            attachmentScope: {
              endpoint: ENDPOINT,
              tenantName: 'Example Org',
              userEmail: 'operator',
              entries: enrolled.map((identity) => ({
                kind: 'repo',
                identity,
                enrolledAt: ENROLLED_AT,
              })),
            },
          }
        : {}),
    },
    defaultDataDir(),
    null,
  );
  writeControlPlaneCredential(
    settingsDir(defaultDataDir()),
    mode === 'scoped'
      ? { specVersion: 2, mode: 'scoped', endpoint: ENDPOINT, apiKey: KEY, mintedAt: ENROLLED_AT }
      : { specVersion: 1, endpoint: ENDPOINT, apiKey: KEY, mintedAt: ENROLLED_AT },
  );
}

/** A repository below the scanned tree, as the walk reports it: a directory holding `.git`. */
function nestedRepository(): string {
  const dir = join(home, 'checkout', 'tools', 'mine');
  mkdirSync(join(dir, '.git'), { recursive: true });
  writeFileSync(
    join(dir, '.git', 'config'),
    `[core]\n\tbare = false\n[remote "origin"]\n\turl = ${NESTED_URL}\n`,
  );
  return dir;
}

/** The register the Scan page records for the project, with nothing in it to send. */
function register(): RecordProjectEgressInput {
  return {
    projectKey: 'git:https://github.com/acme/payments-api.git',
    project: 'payments-api',
    projectId: 'source-project-1',
    reconcile: { mode: 'walk', walkedPrefix: '' },
    hits: [],
  };
}

/** The forward `runScan` makes, with a sender that records what it is asked to send. */
async function forward(nestedRepositories: string[]) {
  const sent: EgressIngestRequest[] = [];
  const outcome = await forwardProjectEgress(defaultDataDir(), register(), {
    send: (_connection, request) => {
      sent.push(request);
      return Promise.resolve({ ok: true as const });
    },
    enabled: true,
    nestedRepositories,
  });
  return { outcome, sent };
}

describe('what the scoped Scan notice claims, against the forward the page calls', () => {
  it('keeps the register on this machine when the project is not an enrolled repository', async () => {
    attach('scoped', 'github.com/acme/ledger');

    const { outcome, sent } = await forward([]);

    expect(outcome).toEqual({ status: 'not-enrolled', endpoint: ENDPOINT });
    expect(sent).toEqual([]);
  });

  it('keeps it on this machine when a repository nested in an enrolled project is not enrolled', async () => {
    attach('scoped', PROJECT);

    const { outcome, sent } = await forward([nestedRepository()]);

    expect(outcome).toEqual({ status: 'not-enrolled', endpoint: ENDPOINT });
    expect(sent).toEqual([]);
  });

  it('sends it when the project and every repository nested in it are enrolled', async () => {
    attach('scoped', PROJECT, NESTED);

    const { outcome, sent } = await forward([nestedRepository()]);

    expect(outcome).toEqual({ status: 'forwarded', endpoint: ENDPOINT, callSites: 0 });
    expect(sent).toHaveLength(1);
  });

  it('sends it from a machine-wide attachment whatever is nested, as the machine-wide notice says', async () => {
    attach('machine');

    const { outcome, sent } = await forward([nestedRepository()]);

    expect(outcome).toEqual({ status: 'forwarded', endpoint: ENDPOINT, callSites: 0 });
    expect(sent).toHaveLength(1);
  });
});
