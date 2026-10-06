import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type * as Persistence from '@akasecurity/persistence';
import {
  applyOnboarding,
  removeControlPlaneCredential,
  settingsDir,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { EgressIngestRequest, RecordProjectEgressInput } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTrees } from '../../../test/helpers/remove-tree.ts';
import type { SharesForwardConnection } from '../src/shares-forward.ts';
import { forwardProjectEgress } from '../src/shares-forward.ts';

// The scope half of the Data Shares forward. On a SCOPED attachment a
// project's register leaves the machine only when its repository is enrolled
// for the deployment the machine is attached to; every other case reports
// `not-enrolled` with nothing sent. A machine-wide attachment is unaffected.
//
// THE MODE IS STOOD IN FOR, NOT WRITTEN. While `reader.scoped` is armed, the
// usable v1 credential on disk is reported by the credential read as its v2
// twin — same endpoint, same key, `mode: 'scoped'`. Each case therefore
// differs from its machine-wide twin in the mode alone, and a red here is the
// verdict's rather than the file reader's. How the reader treats a v2 file on
// disk is pinned in @akasecurity/persistence's credential suite.
const reader = vi.hoisted(() => ({ scoped: false }));

vi.mock('@akasecurity/persistence', async (importActual) => {
  const actual = await importActual<typeof Persistence>();
  return {
    ...actual,
    readControlPlaneCredential: (...args: Parameters<typeof actual.readControlPlaneCredential>) => {
      const real = actual.readControlPlaneCredential(...args);
      return real === null || !reader.scoped ? real : { ...real, specVersion: 2, mode: 'scoped' };
    },
  };
});

const ENDPOINT = 'https://aka.acme.test';
const OTHER_ENDPOINT = 'https://aka.other.test';
const TEST_KEY = 'not-a-real-key';
const WORK_REPO = 'github.com/acme/payments-api';

interface Sent {
  connection: SharesForwardConnection;
  request: EgressIngestRequest;
}

function recorder() {
  const sent: Sent[] = [];
  return {
    sent,
    send: (connection: SharesForwardConnection, request: EgressIngestRequest) => {
      sent.push({ connection, request });
      return Promise.resolve({ ok: true as const });
    },
  };
}

// A register with no call sites: what is under test is whether it is sent at
// all, and a machine-wide attachment sends an empty register too.
const input = (projectKey: string): RecordProjectEgressInput => ({
  projectKey,
  project: 'payments-api',
  projectId: 'source-project-1',
  reconcile: { mode: 'walk', walkedPrefix: 'src' },
  hits: [],
});

// A project key the verdict cannot read. Never produced by a scan; it is how a
// case reaches the verdict's own catch.
const unreadableKey = (): RecordProjectEgressInput =>
  ({
    ...input('git:https://github.com/acme/payments-api.git'),
    projectKey: 42,
  }) as unknown as RecordProjectEgressInput;

let home: string;

function attach(scope?: unknown): void {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, attachedAt: '2026-09-01T10:00:00.000Z' },
    },
    home,
    // No managed overlay: an administrator's file on the machine running this
    // suite must not decide what these cases see.
    null,
  );
  writeControlPlaneCredential(settingsDir(home), {
    specVersion: 1,
    endpoint: ENDPOINT,
    apiKey: TEST_KEY,
  });
  if (scope !== undefined) writeScope(scope);
}

// Written into settings.json as raw JSON rather than through a settings writer:
// the verdict reads the record, whoever wrote it — including a malformed one
// no writer would produce.
function writeScope(scope: unknown): void {
  const file = join(settingsDir(home), 'settings.json');
  const settings = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
  writeFileSync(file, JSON.stringify({ ...settings, attachmentScope: scope }));
}

const enrolled = (identity: string, endpoint = ENDPOINT) => ({
  endpoint,
  entries: [{ kind: 'repo', identity, enrolledAt: '2026-09-02T10:00:00.000Z' }],
});

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-shares-scope-'));
  reader.scoped = false;
});

afterEach(() => {
  removeTrees([home]);
});

describe('forwardProjectEgress — a scoped attachment', () => {
  it('forwards a register whose repository is enrolled', async () => {
    reader.scoped = true;
    attach(enrolled(WORK_REPO));
    const transport = recorder();

    const outcome = await forwardProjectEgress(
      home,
      input('git:https://github.com/acme/payments-api.git'),
      // A walk that found no nested repository says so with an empty list.
      { send: transport.send, nestedRepositories: [] },
    );

    expect(outcome).toEqual({ status: 'forwarded', endpoint: ENDPOINT, callSites: 0 });
    expect(transport.sent).toHaveLength(1);
  });

  it.each([
    'git:git@github.com:acme/payments-api.git',
    'git:https://GitHub.com/acme/payments-api',
    'git:ssh://git@github.com:22/acme/payments-api.git/',
  ])('matches the enrolled key however the repository was cloned (%s)', async (projectKey) => {
    // One repository cloned three ways is one enrollment: the key is the
    // canonical form, never the remote URL as the clone happened to spell it.
    reader.scoped = true;
    attach(enrolled(WORK_REPO));
    const transport = recorder();

    const outcome = await forwardProjectEgress(home, input(projectKey), {
      send: transport.send,
      nestedRepositories: [],
    });

    expect(outcome).toEqual({ status: 'forwarded', endpoint: ENDPOINT, callSites: 0 });
  });

  it('reports not-enrolled for a repository outside the scope, and sends nothing', async () => {
    reader.scoped = true;
    attach(enrolled(WORK_REPO));
    const transport = recorder();

    const outcome = await forwardProjectEgress(
      home,
      input('git:https://github.com/someone/side-project.git'),
      { send: transport.send },
    );

    expect(outcome).toEqual({ status: 'not-enrolled', endpoint: ENDPOINT });
    expect(transport.sent).toHaveLength(0);
  });

  it.each([
    ['a path-keyed project', 'path:/Users/someone/scratch'],
    ['a repository with no remote', 'git:/Users/someone/remoteless'],
  ])(
    'reports not-enrolled for %s — a location on one machine is never enrollable',
    async (_label, projectKey) => {
      reader.scoped = true;
      attach(enrolled(WORK_REPO));
      const transport = recorder();

      const outcome = await forwardProjectEgress(home, input(projectKey), { send: transport.send });

      expect(outcome).toEqual({ status: 'not-enrolled', endpoint: ENDPOINT });
      expect(transport.sent).toHaveLength(0);
    },
  );

  it('reports not-enrolled while nothing is enrolled', async () => {
    // A freshly scoped machine forwards nothing until something is enrolled.
    reader.scoped = true;
    attach();
    const transport = recorder();

    const outcome = await forwardProjectEgress(
      home,
      input('git:https://github.com/acme/payments-api.git'),
      { send: transport.send },
    );

    expect(outcome).toEqual({ status: 'not-enrolled', endpoint: ENDPOINT });
    expect(transport.sent).toHaveLength(0);
  });

  it('reads a scope built for another deployment as empty', async () => {
    // Consent to forward to one deployment is not consent to forward to
    // another: the record names its endpoint, and any other reads as empty.
    reader.scoped = true;
    attach(enrolled(WORK_REPO, OTHER_ENDPOINT));
    const transport = recorder();

    const outcome = await forwardProjectEgress(
      home,
      input('git:https://github.com/acme/payments-api.git'),
      { send: transport.send },
    );

    expect(outcome).toEqual({ status: 'not-enrolled', endpoint: ENDPOINT });
    expect(transport.sent).toHaveLength(0);
  });

  it('reads a malformed scope record as empty, never as forward-everything', async () => {
    reader.scoped = true;
    attach({ endpoint: ENDPOINT, entries: 'everything' });
    const transport = recorder();

    const outcome = await forwardProjectEgress(
      home,
      input('git:https://github.com/acme/payments-api.git'),
      { send: transport.send },
    );

    expect(outcome).toEqual({ status: 'not-enrolled', endpoint: ENDPOINT });
    expect(transport.sent).toHaveLength(0);
  });

  it('fails closed: a key it cannot read reports not-enrolled, never an outage', async () => {
    // The verdict's own catch, not the outer one. A fault while deciding
    // whether to send must not be reported as a send that failed, and must
    // not send.
    reader.scoped = true;
    attach(enrolled(WORK_REPO));
    const transport = recorder();

    const outcome = await forwardProjectEgress(home, unreadableKey(), { send: transport.send });

    expect(outcome).toEqual({ status: 'not-enrolled', endpoint: ENDPOINT });
    expect(transport.sent).toHaveLength(0);
  });

  it('answers an opt-out before the scope, so a run that asked for no network is told so', async () => {
    reader.scoped = true;
    attach();
    const transport = recorder();

    const outcome = await forwardProjectEgress(
      home,
      input('git:https://github.com/someone/side-project.git'),
      { send: transport.send, enabled: false },
    );

    expect(outcome).toEqual({ status: 'disabled', endpoint: ENDPOINT, reason: 'opt-out' });
  });

  it('reports no-credential, not not-enrolled, when there is no credential to read a mode from', async () => {
    // The mode lives on the credential, so without one there is no scope
    // question to ask — and "re-attach" is the state with something to do.
    reader.scoped = true;
    attach();
    removeControlPlaneCredential(settingsDir(home));
    const transport = recorder();

    const outcome = await forwardProjectEgress(
      home,
      input('git:https://github.com/acme/payments-api.git'),
      { send: transport.send },
    );

    expect(outcome).toEqual({ status: 'no-credential', endpoint: ENDPOINT });
  });
});

describe('forwardProjectEgress — a machine-wide attachment ignores the scope', () => {
  it('forwards a repository that no scope names', async () => {
    attach(enrolled('github.com/acme/some-other-repo'));
    const transport = recorder();

    const outcome = await forwardProjectEgress(
      home,
      input('git:https://github.com/someone/side-project.git'),
      { send: transport.send },
    );

    expect(outcome).toEqual({ status: 'forwarded', endpoint: ENDPOINT, callSites: 0 });
    expect(transport.sent).toHaveLength(1);
  });

  it('forwards a path-keyed project, which no scope could ever name', async () => {
    attach();
    const transport = recorder();

    const outcome = await forwardProjectEgress(home, input('path:/Users/someone/scratch'), {
      send: transport.send,
    });

    expect(outcome).toEqual({ status: 'forwarded', endpoint: ENDPOINT, callSites: 0 });
  });

  it('never reads the project key, so an unreadable one still fails exactly as before', async () => {
    // Machine-wide behaviour is the build-before-scopes behaviour: an
    // unreadable key reaches the projection and fails there, as an outage the
    // next scan retries — never as a scope refusal.
    attach();
    const transport = recorder();

    const outcome = await forwardProjectEgress(home, unreadableKey(), { send: transport.send });

    expect(outcome).toEqual({ status: 'failed', endpoint: ENDPOINT, kind: 'unreachable' });
    expect(transport.sent).toHaveLength(0);
  });
});
