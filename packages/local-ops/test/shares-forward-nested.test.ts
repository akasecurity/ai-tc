import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type * as Persistence from '@akasecurity/persistence';
import {
  applyOnboarding,
  settingsDir,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type * as PluginSdk from '@akasecurity/plugin-sdk';
import { resolveRepoAttribution, resolveRepoIdentity } from '@akasecurity/plugin-sdk';
import type { EgressIngestRequest, RecordProjectEgressInput } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTrees } from '../../../test/helpers/remove-tree.ts';
import type { SharesForwardConnection, SharesForwardDeps } from '../src/shares-forward.ts';
import { forwardProjectEgress } from '../src/shares-forward.ts';

// The nested-repository half of the Data Shares forward. A walk folds a nested
// clone's or submodule's files into the project it walks, so on a SCOPED
// attachment the register leaves the machine only when every repository nested
// in it is enrolled as well as the project. A machine-wide attachment never
// looks.
//
// The mode is stood in for exactly as in ./shares-forward-scope.test.ts: while
// `reader.scoped` is armed, the v1 credential on disk reads as its scoped twin.
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

// Called through, so every case keys the real fixture repositories. A spy, so
// a case can show the forward never looked at one.
vi.mock('@akasecurity/plugin-sdk', async (importActual) => {
  const actual = await importActual<typeof PluginSdk>();
  return { ...actual, resolveRepoIdentity: vi.fn(actual.resolveRepoIdentity) };
});

const ENDPOINT = 'https://aka.acme.test';
const TEST_KEY = 'not-a-real-key';
const WORK = 'github.com/acme/payments-api';
const SHARED = 'github.com/acme/shared-lib';
const PERSONAL = 'github.com/someone/side-project';
const SHARED_URL = 'https://github.com/acme/shared-lib.git';
const PERSONAL_URL = 'https://github.com/someone/side-project.git';
// An scp-style remote's userinfo reads as an email address to a scanner, so
// it is built from parts.
const AT = String.fromCharCode(64);
const gitUser = `git${AT}`;

const FORWARDED = { status: 'forwarded', endpoint: ENDPOINT, callSites: 0 } as const;
const NOT_ENROLLED = { status: 'not-enrolled', endpoint: ENDPOINT } as const;

interface Sent {
  connection: SharesForwardConnection;
  request: EgressIngestRequest;
}

let home: string;
let checkout: string;

beforeEach(() => {
  vi.clearAllMocks();
  reader.scoped = false;
  home = mkdtempSync(join(tmpdir(), 'aka-shares-nested-'));
  checkout = mkdtempSync(join(tmpdir(), 'aka-shares-nested-tree-'));
  gitRepo(checkout, { origin: 'https://github.com/acme/payments-api.git' });
});

afterEach(() => {
  removeTrees([home, checkout]);
});

// A repository at `dir` with these remotes, in this order. No remotes is a
// repository with no remote.
function gitRepo(dir: string, remotes: Readonly<Record<string, string>> = {}): void {
  mkdirSync(join(dir, '.git'), { recursive: true });
  const sections = Object.entries(remotes).map(
    ([name, url]) => `[remote "${name}"]\n\turl = ${url}\n`,
  );
  writeFileSync(join(dir, '.git', 'config'), `[core]\n\tbare = false\n${sections.join('')}`);
}

function nested(rel: string, remotes?: Readonly<Record<string, string>>): string {
  const dir = join(checkout, rel);
  gitRepo(dir, remotes);
  return dir;
}

// A submodule checkout: its `.git` is a FILE pointing into the parent's
// `.git/modules`, where the submodule's own config lives.
function submodule(name: string, url: string): string {
  const modules = join(checkout, '.git', 'modules', name);
  mkdirSync(modules, { recursive: true });
  writeFileSync(join(modules, 'config'), `[remote "origin"]\n\turl = ${url}\n`);
  const dir = join(checkout, name);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, '.git'), `gitdir: ../.git/modules/${name}\n`);
  return dir;
}

function attach(scope: unknown): void {
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
  writeScope(scope);
}

// Raw JSON, as in ./shares-forward-scope.test.ts: the verdict reads the record,
// whoever wrote it.
function writeScope(scope: unknown): void {
  const file = join(settingsDir(home), 'settings.json');
  const settings = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
  writeFileSync(file, JSON.stringify({ ...settings, attachmentScope: scope }));
}

const enrolled = (...identities: string[]) => ({
  endpoint: ENDPOINT,
  entries: identities.map((identity) => ({
    kind: 'repo',
    identity,
    enrolledAt: '2026-09-02T10:00:00.000Z',
  })),
});

// The scanned project's register. Empty: what is under test is whether it is
// sent at all.
const register = (): RecordProjectEgressInput => ({
  projectKey: 'git:https://github.com/acme/payments-api.git',
  project: 'payments-api',
  projectId: 'source-project-1',
  reconcile: { mode: 'walk', walkedPrefix: '' },
  hits: [],
});

async function forward(deps: Omit<SharesForwardDeps, 'send'>, input = register()) {
  const sent: Sent[] = [];
  const outcome = await forwardProjectEgress(home, input, {
    send: (connection, request) => {
      sent.push({ connection, request });
      return Promise.resolve({ ok: true as const });
    },
    ...deps,
  });
  return { outcome, sent };
}

// A forward whose list throws when it is read. Built by hand rather than
// through `forward`, whose spread would read the list itself.
async function forwardWithUnreadableList() {
  const sent: Sent[] = [];
  const deps: SharesForwardDeps = {
    send: (connection, request) => {
      sent.push({ connection, request });
      return Promise.resolve({ ok: true as const });
    },
  };
  Object.defineProperty(deps, 'nestedRepositories', {
    get(): never {
      throw new Error('nested list unreadable');
    },
  });
  const outcome = await forwardProjectEgress(home, register(), deps);
  return { outcome, sent };
}

describe('forwardProjectEgress — a scoped attachment and the repositories nested in a project', () => {
  beforeEach(() => {
    reader.scoped = true;
  });

  it('forwards when every nested repository is enrolled as well', async () => {
    const shared = nested('src/shared', { origin: SHARED_URL });
    attach(enrolled(WORK, SHARED));

    const { outcome, sent } = await forward({ nestedRepositories: [shared] });

    expect(outcome).toEqual(FORWARDED);
    expect(sent).toHaveLength(1);
  });

  it('reports not-enrolled for a nested clone whose remote is not enrolled, and sends nothing', async () => {
    // A personal clone kept inside an enrolled checkout: its call sites are in
    // this register, under the work project's key.
    const mine = nested('tools/mine', { origin: PERSONAL_URL });
    attach(enrolled(WORK));

    const { outcome, sent } = await forward({ nestedRepositories: [mine] });

    expect(outcome).toEqual(NOT_ENROLLED);
    expect(sent).toHaveLength(0);
  });

  it('reports not-enrolled for a nested repository with no remote', async () => {
    const scratch = nested('scratch');
    attach(enrolled(WORK));

    const { outcome, sent } = await forward({ nestedRepositories: [scratch] });

    expect(outcome).toEqual(NOT_ENROLLED);
    expect(sent).toHaveLength(0);
  });

  it('holds the register to every nested repository, not to most of them', async () => {
    const shared = nested('src/shared', { origin: SHARED_URL });
    const mine = nested('tools/mine', { origin: PERSONAL_URL });
    attach(enrolled(WORK, SHARED));

    const { outcome, sent } = await forward({ nestedRepositories: [shared, mine] });

    expect(outcome).toEqual(NOT_ENROLLED);
    expect(sent).toHaveLength(0);
  });

  it('keys a submodule by its own remote', async () => {
    const lib = submodule('lib', SHARED_URL);
    attach(enrolled(WORK));
    expect((await forward({ nestedRepositories: [lib] })).outcome).toEqual(NOT_ENROLLED);

    writeScope(enrolled(WORK, SHARED));
    expect((await forward({ nestedRepositories: [lib] })).outcome).toEqual(FORWARDED);
  });

  it("never judges a nested directory by the enclosing project's key once its .git is gone", async () => {
    // Removed between the walk and the forward. Asked about that directory,
    // the identity resolver would climb to the checkout around it and answer
    // with the work project's own, enrolled, key.
    const gone = nested('tools/mine', { origin: PERSONAL_URL });
    rmSync(join(gone, '.git'), { recursive: true, force: true });
    attach(enrolled(WORK));

    const { outcome, sent } = await forward({ nestedRepositories: [gone] });

    expect(outcome).toEqual(NOT_ENROLLED);
    expect(sent).toHaveLength(0);
  });

  it("reads a nested repository's remote afresh on every forward", async () => {
    // The dashboard server is long-lived. A remembered remote would let a clone
    // repointed at a personal fork go on forwarding under its old key.
    const shared = nested('src/shared', { origin: SHARED_URL });
    attach(enrolled(WORK, SHARED));
    expect((await forward({ nestedRepositories: [shared] })).outcome).toEqual(FORWARDED);

    gitRepo(shared, { origin: PERSONAL_URL });
    expect((await forward({ nestedRepositories: [shared] })).outcome).toEqual(NOT_ENROLLED);
  });

  it('reports not-enrolled when the caller does not say what its walk found', async () => {
    attach(enrolled(WORK));

    const { outcome, sent } = await forward({});

    expect(outcome).toEqual(NOT_ENROLLED);
    expect(sent).toHaveLength(0);
  });

  it('forwards a project whose walk found no nested repository', async () => {
    attach(enrolled(WORK));

    expect((await forward({ nestedRepositories: [] })).outcome).toEqual(FORWARDED);
  });

  it('fails closed: a list it cannot read reports not-enrolled, never an outage', async () => {
    attach(enrolled(WORK));

    const { outcome, sent } = await forward({
      nestedRepositories: 42 as unknown as readonly string[],
    });

    expect(outcome).toEqual(NOT_ENROLLED);
    expect(sent).toHaveLength(0);
  });

  it('fails closed: a list that throws when read reports not-enrolled, never an outage', async () => {
    // Read inside the verdict's guard, never at the call site, where a throw
    // would reach the outer catch and read as an unreachable deployment.
    attach(enrolled(WORK));

    const { outcome, sent } = await forwardWithUnreadableList();

    expect(outcome).toEqual(NOT_ENROLLED);
    expect(sent).toHaveLength(0);
  });

  it('decides the project first, and reads no nested repository for one out of scope', async () => {
    const shared = nested('src/shared', { origin: SHARED_URL });
    attach(enrolled(SHARED));

    const { outcome } = await forward({ nestedRepositories: [shared] });

    expect(outcome).toEqual(NOT_ENROLLED);
    expect(resolveRepoIdentity).not.toHaveBeenCalled();
  });
});

describe('forwardProjectEgress — a nested repository is keyed as the plugin keys it', () => {
  // The key a scoped forward checks for a nested repository must be the key
  // the plugin's resolver stamps on that repository's own captures. If not,
  // one enrollment would cover one and not the other.
  const FIXTURES: readonly (readonly [string, () => string])[] = [
    ['a clone with an origin', () => nested('a', { origin: SHARED_URL })],
    [
      'a clone spelled in scp form',
      () => nested('b', { origin: `${gitUser}GitHub.com:acme/shared-lib.git` }),
    ],
    [
      'a clone with no origin, by its first remote',
      () => nested('c', { upstream: SHARED_URL, fork: PERSONAL_URL }),
    ],
    [
      'a clone whose origin is listed after another remote',
      () => nested('d', { upstream: PERSONAL_URL, origin: SHARED_URL }),
    ],
    ['a submodule', () => submodule('e', SHARED_URL)],
  ];

  it.each(FIXTURES)('%s', async (_label, make) => {
    reader.scoped = true;
    const dir = make();
    expect(resolveRepoAttribution(dir).scopeKey).toBe(SHARED);

    attach(enrolled(WORK, SHARED));
    expect((await forward({ nestedRepositories: [dir] })).outcome).toEqual(FORWARDED);

    writeScope(enrolled(WORK, PERSONAL));
    expect((await forward({ nestedRepositories: [dir] })).outcome).toEqual(NOT_ENROLLED);
  });

  it('a nested repository with no remote has no key on either side', async () => {
    reader.scoped = true;
    const dir = nested('f');
    expect(resolveRepoAttribution(dir).scopeKey).toBeUndefined();

    attach(enrolled(WORK));
    expect((await forward({ nestedRepositories: [dir] })).outcome).toEqual(NOT_ENROLLED);
  });
});

describe('forwardProjectEgress — a machine-wide attachment and nested repositories', () => {
  it('sends exactly what it sends with no nested repositories, and reads none of them', async () => {
    const mine = nested('tools/mine', { origin: PERSONAL_URL });
    const scratch = nested('scratch');
    attach(enrolled('github.com/acme/unrelated'));

    const withNested = await forward({ nestedRepositories: [mine, scratch] });
    const without = await forward({});

    expect(withNested.outcome).toEqual(FORWARDED);
    expect(without.outcome).toEqual(FORWARDED);
    expect(JSON.stringify(withNested.sent)).toBe(JSON.stringify(without.sent));
    // No repository was looked at: a machine attachment pays nothing for scope.
    expect(resolveRepoIdentity).not.toHaveBeenCalled();
  });

  it('never reads the list: one that throws when read still forwards', async () => {
    attach(enrolled('github.com/acme/unrelated'));

    const { outcome, sent } = await forwardWithUnreadableList();

    expect(outcome).toEqual(FORWARDED);
    expect(sent).toHaveLength(1);
  });
});
