import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type * as RemoteModule from '@akasecurity/remote';
import type { AttachedCredential, ControlPlaneConnection, PolicyBundle } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { createPolicyStore } from '../../src/attached/policy-store.ts';
import { pullPolicyBundle, runPolicySync, SYNC_REQUEST_TIMEOUT_MS } from '../../src/attached/policy-sync.ts';
import { REQUEST_TIMEOUT_MS } from '../../src/attached/with-timeout.ts';

const getPolicyBundle = vi.fn();

// Partial mock: only the client FACTORY is replaced, so `RemoteRequestError`
// below is the REAL error type this module classifies in production. Mocking
// the module wholesale would have the contract test assert against a stand-in.
vi.mock('@akasecurity/remote', async (importOriginal) => ({
  ...(await importOriginal<typeof RemoteModule>()),
  createRemoteClient: () => ({ getPolicyBundle }),
}));

const CONNECTION: ControlPlaneConnection = {
  endpoint: 'https://aka.example-org.internal',
  attachedAt: '2026-08-19T10:00:00.000Z',
};

const CREDENTIAL: AttachedCredential = {
  specVersion: 1,
  endpoint: 'https://aka.example-org.internal',
  apiKey: 'not-a-real-key-3c9e6b1d8f42',
};

function bundle(version: string): PolicyBundle {
  return {
    version,
    policies: [],
    customKeywords: [],
    fetchedAt: '2026-08-19T10:00:00.000Z',
  };
}

let dataDir: string;

/**
 * What the transport raises for a 2xx body it cannot read. Built by NAME rather
 * than imported, so this suite proves the structural recognition the classifier
 * actually performs instead of relying on a shared prototype — which is the
 * property that replaced a regex over the error's wording.
 */
function invalidResponse(): Error {
  const err = new Error('control plane answered /v1/policy-bundle with a body this client cannot read');
  err.name = 'RemoteResponseInvalid';
  return err;
}

/** Both halves of an attachment in a real ~/.aka layout. */
function attach(base: string): void {
  applyOnboarding({ runMode: 'attached', controlPlane: CONNECTION }, base);
  writeControlPlaneCredential(settingsDirOf(base), CREDENTIAL);
}

beforeEach(() => {
  getPolicyBundle.mockReset();
  dataDir = mkdtempSync(join(tmpdir(), 'aka-sync-'));
});

afterEach(() => {
  rmSync(dataDir, { recursive: true, force: true });
});

describe('pullPolicyBundle', () => {
  it('caches a fetched bundle with its etag', async () => {
    getPolicyBundle.mockResolvedValue({
      changed: true,
      bundle: bundle('v1'),
      etag: 'W/"aaa"',
    });
    const store = createPolicyStore(dataDir);

    await expect(pullPolicyBundle({ connection: CONNECTION, credential: CREDENTIAL, store })).resolves.toBe('ok');

    const cached = await store.read();
    expect(cached?.bundle.version).toBe('v1');
    expect(cached?.etag).toBe('W/"aaa"');
  });

  it('replays the cached etag as the conditional validator', async () => {
    const store = createPolicyStore(dataDir);
    await store.write(bundle('v1'), 'W/"aaa"');
    getPolicyBundle.mockResolvedValue({ changed: false, etag: 'W/"aaa"' });

    await pullPolicyBundle({ connection: CONNECTION, credential: CREDENTIAL, store });

    expect(getPolicyBundle).toHaveBeenCalledWith('W/"aaa"');
  });

  it('sends no validator when there is no cache', async () => {
    getPolicyBundle.mockResolvedValue({
      changed: true,
      bundle: bundle('v1'),
      etag: 'W/"aaa"',
    });

    await pullPolicyBundle({ connection: CONNECTION, credential: CREDENTIAL, store: createPolicyStore(dataDir) });

    expect(getPolicyBundle).toHaveBeenCalledWith(undefined);
  });

  it('CARRIES THE ETAG FORWARD on a 304, and advances fetchedAtMs', async () => {
    // Dropping the etag here regresses into the alternating full-download/304
    // loop the client's own tests exist to prevent: no validator next cycle
    // means a full download, which yields a tag, which is lost on the next
    // tagless 304, forever.
    const store = createPolicyStore(dataDir);
    await store.write(bundle('v1'), 'W/"old"');
    const before = await store.read();

    getPolicyBundle.mockResolvedValue({ changed: false, etag: 'W/"new"' });
    await new Promise((r) => setTimeout(r, 2));
    await expect(pullPolicyBundle({ connection: CONNECTION, credential: CREDENTIAL, store })).resolves.toBe('not-modified');

    const after = await store.read();
    expect(after?.etag).toBe('W/"new"');
    expect(after?.bundle.version, 'the bundle itself is unchanged').toBe('v1');
    expect(after?.fetchedAtMs, 'freshness advanced').toBeGreaterThan(before?.fetchedAtMs ?? 0);
  });

  it('writes nothing on a 304 against an empty cache', async () => {
    // Should be impossible — we send no validator with no cache — but a proxy
    // can synthesise one, and there is no bundle to write in that case.
    getPolicyBundle.mockResolvedValue({ changed: false, etag: 'W/"x"' });
    const store = createPolicyStore(dataDir);

    await expect(pullPolicyBundle({ connection: CONNECTION, credential: CREDENTIAL, store })).resolves.toBe('not-modified');
    expect(await store.read()).toBeNull();
  });

  it('REFUSES to cache a 200 whose body is not a PolicyBundle', async () => {
    // The transport parses every 2xx body with `PolicyBundle` and raises
    // `RemoteResponseInvalid` when it cannot, so THAT is what this path sees —
    // driven here as a rejection rather than as a garbage resolve, because a
    // resolve is a state the real client cannot produce. Caching an unreadable
    // bundle would poison the cache permanently: read() returns null forever,
    // so the machine has no organization policy while sync keeps saying `ok`.
    // Realistic producers: version skew, or a captive-portal/SSO interstitial
    // answering 200 with HTML wrapped in JSON.
    getPolicyBundle.mockRejectedValue(invalidResponse());
    const store = createPolicyStore(dataDir);

    await expect(
      pullPolicyBundle({ connection: CONNECTION, credential: CREDENTIAL, store }),
    ).rejects.toMatchObject({ name: 'RemoteResponseInvalid' });
    expect(await store.read(), 'nothing may be cached').toBeNull();
  });

  it('leaves a GOOD cache intact when the plane starts sending garbage', async () => {
    const store = createPolicyStore(dataDir);
    await store.write(bundle('v1'), 'W/"good"');
    getPolicyBundle.mockRejectedValue(invalidResponse());

    await expect(
      pullPolicyBundle({ connection: CONNECTION, credential: CREDENTIAL, store }),
    ).rejects.toMatchObject({ name: 'RemoteResponseInvalid' });
    const cached = await store.read();
    expect(cached?.bundle.version, 'the last good bundle survives').toBe('v1');
    expect(cached?.etag, 'and so does the validator that fetched it').toBe('W/"good"');
  });

  it('bounds the download by the SYNC budget, not the 2s hook budget', () => {
    // Reusing REQUEST_TIMEOUT_MS here converts a slow link into an unbounded
    // spawn loop: every attempt times out, nothing caches, `cold` stays true, so
    // the throttle is bypassed on every session forever.
    expect(SYNC_REQUEST_TIMEOUT_MS).toBeGreaterThan(REQUEST_TIMEOUT_MS);
  });

  it('propagates a transport failure for the caller to classify', async () => {
    getPolicyBundle.mockRejectedValue(new Error('connect ECONNREFUSED'));
    await expect(
      pullPolicyBundle({ connection: CONNECTION, credential: CREDENTIAL, store: createPolicyStore(dataDir) }),
    ).rejects.toThrow(/ECONNREFUSED/);
  });

  it('leaves the cache untouched when the request fails', async () => {
    const store = createPolicyStore(dataDir);
    await store.write(bundle('v1'), 'W/"aaa"');
    getPolicyBundle.mockRejectedValue(new Error('403 Forbidden'));

    await expect(pullPolicyBundle({ connection: CONNECTION, credential: CREDENTIAL, store })).rejects.toThrow();

    const cached = await store.read();
    expect(cached?.bundle.version).toBe('v1');
    expect(cached?.etag).toBe('W/"aaa"');
  });
});

describe('runPolicySync classifies the attempt', () => {
  it('reports NO ATTEMPT (null) when the device is not attached', async () => {
    // An empty home: no descriptor and no credential, so there is nothing to
    // sync against. This is not a failed sync — it is the absence of one, and
    // the outcome enum has no member for it. Returning `unreachable` here would
    // have the caller persist a verdict about a control plane that was never
    // called, and status would print "control plane unreachable at last
    // attempt" for it.
    const base = mkdtempSync(join(tmpdir(), 'aka-home-'));
    try {
      await expect(
        runPolicySync({ base, settingsDir: settingsDirOf(base), dataDir }),
      ).resolves.toBeNull();
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  });

  it('a REAL failure is still an outcome, not a null', async () => {
    // The control that keeps the case above honest: null must mean "no attempt",
    // not "anything went wrong". With a connection present, a transport failure
    // is a genuine attempt and has to stay visible in status.
    const base = mkdtempSync(join(tmpdir(), 'aka-home-'));
    try {
      attach(base);
      getPolicyBundle.mockRejectedValue(new Error('ECONNREFUSED'));
      await expect(
        runPolicySync({ base, settingsDir: settingsDirOf(base), dataDir, now: () => 5 }),
      ).resolves.toEqual({ outcome: 'unreachable', atMs: 5 });
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  });
});

describe('the refusal arms read the client STATUS, not its wording', () => {
  // Recovering a status by matching an error's TEXT joins two packages by
  // nothing but wording: reword it and the arm degrades silently to
  // `unreachable`, turning the one outcome a human is supposed to act on into
  // the one they are meant to ignore. Reading the field is what removes that
  // coupling, and these cases are what keep it removed.
  //
  // The transport raises a `RemoteRequestError` carrying the status as a field,
  // so the join is structural and the real type can be fed through the real
  // classifier below. That is a contract test rather than a canary: it fails if
  // the transport stops carrying a status, and it does not fail if someone
  // rewords the message.
  const withConnection = async (
    err: unknown,
  ): Promise<Awaited<ReturnType<typeof runPolicySync>>> => {
    const base = mkdtempSync(join(tmpdir(), 'aka-home-'));
    try {
      attach(base);
      getPolicyBundle.mockRejectedValue(err);
      return await runPolicySync({ base, settingsDir: settingsDirOf(base), dataDir });
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  };

  it('a 401 from the real client error type is `unauthorized`', async () => {
    const { RemoteRequestError } = await import('@akasecurity/remote');
    await expect(withConnection(new RemoteRequestError(401))).resolves.toMatchObject({
      outcome: 'unauthorized',
    });
  });

  it('a 403 is `forbidden` — NOT the same arm', async () => {
    // They used to share one outcome, and so one remediation. `GET
    // /v1/policy-bundle` carries no role guard, so a 403 here is a suspended
    // account, or a credential scoped away from the route — none of which
    // re-attaching fixes, and all of which the `unauthorized` line would have
    // told the user to re-attach for.
    const { RemoteRequestError } = await import('@akasecurity/remote');
    await expect(withConnection(new RemoteRequestError(403))).resolves.toMatchObject({
      outcome: 'forbidden',
    });
  });

  it('a message that merely MENTIONS a status is not a refusal', async () => {
    // The precise thing the regex got wrong in the other direction, and the
    // reason the replacement reads a field: text is not evidence.
    await expect(
      withConnection(new Error('connect ECONNREFUSED while fetching; not a 403')),
    ).resolves.toMatchObject({ outcome: 'unreachable' });
  });

  it('an unreadable body is `invalid-bundle`, not `unreachable`', async () => {
    // The distinction a user acts on: a plane that answered promptly and
    // correctly at the HTTP layer, running a version this build cannot read,
    // must not be reported as a network problem. This is the production
    // classifier, so it fails if the recognition regresses to matching wording.
    await expect(withConnection(invalidResponse())).resolves.toMatchObject({
      outcome: 'invalid-bundle',
    });
  });

  it('a 500 is `unreachable`, not a refusal', async () => {
    const { RemoteRequestError } = await import('@akasecurity/remote');
    await expect(withConnection(new RemoteRequestError(500))).resolves.toMatchObject({
      outcome: 'unreachable',
    });
  });
});

describe('policy-store legacy compatibility', () => {
  it('reads a pre-B3 two-member cache that has no etag', async () => {
    // Existing caches predate ETags. Failing closed on them would make every
    // already-deployed device re-download on its next sync at best, and read as
    // uncached at worst.
    const store = createPolicyStore(dataDir);
    const { writeFileSync } = await import('node:fs');
    writeFileSync(
      join(dataDir, 'policy-cache.json'),
      JSON.stringify({ bundle: bundle('legacy'), fetchedAtMs: 12345 }),
    );

    const cached = await store.read();
    expect(cached?.bundle.version).toBe('legacy');
    expect(cached?.fetchedAtMs).toBe(12345);
    expect(cached?.etag).toBeUndefined();
  });
});
