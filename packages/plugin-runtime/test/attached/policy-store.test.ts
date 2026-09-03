import { mkdtemp, readdir, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { Policy, PolicyBundle } from '@akasecurity/schema';
import { POLICY_BUNDLE_SHAPE_ID } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { createPolicyStore } from '../../src/attached/policy-store.ts';

async function dir(): Promise<string> {
  return await mkdtemp(join(tmpdir(), 'aka-policy-store-'));
}

const bundle = (version: string): PolicyBundle => ({
  version,
  policies: [],
  rules: [],
  customKeywords: [],
  fetchedAt: '2026-08-19T00:00:00.000Z',
});

// A policy as the control plane authored it, rather than an expansion of a
// built-in archetype. Spelled out here because what this file checks is which
// of its fields survive `PolicyBundle.parse`.
const POLICY: Policy = {
  id: '0b3f5f6e-6c1a-4a4f-9a2e-6c9d1f0c9a11',
  scope: 'global',
  target: { category: 'secret' },
  action: 'block',
  enabled: true,
  provenance: 'authored',
};

const authored = (version: string): PolicyBundle => ({ ...bundle(version), policies: [POLICY] });

// policy-cache.json is the only thing standing between an attached device and
// enforcing local-only. A torn or missing cache is fail-open by design — read()
// returns null and the tenant's raise-only floor silently disappears — so how
// this file is PUBLISHED is a security property, not a housekeeping detail.
describe('the policy cache publishes atomically', () => {
  it('round-trips a bundle', async () => {
    const d = await dir();
    const store = createPolicyStore(d);
    await store.write(bundle('v1'), 'W/"etag-1"');
    await expect(store.read()).resolves.toMatchObject({
      bundle: { version: 'v1' },
      etag: 'W/"etag-1"',
    });
  });

  it('writes 0600 — the bundle carries org rules and custom keywords', async () => {
    const d = await dir();
    const store = createPolicyStore(d);
    await store.write(bundle('v1'));
    // Windows has no POSIX modes; the rest of the ~/.aka layout says so too.
    if (process.platform !== 'win32') {
      expect((await stat(store.file)).mode & 0o777).toBe(0o600);
    }
  });

  it('CONCURRENT writers never tear the cache, and all of them land', async () => {
    // The regression this file exists for. With one shared `${file}.tmp`, two
    // overlapping sync children interleave into the same path: the loser's
    // rename hits ENOENT, or one writes while the other renames and the reader
    // parses a half-file. Either way `read()` returns null and enforcement
    // quietly drops to local-only.
    const d = await dir();
    const store = createPolicyStore(d);
    await Promise.all(
      Array.from({ length: 12 }, (_, i) =>
        store.write(bundle(`v${String(i)}`), `W/"e${String(i)}"`),
      ),
    );
    const got = await store.read();
    expect(got).not.toBeNull();
    // Whichever writer won, the file is a COMPLETE record — never a torn one.
    expect(got?.bundle.version).toMatch(/^v\d+$/);
    expect(got?.etag).toMatch(/^W\/"e\d+"$/);
  });

  it('leaves no temp files behind', async () => {
    const d = await dir();
    const store = createPolicyStore(d);
    await Promise.all([
      store.write(bundle('a')),
      store.write(bundle('b')),
      store.write(bundle('c')),
    ]);
    const left = (await readdir(d)).filter((n) => n.includes('.tmp'));
    expect(left).toEqual([]);
  });

  it('a corrupt cache reads as no cache rather than throwing', async () => {
    const d = await dir();
    const store = createPolicyStore(d);
    await writeFile(store.file, '{ this is not json', 'utf8');
    await expect(store.read()).resolves.toBeNull();
  });

  /**
   * `read()` parses through `PolicyBundle`, and Zod STRIPS what the shape does
   * not declare. So every field a policy carries across this cache is only ever
   * present because the schema names it — a field the control plane sends and
   * the schema has not heard of reaches disk and then vanishes on the way back,
   * with nothing anywhere reporting a loss.
   *
   * `provenance` is the one whose loss is silent AND consequential: it marks a
   * policy as AUTHORED against the deployment, which is what locks the rules it
   * targets out of local re-assignment. A device that reads the bundle back
   * without it goes on enforcing the action while quietly handing the override
   * back.
   */
  it("keeps a policy's authored `provenance` across the round trip", async () => {
    const d = await dir();
    const store = createPolicyStore(d);
    await store.write(authored('v1'));
    const got = await store.read();
    expect(got?.bundle.policies[0]?.provenance).toBe('authored');
  });

  it('leaves `provenance` absent when the producer sent none', async () => {
    // The control for the case above: absent must stay absent rather than being
    // defaulted to a marker nobody sent. `provenance` absent reads as 'builtin',
    // and a builtin policy is the one a device MAY still re-assign locally.
    const d = await dir();
    const store = createPolicyStore(d);
    // Built by OMISSION rather than by setting `provenance: undefined`, which under
    // exactOptionalPropertyTypes is a different value from an absent key — and
    // an absent key is what an older producer actually sends.
    const builtinPolicy: Policy = {
      id: POLICY.id,
      scope: POLICY.scope,
      target: POLICY.target,
      action: POLICY.action,
      enabled: POLICY.enabled,
    };
    await store.write({ ...bundle('v1'), policies: [builtinPolicy] });
    const got = await store.read();
    expect(got?.bundle.policies).toHaveLength(1);
    expect(got?.bundle.policies[0]?.provenance).toBeUndefined();
  });
});

// The cache is the only copy of the organization's decisions a hook ever reads,
// and `PolicyBundle.parse` narrows it to the fields THIS build declares. A
// record an older build wrote is therefore missing whatever that build had
// never heard of, while still carrying the `version` of a representation that
// carried it — so replaying its validator earns a 304 forever and the missing
// field can never arrive. The stamp is what separates a device that recovers a
// governance decision from one that is told "nothing has changed" for the life
// of the install.
describe('the policy cache records which bundle shape wrote it', () => {
  const CACHE = 'policy-cache.json';

  async function restamp(d: string, shapeId: string | undefined): Promise<void> {
    const file = join(d, CACHE);
    const record = JSON.parse(await readFile(file, 'utf8')) as Record<string, unknown>;
    if (shapeId === undefined) delete record.shapeId;
    else record.shapeId = shapeId;
    await writeFile(file, JSON.stringify(record), 'utf8');
  }

  it('stamps every write with the shape this build understands', async () => {
    const d = await dir();
    await createPolicyStore(d).write(bundle('v1'), 'W/"e"');
    const record = JSON.parse(await readFile(join(d, CACHE), 'utf8')) as Record<string, unknown>;
    expect(record.shapeId).toBe(POLICY_BUNDLE_SHAPE_ID);
  });

  it("replays the validator when the stamp is this build's", async () => {
    // The positive control, and it is load-bearing: without it every assertion
    // below is satisfied by a read() that returns no etag at all, which would
    // cost each device a full bundle download on every single poll.
    const d = await dir();
    const store = createPolicyStore(d);
    await store.write(bundle('v1'), 'W/"e"');
    expect((await store.read())?.etag).toBe('W/"e"');
  });

  it("withholds the validator when the stamp is another build's", async () => {
    const d = await dir();
    const store = createPolicyStore(d);
    await store.write(bundle('v1'), 'W/"e"');
    await restamp(d, 'customKeywords,fetchedAt,policies,version');
    expect((await store.read())?.etag).toBeUndefined();
  });

  it('withholds the validator when there is no stamp at all', async () => {
    // Every cache written before the stamp existed looks like this, and those
    // are the ones actually on disk. An absent stamp has to read as a mismatch
    // or none of them is ever repaired.
    const d = await dir();
    const store = createPolicyStore(d);
    await store.write(bundle('v1'), 'W/"e"');
    await restamp(d, undefined);
    expect((await store.read())?.etag).toBeUndefined();
  });

  it('keeps the BUNDLE whatever the stamp says', async () => {
    // Only the validator is withheld. Returning null instead would take the
    // organization's raise-only floor with it until a sync lands — enforcement
    // lost in order to repair enforcement.
    const d = await dir();
    const store = createPolicyStore(d);
    await store.write(authored('v1'), 'W/"e"');
    await restamp(d, 'a-shape-this-build-does-not-have');
    const got = await store.read();
    expect(got?.bundle.version).toBe('v1');
    expect(got?.bundle.policies[0]?.provenance).toBe('authored');
  });
});

// One ~/.aka serves every host plugin on the machine, and they are separately
// published packages that upgrade on their own schedules — so during a rollout a
// build that understands fewer bundle fields is routinely sharing this cache
// with one that understands more. The read check above repairs a narrowed
// record; this is what stops the narrowing from being written in the first
// place, so the two builds do not take turns flattening and repairing the file.
describe('a narrower build does not flatten a wider record', () => {
  const CACHE = 'policy-cache.json';

  // This build's own key set plus one it has never heard of: what a LATER
  // build's stamp looks like from here.
  const WIDER = [...POLICY_BUNDLE_SHAPE_ID.split(','), 'zzzFutureField'].sort().join(',');

  async function record(d: string): Promise<Record<string, unknown>> {
    return JSON.parse(await readFile(join(d, CACHE), 'utf8')) as Record<string, unknown>;
  }

  async function restamp(d: string, shapeId: string): Promise<void> {
    const file = join(d, CACHE);
    const r = JSON.parse(await readFile(file, 'utf8')) as Record<string, unknown>;
    r.shapeId = shapeId;
    await writeFile(file, JSON.stringify(r), 'utf8');
  }

  it('leaves a record stamped by a build that knows MORE fields alone', async () => {
    // Same version on both sides: flattening would destroy fields this build
    // cannot name in order to land bytes the device already has.
    const d = await dir();
    const store = createPolicyStore(d);
    await store.write(bundle('wide'), 'W/"wide"');
    await restamp(d, WIDER);

    await store.write(bundle('wide'), 'W/"narrowed"');

    const got = await record(d);
    expect((got.bundle as { version: string }).version, 'the wider body survived').toBe('wide');
    expect(got.shapeId, "and so did the wider build's stamp").toBe(WIDER);
    expect(got.etag, 'the validator still describes the body beside it').toBe('W/"wide"');
  });

  it('still replaces a record with NO stamp — the repair must keep working', async () => {
    // The control that keeps the guard from swallowing its own fix. Every cache
    // written before stamping has no shapeId, and an absent stamp is not a
    // superset of anything.
    const d = await dir();
    const store = createPolicyStore(d);
    await store.write(bundle('v1'), 'W/"e1"');
    const file = join(d, CACHE);
    const r = JSON.parse(await readFile(file, 'utf8')) as Record<string, unknown>;
    delete r.shapeId;
    await writeFile(file, JSON.stringify(r), 'utf8');

    await store.write(bundle('v2'), 'W/"e2"');
    expect((await store.read())?.bundle.version).toBe('v2');
  });

  it('replaces a record stamped by a build that knows FEWER fields', async () => {
    // The repair direction: a wider build overwrites what a narrower one left.
    const d = await dir();
    const store = createPolicyStore(d);
    await store.write(bundle('narrow'), 'W/"e1"');
    await restamp(d, 'customKeywords,fetchedAt,policies,version');

    await store.write(bundle('wide'), 'W/"e2"');
    expect((await store.read())?.bundle.version).toBe('wide');
  });

  it('replaces a record stamped by this same build', async () => {
    const d = await dir();
    const store = createPolicyStore(d);
    await store.write(bundle('v1'), 'W/"e1"');
    await store.write(bundle('v2'), 'W/"e2"');
    expect((await store.read())?.bundle.version).toBe('v2');
  });
});

// Declining to narrow a record is only half the answer. The narrower build runs
// every window for the life of the install, so what it does on the way past
// decides whether the device keeps polling cheaply and keeps reporting itself
// as alive — or downloads the whole bundle forever while its console says it
// stopped syncing.
describe('a narrower build stays a good citizen of a wider record', () => {
  const CACHE = 'policy-cache.json';
  const WIDER = [...POLICY_BUNDLE_SHAPE_ID.split(','), 'zzzFutureField'].sort().join(',');

  async function record(d: string): Promise<Record<string, unknown>> {
    return JSON.parse(await readFile(join(d, CACHE), 'utf8')) as Record<string, unknown>;
  }

  async function restamp(d: string, shapeId: string): Promise<void> {
    const file = join(d, CACHE);
    const r = JSON.parse(await readFile(file, 'utf8')) as Record<string, unknown>;
    r.shapeId = shapeId;
    await writeFile(file, JSON.stringify(r), 'utf8');
  }

  it('REPLAYS the validator of a record that knows more than it does', async () => {
    // Without this the narrower build sends no If-None-Match every window and
    // the control plane answers with the whole bundle each time — the cheap
    // poll turned into a scheduled full transfer. A wider record already
    // carries everything this build declares, so its validator is one this
    // build has no reason to refetch against.
    const d = await dir();
    const store = createPolicyStore(d);
    await store.write(bundle('v1'), 'W/"wide"');
    await restamp(d, WIDER);
    expect((await store.read())?.etag).toBe('W/"wide"');
  });

  it('advances freshness, keeps the wider body, and adopts NO new validator', async () => {
    // The wider record carries a field this build does not declare. Without it
    // the "body stays" assertion is true by construction — prior and incoming
    // would be the same bundle — and flattening would pass the case.
    const d = await dir();
    const store = createPolicyStore(d);
    await store.write(bundle('same'), 'W/"old"');
    const file = join(d, CACHE);
    {
      const r = JSON.parse(await readFile(file, 'utf8')) as {
        shapeId: string;
        bundle: Record<string, unknown>;
      };
      r.shapeId = WIDER;
      r.bundle.zzzFutureField = 'only the wider build understands this';
      await writeFile(file, JSON.stringify(r), 'utf8');
    }
    const before = (await record(d)).fetchedAtMs as number;
    await new Promise((r) => setTimeout(r, 2));

    await store.write(bundle('same'), 'W/"new"');

    const after = await record(d);
    expect(
      (after.bundle as Record<string, unknown>).zzzFutureField,
      'the field only the wider build understands survived',
    ).toBe('only the wider build understands this');
    expect(after.shapeId, "the wider build's stamp is untouched").toBe(WIDER);
    expect(after.fetchedAtMs as number, 'freshness advanced').toBeGreaterThan(before);
    // Not adopted: pairing these bytes with a validator this build never held
    // for them would rest on the plane bumping `version` for every
    // representation it serves, which this package cannot check.
    expect(after.etag, 'the validator already on disk is kept').toBe('W/"old"');
  });

  it('WRITES a different version through, narrowed, rather than deadlocking', async () => {
    // The organization published a new policy. Declining because this build
    // cannot represent one field of the OLD one would strand the device: `read`
    // hands the wider validator back next pass, the pull returns the same 200,
    // and the write declines again every window, forever, while the sync
    // reports `ok`. Adopting it narrowed is strictly better — and the narrower
    // stamp is what makes the wider build restore its own fields next pull.
    const d = await dir();
    const store = createPolicyStore(d);
    await store.write(bundle('old'), 'W/"old"');
    await restamp(d, WIDER);

    await store.write(bundle('new'), 'W/"new"');

    const after = await record(d);
    expect((after.bundle as { version: string }).version, 'the new policy landed').toBe('new');
    expect(after.shapeId, "stamped with THIS build's shape, so the wider one refetches").toBe(
      POLICY_BUNDLE_SHAPE_ID,
    );
    expect(after.etag).toBe('W/"new"');
  });
});
