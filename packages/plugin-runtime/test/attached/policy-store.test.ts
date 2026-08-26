import { mkdtemp, readdir, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { PolicyBundle } from '@akasecurity/schema';
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
});
