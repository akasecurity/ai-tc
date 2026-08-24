import type * as NodeCrypto from 'node:crypto';
import { mkdtemp, readFile, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { PolicyBundle } from '@akasecurity/schema';
import { describe, expect, it, vi } from 'vitest';

// The temp name is randomised in production precisely so it cannot be guessed.
// That also makes the O_EXCL guarantee untestable — a planted path is never the
// one used. Pinning the uuid here is what makes the guarantee observable: with
// `wx` the open fails and the victim is untouched; without it, `writeFile`
// FOLLOWS the symlink and writes the cache straight through to the target.
const FIXED = '00000000-0000-4000-8000-000000000000';
vi.mock('node:crypto', async (orig) => ({
  ...(await orig<typeof NodeCrypto>()),
  randomUUID: () => FIXED,
}));

const { createPolicyStore } = await import('../../src/attached/policy-store.ts');

const bundle = (): PolicyBundle => ({
  version: 'v1',
  policies: [],
  rules: [],
  customKeywords: [],
  fetchedAt: '2026-08-19T00:00:00.000Z',
});

describe.skipIf(process.platform === 'win32')('the temp file is creation-exclusive', () => {
  it('does not write through a symlink planted at the temp path', async () => {
    const d = await mkdtemp(join(tmpdir(), 'aka-policy-symlink-'));
    const victim = join(d, 'victim.txt');
    await writeFile(victim, 'untouched', 'utf8');
    await symlink(victim, join(d, `policy-cache.json.${FIXED}.tmp`));

    const store = createPolicyStore(d);
    // `wx` refuses the pre-existing path, so the write fails loudly rather than
    // silently redirecting. Failing is the correct outcome: runPolicySync
    // records it, and the previous cache stays intact.
    await expect(store.write(bundle())).rejects.toThrow();
    expect(await readFile(victim, 'utf8')).toBe('untouched');
  });
});
