import { mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { SightingKeys } from '@akasecurity/persistence';
import { sightingToken } from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  CREDENTIAL_LOOKUPS_FILENAME,
  pastedCredentialNote,
  readCredentialLookups,
  saveCredentialLookups,
  swapPastedCredentials,
} from '../../src/credentials/pasted.ts';

const TOKEN = `github_pat_${'A1b2C3d4E5'.repeat(8)}xy`;
const OTHER = `ghp_${'Z9y8X7w6V5'.repeat(3)}abcdef`;
const CURRENT = { keyVersion: 2, key: new Uint8Array(32).fill(2) };
const PREVIOUS = { keyVersion: 1, key: new Uint8Array(32).fill(1) };
const KEYS: SightingKeys = { current: CURRENT, previous: [PREVIOUS] };

function secret(rawMatch: string) {
  return { category: 'secret', rawMatch };
}

describe('swapPastedCredentials', () => {
  it('replaces every occurrence of a vaulted value with its handle', () => {
    const lookups = new Map([[sightingToken(CURRENT, TOKEN), 'github-demo']]);
    const out = swapPastedCredentials(
      `use ${TOKEN} then ${TOKEN} again`,
      [secret(TOKEN)],
      lookups,
      KEYS,
    );

    expect(out.text).toBe('use [[aka:cred:github-demo]] then [[aka:cred:github-demo]] again');
    expect(out.swapped).toEqual([{ slug: 'github-demo', rawMatch: TOKEN }]);
  });

  it('matches a lookup made under a previous key version', () => {
    const lookups = new Map([[sightingToken(PREVIOUS, TOKEN), 'github-demo']]);

    expect(swapPastedCredentials(TOKEN, [secret(TOKEN)], lookups, KEYS).text).toBe(
      '[[aka:cred:github-demo]]',
    );
  });

  it('leaves values that are not vaulted, and findings that are not secrets', () => {
    const lookups = new Map([[sightingToken(CURRENT, TOKEN), 'github-demo']]);
    const text = `${OTHER} ${TOKEN}`;
    const out = swapPastedCredentials(
      text,
      [secret(OTHER), { category: 'pii', rawMatch: TOKEN }],
      lookups,
      KEYS,
    );

    expect(out).toEqual({ text, swapped: [] });
  });

  it('does not match under a different organization key', () => {
    const lookups = new Map([[sightingToken(CURRENT, TOKEN), 'github-demo']]);
    const elsewhere: SightingKeys = {
      current: { keyVersion: 2, key: new Uint8Array(32).fill(9) },
      previous: [],
    };

    expect(swapPastedCredentials(TOKEN, [secret(TOKEN)], lookups, elsewhere).swapped).toEqual([]);
  });
});

describe('credential lookups file', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-lookups-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('round-trips the lookups of credentials that carry them, owner-only', () => {
    saveCredentialLookups(dir, [
      { slug: 'github-demo', description: '', lookups: ['t1', 't2'] },
      { slug: 'no-lookups', description: '' },
    ]);

    expect([...readCredentialLookups(dir)]).toEqual([
      ['t1', 'github-demo'],
      ['t2', 'github-demo'],
    ]);
    if (process.platform !== 'win32') {
      expect(statSync(join(dir, CREDENTIAL_LOOKUPS_FILENAME)).mode & 0o777).toBe(0o600);
    }
  });

  it('removes the file when no credential carries a lookup', () => {
    saveCredentialLookups(dir, [{ slug: 'github-demo', description: '', lookups: ['t1'] }]);
    saveCredentialLookups(dir, []);

    expect(readCredentialLookups(dir).size).toBe(0);
  });

  it('reads a corrupt file as no lookups', () => {
    writeFileSync(join(dir, CREDENTIAL_LOOKUPS_FILENAME), '{not json');

    expect(readCredentialLookups(dir).size).toBe(0);
  });
});

describe('pastedCredentialNote', () => {
  it('names each handle once', () => {
    expect(
      pastedCredentialNote([
        { slug: 'github-demo', rawMatch: 'a' },
        { slug: 'github-demo', rawMatch: 'b' },
      ]),
    ).toContain('([[aka:cred:github-demo]])');
  });
});
