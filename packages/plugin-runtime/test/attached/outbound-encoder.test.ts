import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { SightingKey } from '@akasecurity/persistence';
import {
  createSightingKeyStore,
  dataDir as dataDirOf,
  FileKeyProvider,
  keysDir as keysDirOf,
  loadOrCreateFingerprintKey,
  openLocalDatabase,
  SecretVault,
  UNAVAILABLE,
} from '@akasecurity/persistence';
import type { IngestEvent } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type {
  OutboundEncoderDeps,
  PointerFingerprinter,
} from '../../src/attached/outbound-encoder.ts';
import {
  createOutboundEncoder,
  createStoreOutboundEncoder,
  FAIL_CLOSED_MARKER,
} from '../../src/attached/outbound-encoder.ts';
import {
  emailShaped,
  expectedToken,
  keyOf,
  keysOf,
  materialOf,
  patShaped,
} from '../helpers/sighting-fixtures.ts';

const pointerOf = (category: string, fill: string): string =>
  `[[aka:${category}:AE.${fill.repeat(26)}.${'B'.repeat(16)}]]`;

function encoderWith(
  key: SightingKey | undefined,
  overrides: Partial<OutboundEncoderDeps> = {},
): ReturnType<typeof createOutboundEncoder> {
  return createOutboundEncoder({
    readKeys: () => (key === undefined ? undefined : keysOf(key)),
    openVault: () => {
      throw new Error('no vault in this test');
    },
    ...overrides,
  });
}

describe('outbound encoder: values', () => {
  const value = patShaped(17);

  it('replaces a secret with its versioned fingerprint token and names its rule', async () => {
    const key = keyOf(4, 1);
    const result = await encoderWith(key).encodeContent(`push with ${value} please`);
    expect(result.content).toBe(`push with ${expectedToken(key, value)} please`);
    expect(result.sightings).toEqual([
      { token: expectedToken(key, value), ruleId: 'secrets/github-pat', category: 'secret' },
    ]);
  });

  it('gives a padded value the same token as the bare one', async () => {
    const key = keyOf(1, 2);
    const padded = `${value.slice(0, 8)}\u200B${value.slice(8)}`;
    const bare = await encoderWith(key).encodeContent(value);
    const result = await encoderWith(key).encodeContent(padded);
    expect(result.content).toBe(bare.content);
    expect(result.content).toBe(expectedToken(key, value));
  });

  it('leaves other categories untouched', async () => {
    const text = `${emailShaped()} sent ${value}`;
    const result = await encoderWith(keyOf(1, 3)).encodeContent(text);
    expect(result.content.startsWith(`${emailShaped()} sent [[aka:fp:v1.`)).toBe(true);
  });

  it('yields different tokens under different keys', async () => {
    const a = await encoderWith(keyOf(1, 4)).encodeContent(value);
    const b = await encoderWith(keyOf(1, 5)).encodeContent(value);
    expect(a.content).not.toBe(b.content);
  });

  it('sends the marker when no key is stored', async () => {
    const result = await encoderWith(undefined).encodeContent(`a ${value} b`);
    expect(result).toEqual({ content: `a ${FAIL_CLOSED_MARKER} b`, sightings: [] });
  });

  it('sends the marker when reading the key throws', async () => {
    const result = await encoderWith(keyOf(1, 6), {
      readKeys: () => {
        throw new Error('custody fault');
      },
    }).encodeContent(`a ${value} b`);
    expect(result.content).toBe(`a ${FAIL_CLOSED_MARKER} b`);
  });

  it('sends the marker when hashing the value fails', async () => {
    const broken = { keyVersion: 1, key: null } as unknown as SightingKey;
    const result = await encoderWith(broken).encodeContent(`a ${value} b`);
    expect(result).toEqual({ content: `a ${FAIL_CLOSED_MARKER} b`, sightings: [] });
  });

  it('sends the marker for a span no single value covers', async () => {
    const text = 'xx 0123456789 yy';
    const result = await encoderWith(keyOf(1, 7), {
      findSpans: () => [{ start: 3, end: 13, ruleId: 'r', category: 'secret', value: undefined }],
    }).encodeContent(text);
    expect(result.content).toBe(`xx ${FAIL_CLOSED_MARKER} yy`);
  });

  it('replaces the whole content with the marker when the scan fails', async () => {
    const result = await encoderWith(keyOf(1, 8), {
      findSpans: () => {
        throw new Error('scan fault');
      },
    }).encodeContent(`keep ${value} out`);
    expect(result).toEqual({ content: FAIL_CLOSED_MARKER, sightings: [] });
  });

  it('lists a repeated value once', async () => {
    const key = keyOf(2, 9);
    const result = await encoderWith(key).encodeContent(`${value} and ${value}`);
    const expected = expectedToken(key, value);
    expect(result.content).toBe(`${expected} and ${expected}`);
    expect(result.sightings).toHaveLength(1);
  });
});

describe('outbound encoder: vault pointers', () => {
  const vaulted = patShaped(23);
  const secretPointer = pointerOf('secret', 'A');
  const piiPointer = pointerOf('pii', 'C');

  function fakeVault(
    answer: (
      token: string,
      digest: (raw: string) => string,
    ) => ReturnType<PointerFingerprinter['fingerprintPointer']>,
  ): { deps: Partial<OutboundEncoderDeps>; opened: () => number; closed: () => number } {
    let opened = 0;
    let closed = 0;
    return {
      deps: {
        openVault: () => {
          opened += 1;
          return {
            vault: { fingerprintPointer: answer },
            close: () => {
              closed += 1;
            },
          };
        },
      },
      opened: () => opened,
      closed: () => closed,
    };
  }

  it('resolves a secret pointer through the vault to its token, once per capture', async () => {
    const key = keyOf(3, 1);
    const asked: string[] = [];
    const vault = fakeVault((token, digest) => {
      asked.push(token);
      return Promise.resolve({ digest: digest(vaulted), ruleId: 'secrets/vaulted' });
    });
    const result = await encoderWith(key, vault.deps).encodeContent(
      `a ${secretPointer} b ${piiPointer} c ${secretPointer}`,
    );
    const expected = expectedToken(key, vaulted);
    expect(result.content).toBe(`a ${expected} b ${piiPointer} c ${expected}`);
    expect(result.sightings).toEqual([
      { token: expected, ruleId: 'secrets/vaulted', category: 'secret' },
    ]);
    expect(asked).toEqual([secretPointer]);
    expect(vault.opened()).toBe(1);
    expect(vault.closed()).toBe(1);
  });

  it('sends the marker when the vault cannot resolve the pointer', async () => {
    const vault = fakeVault(() => Promise.resolve(UNAVAILABLE));
    const result = await encoderWith(keyOf(1, 2), vault.deps).encodeContent(`x ${secretPointer}`);
    expect(result).toEqual({ content: `x ${FAIL_CLOSED_MARKER}`, sightings: [] });
    expect(vault.closed()).toBe(1);
  });

  it('sends the marker when the vault throws', async () => {
    const vault = fakeVault(() => Promise.reject(new Error('vault fault')));
    const result = await encoderWith(keyOf(1, 3), vault.deps).encodeContent(secretPointer);
    expect(result.content).toBe(FAIL_CLOSED_MARKER);
  });

  it('sends the marker when the vault cannot be opened', async () => {
    const result = await encoderWith(keyOf(1, 4)).encodeContent(secretPointer);
    expect(result.content).toBe(FAIL_CLOSED_MARKER);
  });

  it('sends the marker without opening the vault when no key is stored', async () => {
    const vault = fakeVault(() => Promise.resolve({ digest: 'x', ruleId: 'r' }));
    const result = await encoderWith(undefined, vault.deps).encodeContent(secretPointer);
    expect(result.content).toBe(FAIL_CLOSED_MARKER);
    expect(vault.opened()).toBe(0);
  });

  it('does not open the vault for content with no secret pointer', async () => {
    const vault = fakeVault(() => Promise.resolve(UNAVAILABLE));
    const result = await encoderWith(keyOf(1, 5), vault.deps).encodeContent(`only ${piiPointer}`);
    expect(result.content).toBe(`only ${piiPointer}`);
    expect(vault.opened()).toBe(0);
  });
});

describe('outbound encoder: events', () => {
  const event = (content: string, metadata?: IngestEvent['metadata']): IngestEvent => ({
    id: '00000000-0000-4000-8000-000000000001',
    sourceTool: 'claude-code',
    kind: 'prompt',
    occurredAt: '2026-10-01T10:00:00.000Z',
    contentHash: 'h',
    content,
    ...(metadata === undefined ? {} : { metadata }),
  });

  it('returns the same event when nothing needs encoding', async () => {
    const plain = event('nothing secret here', { repo: 'r' });
    await expect(encoderWith(keyOf(1, 1)).encodeEvent(plain)).resolves.toBe(plain);
  });

  it('rewrites content and records sightings beside the other metadata', async () => {
    const key = keyOf(5, 2);
    const value = patShaped(31);
    const encoded = await encoderWith(key).encodeEvent(event(`k ${value}`, { repo: 'r' }));
    expect(encoded.content).toBe(`k ${expectedToken(key, value)}`);
    expect(encoded.metadata).toEqual({
      repo: 'r',
      sightings: [
        { token: expectedToken(key, value), ruleId: 'secrets/github-pat', category: 'secret' },
      ],
    });
  });

  it('drops sightings the event already carried', async () => {
    const forged = event('plain', {
      sightings: [{ token: expectedToken(keyOf(1, 1), 'x'), ruleId: 'r', category: 'secret' }],
    });
    const encoded = await encoderWith(keyOf(1, 3)).encodeEvent(forged);
    expect(encoded.metadata).toEqual({});
  });
});

describe('createStoreOutboundEncoder', () => {
  let base: string;

  beforeEach(() => {
    base = mkdtempSync(join(tmpdir(), 'aka-encoder-'));
  });

  afterEach(() => {
    rmSync(base, { recursive: true, force: true });
  });

  it('resolves a vaulted secret through the audited path, never logging the value', async () => {
    const key = keyOf(6, 4);
    createSightingKeyStore('file', keysDirOf(base)).replace({
      keyVersion: key.keyVersion,
      algorithm: 'hmac-sha256',
      key: materialOf(key),
      fetchedAtMs: 1,
    });
    const value = patShaped(41);
    const db = openLocalDatabase(dataDirOf(base));
    try {
      const minted = await new SecretVault({
        repo: db.secretVault,
        keys: new FileKeyProvider(keysDirOf(base)),
        isConsented: () => true,
      }).tokenize(
        value,
        { ruleId: 'secrets/github-pat', category: 'secret', maskedMatch: 'gh****' },
        () => loadOrCreateFingerprintKey(dataDirOf(base)),
      );
      if (typeof minted !== 'string') throw new Error('expected a pointer');

      const log = vi.spyOn(console, 'log');
      const result = await createStoreOutboundEncoder(base).encodeContent(`use ${minted}`);
      expect(log).not.toHaveBeenCalled();
      log.mockRestore();

      expect(result.content).toBe(`use ${expectedToken(key, value)}`);
      expect(result.sightings).toEqual([
        { token: expectedToken(key, value), ruleId: 'secrets/github-pat', category: 'secret' },
      ]);
      const derefs = db.secretVault.listDerefs({ includeBatched: true }).items;
      expect(derefs).toHaveLength(1);
      expect(derefs[0]).toMatchObject({
        target: 'fingerprint',
        reason: 'sighting',
        outcome: 'revealed',
      });
      expect(JSON.stringify(derefs)).not.toContain(value);
    } finally {
      db.close();
    }
  });

  it('sends the marker for a pointer the vault does not hold', async () => {
    const key = keyOf(1, 5);
    createSightingKeyStore('file', keysDirOf(base)).replace({
      keyVersion: key.keyVersion,
      algorithm: 'hmac-sha256',
      key: materialOf(key),
      fetchedAtMs: 1,
    });
    const result = await createStoreOutboundEncoder(base).encodeContent(pointerOf('secret', 'D'));
    expect(result.content).toBe(FAIL_CLOSED_MARKER);
  });
});
