import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { SightingKey } from '@akasecurity/persistence';
import {
  dataDir as dataDirOf,
  FileKeyProvider,
  keysDir as keysDirOf,
  loadOrCreateFingerprintKey,
  openLocalDatabase,
  rotateFingerprintKey,
  SecretVault,
  UNAVAILABLE,
} from '@akasecurity/persistence';
import { captureWireId } from '@akasecurity/persistence';
import type { SecretSpan } from '@akasecurity/plugin-sdk';
import { contentHashOf } from '@akasecurity/plugin-sdk';
import type { IngestEvent, Rule } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import type {
  OutboundEncoder,
  OutboundEncoderDeps,
  PointerFingerprinter,
} from '../../src/attached/outbound-encoder.ts';
import {
  createOutboundEncoder,
  createStoreOutboundEncoder,
  encodedWireId,
  FAIL_CLOSED_MARKER,
} from '../../src/attached/outbound-encoder.ts';
import {
  emailShaped,
  expectedToken,
  keyOf,
  keysOf,
  patShaped,
  storeSightingKey,
} from '../helpers/sighting-fixtures.ts';

const pointerOf = (category: string, fill: string): string =>
  `[[aka:${category}:AE.${fill.repeat(26)}.${'B'.repeat(16)}]]`;

function must<T>(value: T | undefined): T {
  if (value === undefined) throw new Error('expected the capture to be encoded, not held');
  return value;
}

const ID_KEY = Buffer.alloc(32, 7);

const noInstalledRules = (): Promise<readonly Rule[]> => Promise.resolve([]);

function rawEncoderWith(
  key: SightingKey | undefined,
  overrides: Partial<OutboundEncoderDeps> = {},
): OutboundEncoder {
  return createOutboundEncoder({
    readKeys: () => (key === undefined ? undefined : keysOf(key)),
    openVault: () => {
      throw new Error('no vault in this test');
    },
    loadRules: noInstalledRules,
    readSharing: () => true,
    readIdKey: () => ID_KEY,
    ...overrides,
  });
}

function encoderWith(key: SightingKey | undefined, overrides: Partial<OutboundEncoderDeps> = {}) {
  const encoder = rawEncoderWith(key, overrides);
  return {
    encodeContent: async (text: string) => must(await encoder.encodeContent(text)),
    encodeEvent: async (event: IngestEvent) => must(await encoder.encodeEvent(event)),
  };
}

const scannerOf = (find: (text: string) => Promise<SecretSpan[]>) => () => ({
  find,
  close: () => Promise.resolve(),
});

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
      createScanner: scannerOf(() =>
        Promise.resolve([{ start: 3, end: 13, ruleId: 'r', category: 'secret', value: undefined }]),
      ),
    }).encodeContent(text);
    expect(result.content).toBe(`xx ${FAIL_CLOSED_MARKER} yy`);
  });

  it('holds the capture when the scan cannot start or finish', async () => {
    const encoder = rawEncoderWith(keyOf(1, 8), {
      createScanner: scannerOf(() => Promise.reject(new Error('scan fault'))),
    });
    await expect(encoder.encodeContent(`keep ${value} out`)).resolves.toBeUndefined();
  });

  it('reuses one scanner across captures and closes it with the encoder', async () => {
    let created = 0;
    let closed = 0;
    const encoder = rawEncoderWith(keyOf(1, 9), {
      createScanner: () => {
        created += 1;
        return {
          find: () => Promise.resolve([]),
          close: () => {
            closed += 1;
            return Promise.resolve();
          },
        };
      },
    });
    await encoder.encodeContent('one');
    await encoder.encodeContent('two');
    expect(created).toBe(1);
    expect(closed).toBe(0);
    await encoder.close();
    expect(closed).toBe(1);
  });

  it('holds the capture when the effective rules cannot be loaded', async () => {
    const encoder = rawEncoderWith(keyOf(1, 8), {
      loadRules: () => Promise.reject(new Error('store unreadable')),
    });
    await expect(encoder.encodeContent(`keep ${value} out`)).resolves.toBeUndefined();
  });

  it('tokenises a value only an installed secret rule matches', async () => {
    const key = keyOf(3, 3);
    const installedValue = ['ACME', 'TOK', '4'.repeat(10)].join('');
    const installed: Rule = {
      specVersion: 1,
      id: 'acme/internal-token',
      name: 'Internal token',
      category: 'secret',
      severity: 'high',
      matcher: { type: 'regex', pattern: 'ACMETOK[0-9]{10}', flags: 'g' },
    };
    const result = await encoderWith(key, {
      loadRules: () => Promise.resolve([installed]),
    }).encodeContent(`a ${installedValue} b`);
    expect(result.content).toBe(`a ${expectedToken(key, installedValue)} b`);
    expect(result.sightings).toEqual([
      {
        token: expectedToken(key, installedValue),
        ruleId: 'acme/internal-token',
        category: 'secret',
      },
    ]);
  });

  it('lists a repeated value once', async () => {
    const key = keyOf(2, 9);
    const result = await encoderWith(key).encodeContent(`${value} and ${value}`);
    const expected = expectedToken(key, value);
    expect(result.content).toBe(`${expected} and ${expected}`);
    expect(result.sightings).toHaveLength(1);
  });
});

describe('outbound encoder: previous key versions', () => {
  const value = patShaped(19);
  const current = keyOf(5, 1);
  const older = keyOf(3, 2);
  const newer = keyOf(4, 3);
  const withPrevious = (previous: SightingKey[]) =>
    encoderWith(current, { readKeys: () => ({ current, previous }) });

  it('lists the value under each previous version as aliases, and puts only the current token in content', async () => {
    const result = await withPrevious([older, newer]).encodeContent(`push ${value}`);
    expect(result.content).toBe(`push ${expectedToken(current, value)}`);
    expect(result.content).not.toContain(expectedToken(newer, value));
    expect(result.sightings).toEqual([
      {
        token: expectedToken(current, value),
        aliases: [expectedToken(newer, value), expectedToken(older, value)],
        ruleId: 'secrets/github-pat',
        category: 'secret',
      },
    ]);
  });

  it('carries no aliases member with no previous version', async () => {
    const result = await withPrevious([]).encodeContent(value);
    expect(result.sightings[0]).not.toHaveProperty('aliases');
  });

  it('gives a vaulted secret its aliases too', async () => {
    const vaulted = patShaped(29);
    const result = await encoderWith(current, {
      readKeys: () => ({ current, previous: [older] }),
      openVault: () => ({
        vault: {
          fingerprintPointer: (_token, digest) =>
            Promise.resolve({ digest: digest(vaulted), ruleId: 'secrets/vaulted' }),
        },
        close: () => undefined,
      }),
    }).encodeContent(pointerOf('secret', 'A'));
    expect(result.content).toBe(expectedToken(current, vaulted));
    expect(result.sightings).toEqual([
      {
        token: expectedToken(current, vaulted),
        aliases: [expectedToken(older, vaulted)],
        ruleId: 'secrets/vaulted',
        category: 'secret',
      },
    ]);
  });

  it('never puts a raw value anywhere in the event it sends', async () => {
    const encoder = withPrevious([older]);
    const content = `k ${value}`;
    const encoded = await encoder.encodeEvent({
      id: captureWireId('s', contentHashOf(content), null),
      sourceTool: 'claude-code',
      kind: 'prompt',
      occurredAt: '2026-10-01T10:00:00.000Z',
      contentHash: contentHashOf(content),
      content,
      metadata: { sessionId: 's' },
    });
    expect(encoded.metadata?.sightings?.[0]?.aliases).toEqual([expectedToken(older, value)]);
    expect(JSON.stringify(encoded)).not.toContain(value);
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
    id: captureWireId(metadata?.sessionId ?? null, contentHashOf(content), null),
    sourceTool: 'claude-code',
    kind: 'prompt',
    occurredAt: '2026-10-01T10:00:00.000Z',
    contentHash: contentHashOf(content),
    content,
    ...(metadata === undefined ? {} : { metadata }),
  });

  it('never sends the hash of the raw content, nor an id derived from it', async () => {
    const value = patShaped(37);
    const raw = event(value, { sessionId: 'sess-1' });
    const encoded = await encoderWith(keyOf(2, 4)).encodeEvent(raw);
    expect(encoded.contentHash).not.toBe(contentHashOf(value));
    expect(encoded.contentHash).toBe(contentHashOf(encoded.content));
    expect(encoded.id).not.toBe(raw.id);
    expect(encoded.id).toBe(encodedWireId(ID_KEY, 'sess-1', raw.contentHash, null));
    expect(encoded.id).not.toBe(captureWireId('sess-1', contentHashOf(encoded.content), null));
    expect(JSON.stringify(encoded)).not.toContain(contentHashOf(value));
  });

  it('derives the same wire id on every encoding of a row, from the identity it is given', async () => {
    const value = patShaped(43);
    const raw = event(`p ${value}`, { sessionId: 'sess-2', filePath: 'a.ts' });
    const encoder = rawEncoderWith(keyOf(2, 5));
    const first = must(await encoder.encodeEvent(raw, { sessionId: 'sess-2', filePath: '' }));
    const again = must(await encoder.encodeEvent(raw, { sessionId: 'sess-2', filePath: '' }));
    expect(again.id).toBe(first.id);
    expect(first.id).toBe(encodedWireId(ID_KEY, 'sess-2', raw.contentHash, ''));
  });

  it('keeps captures that differ only in their secret apart, with sharing on or off', async () => {
    const identity = { sessionId: 's', filePath: '' };
    for (const sharing of [false, true]) {
      const encoder = rawEncoderWith(keyOf(1, 1), { readSharing: () => sharing });
      const a = must(await encoder.encodeEvent(event(`deploy with ${patShaped(11)}`), identity));
      const b = must(await encoder.encodeEvent(event(`deploy with ${patShaped(29)}`), identity));
      if (!sharing) expect(a.content).toBe(b.content);
      expect(a.id).not.toBe(b.id);
    }
  });

  it('keys the wire id, so another machine derives a different one for the same row', async () => {
    const raw = event(`p ${patShaped(47)}`, { sessionId: 'sess-3' });
    const here = must(await rawEncoderWith(keyOf(1, 1)).encodeEvent(raw));
    const elsewhere = must(
      await rawEncoderWith(keyOf(1, 1), { readIdKey: () => Buffer.alloc(32, 8) }).encodeEvent(raw),
    );
    expect(elsewhere.content).toBe(here.content);
    expect(elsewhere.id).not.toBe(here.id);
  });

  it('holds an encoded event when the id key cannot be read', async () => {
    const encoder = rawEncoderWith(keyOf(1, 1), {
      readIdKey: () => {
        throw new Error('key unreadable');
      },
    });
    await expect(encoder.encodeEvent(event(`p ${patShaped(53)}`))).resolves.toBeUndefined();
  });

  it('holds an event when the effective rules cannot be loaded', async () => {
    const encoder = rawEncoderWith(keyOf(1, 2), {
      loadRules: () => Promise.reject(new Error('store unreadable')),
    });
    await expect(encoder.encodeEvent(event('anything'))).resolves.toBeUndefined();
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

const encoderOver = (base: string) => {
  const encoder = createStoreOutboundEncoder(base, { loadRules: noInstalledRules });
  return { encodeContent: async (text: string) => must(await encoder.encodeContent(text)) };
};

describe('createStoreOutboundEncoder', () => {
  let base: string;

  beforeEach(() => {
    base = mkdtempSync(join(tmpdir(), 'aka-encoder-'));
  });

  afterEach(() => {
    removeTree(base);
  });

  it('keeps the wire id of an encoded capture when the exception key rotates', async () => {
    storeSightingKey(base, keyOf(6, 5));
    const content = `p ${patShaped(59)}`;
    const raw: IngestEvent = {
      id: captureWireId('sess-r', contentHashOf(content), null),
      sourceTool: 'claude-code',
      kind: 'prompt',
      occurredAt: '2026-10-01T10:00:00.000Z',
      contentHash: contentHashOf(content),
      content,
      metadata: { sessionId: 'sess-r' },
    };
    loadOrCreateFingerprintKey(dataDirOf(base));
    const before = must(
      await createStoreOutboundEncoder(base, { loadRules: noInstalledRules }).encodeEvent(raw),
    );
    rotateFingerprintKey(dataDirOf(base));
    const after = must(
      await createStoreOutboundEncoder(base, { loadRules: noInstalledRules }).encodeEvent(raw),
    );
    expect(after.id).toBe(before.id);
  });

  it('resolves a vaulted secret through the audited path, never logging the value', async () => {
    const key = keyOf(6, 4);
    storeSightingKey(base, key);
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
      const result = await encoderOver(base).encodeContent(`use ${minted}`);
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

  it('uses a stored previous version only inside its window', async () => {
    const key = keyOf(7, 4);
    const previous = keyOf(6, 5);
    const value = patShaped(47);
    const until = (offsetMs: number) => new Date(Date.now() + offsetMs).toISOString();

    storeSightingKey(base, key, { previous: [{ key: previous, acceptedUntil: until(60_000) }] });
    const inside = await encoderOver(base).encodeContent(value);
    expect(inside.sightings[0]?.aliases).toEqual([expectedToken(previous, value)]);

    storeSightingKey(base, key, { previous: [{ key: previous, acceptedUntil: until(-1_000) }] });
    const past = await encoderOver(base).encodeContent(value);
    expect(past.sightings[0]).not.toHaveProperty('aliases');

    storeSightingKey(base, key, { previous: [{ key: previous }] });
    const unbounded = await encoderOver(base).encodeContent(value);
    expect(unbounded.sightings[0]).not.toHaveProperty('aliases');
    expect(unbounded.content).toBe(expectedToken(key, value));
  });

  it('sends no alias, and no token at all, while sighting sharing is off', async () => {
    const key = keyOf(7, 4);
    const previous = keyOf(6, 5);
    const value = patShaped(53);
    const acceptedUntil = new Date(Date.now() + 60_000).toISOString();
    storeSightingKey(base, key, { sharing: false, previous: [{ key: previous, acceptedUntil }] });

    const result = await encoderOver(base).encodeContent(value);

    expect(result).toEqual({ content: FAIL_CLOSED_MARKER, sightings: [] });
    expect(result.content).not.toContain(expectedToken(previous, value));
  });

  it('sends the marker for a pointer the vault does not hold', async () => {
    const key = keyOf(1, 5);
    storeSightingKey(base, key);
    const result = await encoderOver(base).encodeContent(pointerOf('secret', 'D'));
    expect(result.content).toBe(FAIL_CLOSED_MARKER);
  });
});

describe('outbound encoder: the sighting-sharing gate', () => {
  const value = patShaped(101);
  const pointer = pointerOf('secret', 'E');

  it('sends only markers, no token and no sightings, while sharing is off', async () => {
    let opened = 0;
    const result = await encoderWith(keyOf(1, 1), {
      readSharing: () => false,
      openVault: () => {
        opened += 1;
        throw new Error('the vault is not opened while sharing is off');
      },
    }).encodeContent(`a ${value} b ${pointer}`);
    expect(result).toEqual({
      content: `a ${FAIL_CLOSED_MARKER} b ${FAIL_CLOSED_MARKER}`,
      sightings: [],
    });
    expect(result.content).not.toContain('[[aka:fp:');
    expect(opened).toBe(0);
  });

  it('asks the gate on every capture, so a change applies to the next one', async () => {
    let sharing = true;
    const encoder = encoderWith(keyOf(2, 2), { readSharing: () => sharing });
    expect((await encoder.encodeContent(value)).content).toContain('[[aka:fp:v2.');
    sharing = false;
    expect((await encoder.encodeContent(value)).content).toBe(FAIL_CLOSED_MARKER);
    sharing = true;
    expect((await encoder.encodeContent(value)).content).toContain('[[aka:fp:v2.');
  });

  it('treats a gate that throws as sharing off', async () => {
    const result = await encoderWith(keyOf(1, 3), {
      readSharing: () => {
        throw new Error('settings unreadable');
      },
    }).encodeContent(value);
    expect(result).toEqual({ content: FAIL_CLOSED_MARKER, sightings: [] });
  });
});
