import { existsSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { StoredSightingKeys } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { keysDir } from '../../src/local-layout.ts';
import { DATA_FILE_MODE } from '../../src/paths.ts';
import { applyOnboarding } from '../../src/settings.ts';
import type { SecurityExec } from '../../src/vault/key-provider.ts';
import { VAULT_KEY_FILENAME } from '../../src/vault/key-provider.ts';
import {
  createSightingKeyStore,
  readSightingKeys,
  SIGHTING_KEY_FILENAME,
} from '../../src/vault/sighting-keys.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

const POSIX_MODES = process.platform !== 'win32';

const material = (fill: number): string => Buffer.alloc(32, fill).toString('base64url');

const stored = (overrides: Partial<StoredSightingKeys> = {}): StoredSightingKeys => ({
  keyVersion: 2,
  algorithm: 'hmac-sha256',
  key: material(7),
  previous: [{ keyVersion: 1, key: material(3) }],
  fetchedAtMs: 1_766_000_000_000,
  ...overrides,
});

/** An in-memory keychain answering the `security` calls the store makes. */
function fakeKeychain(): {
  exec: SecurityExec;
  items: Map<string, string>;
  calls: { args: string[]; stdin: string | undefined }[];
} {
  const items = new Map<string, string>();
  const calls: { args: string[]; stdin: string | undefined }[] = [];
  const arg = (tokens: string[], flag: string): string => tokens[tokens.indexOf(flag) + 1] ?? '';
  const exec: SecurityExec = (args, stdin) => {
    calls.push({ args, stdin });
    if (args[0] === 'find-generic-password') {
      const item = items.get(`${arg(args, '-s')}/${arg(args, '-a')}`);
      if (item === undefined) throw Object.assign(new Error('item not found'), { status: 44 });
      return `${item}\n`;
    }
    const tokens = (stdin ?? '').trim().split(' ');
    const hex = arg(tokens, '-X');
    items.set(
      `${arg(tokens, '-s')}/${arg(tokens, '-a')}`,
      Buffer.from(hex, 'hex').toString('utf8'),
    );
    return '';
  };
  return { exec, items, calls };
}

let base: string;
let dir: string;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-sighting-home-'));
  dir = keysDir(base);
});

afterEach(() => {
  rmSync(base, { recursive: true, force: true });
});

describe('file custody', () => {
  it('reads absent as undefined, and creates nothing', () => {
    expect(createSightingKeyStore('file', dir).read()).toBeUndefined();
    expect(readSightingKeys(base)).toBeUndefined();
    expect(existsSync(join(dir, SIGHTING_KEY_FILENAME))).toBe(false);
  });

  it('round-trips the stored map under its own file, beside and apart from the vault key', () => {
    const store = createSightingKeyStore('file', dir);
    store.replace(stored());

    expect(store.read()).toEqual(stored());
    expect(existsSync(join(dir, SIGHTING_KEY_FILENAME))).toBe(true);
    expect(existsSync(join(dir, VAULT_KEY_FILENAME))).toBe(false);
  });

  it.skipIf(!POSIX_MODES)('writes the file owner-only', () => {
    createSightingKeyStore('file', dir).replace(stored());
    expect(statSync(join(dir, SIGHTING_KEY_FILENAME)).mode & 0o777).toBe(DATA_FILE_MODE);
  });

  it('replaces the stored map wholesale, previous versions included, and leaves no temp file', () => {
    const store = createSightingKeyStore('file', dir);
    store.replace(stored());
    store.replace(stored({ keyVersion: 3, key: material(9), previous: [], fetchedAtMs: 5 }));

    expect(store.read()).toEqual(
      stored({ keyVersion: 3, key: material(9), previous: [], fetchedAtMs: 5 }),
    );
    expect(readdirSync(dir)).toEqual([SIGHTING_KEY_FILENAME]);
  });

  it('refuses a corrupt file without quoting it, and the port reads it as no key', () => {
    const leaked = material(5);
    createSightingKeyStore('file', dir).replace(stored());
    writeFileSync(join(dir, SIGHTING_KEY_FILENAME), `{"keyVersion":2,"key":"${leaked}`);

    const error = (() => {
      try {
        createSightingKeyStore('file', dir).read();
        return undefined;
      } catch (e) {
        return e as Error;
      }
    })();
    expect(error?.message).toMatch(/sighting key/);
    expectNoEchoOf(error?.message, leaked);
    expect(readSightingKeys(base)).toBeUndefined();
  });

  it('refuses a well-formed file whose key is the wrong length', () => {
    createSightingKeyStore('file', dir).replace(stored());
    writeFileSync(
      join(dir, SIGHTING_KEY_FILENAME),
      JSON.stringify({ ...stored(), key: Buffer.alloc(16, 1).toString('base64url') }),
    );
    expect(() => createSightingKeyStore('file', dir).read()).toThrow(/sighting key/);
  });
});

describe('keychain custody', () => {
  it('reads item-not-found as undefined', () => {
    const { exec } = fakeKeychain();
    expect(createSightingKeyStore('keychain', dir, exec).read()).toBeUndefined();
  });

  it('round-trips through its own item, never the vault keyring item', () => {
    const { exec, items } = fakeKeychain();
    const store = createSightingKeyStore('keychain', dir, exec);
    store.replace(stored());

    expect(store.read()).toEqual(stored());
    expect([...items.keys()]).toHaveLength(1);
    expect([...items.keys()][0]).not.toMatch(/^aka-vault\//);
  });

  it('replaces the item in place (-U) and keeps the payload off argv', () => {
    const { exec, calls } = fakeKeychain();
    const store = createSightingKeyStore('keychain', dir, exec);
    store.replace(stored());
    store.replace(stored({ keyVersion: 3, previous: [] }));

    expect(store.read()).toEqual(stored({ keyVersion: 3, previous: [] }));
    const writes = calls.filter((c) => c.stdin?.startsWith('add-generic-password'));
    expect(writes).toHaveLength(2);
    for (const write of writes) {
      expect(write.args).toEqual(['-i']);
      expect(write.stdin).toContain(' -U ');
    }
    const argv = calls.map((c) => c.args.join(' ')).join('\n');
    expect(argv).not.toMatch(/[0-9a-f]{64}/);
    expectNoEchoOf(argv, material(7));
  });

  it('throws on a denied read rather than reading it as absent', () => {
    const exec: SecurityExec = () => {
      throw Object.assign(new Error('denied'), { status: 1 });
    };
    expect(() => createSightingKeyStore('keychain', dir, exec).read()).toThrow(
      /keychain read failed/,
    );
  });

  it('reports a failed write by exit status alone', () => {
    const payload = material(7);
    const exec: SecurityExec = (_args, stdin) => {
      throw Object.assign(new Error(`failed: ${stdin ?? ''}`), { status: 45, stdout: stdin });
    };
    const error = (() => {
      try {
        createSightingKeyStore('keychain', dir, exec).replace(stored());
        return undefined;
      } catch (e) {
        return e as Error;
      }
    })();
    expect(error?.message).toMatch(/keychain write failed \(exit 45\)/);
    expectNoEchoOf(error?.message, payload);
    expect(error?.cause).toBeUndefined();
  });
});

describe('readSightingKeys', () => {
  it('hands out the current and previous versions as raw bytes', () => {
    createSightingKeyStore('file', dir).replace(stored());

    const keys = readSightingKeys(base);

    expect(keys?.current.keyVersion).toBe(2);
    expect(keys?.current.key).toBeInstanceOf(Uint8Array);
    expect(Buffer.from(keys?.current.key ?? []).equals(Buffer.alloc(32, 7))).toBe(true);
    expect(keys?.previous.map((p) => p.keyVersion)).toEqual([1]);
    expect(Buffer.from(keys?.previous[0]?.key ?? []).equals(Buffer.alloc(32, 3))).toBe(true);
  });

  it('reads an absent previous list as empty', () => {
    const withoutPrevious = stored();
    delete withoutPrevious.previous;
    createSightingKeyStore('file', dir).replace(withoutPrevious);
    expect(readSightingKeys(base)?.previous).toEqual([]);
  });

  it('follows the vault key custody setting', () => {
    applyOnboarding({ vaultKeyCustody: 'keychain' }, base, null);
    const { exec } = fakeKeychain();
    createSightingKeyStore('keychain', dir, exec).replace(stored());

    expect(readSightingKeys(base, { exec })?.current.keyVersion).toBe(2);
    // The file backend holds nothing, so a reader that ignored the setting
    // would come back empty.
    expect(createSightingKeyStore('file', dir).read()).toBeUndefined();
  });

  it('reads an unreadable keychain as no key rather than throwing', () => {
    applyOnboarding({ vaultKeyCustody: 'keychain' }, base, null);
    const exec: SecurityExec = () => {
      throw Object.assign(new Error('denied'), { status: 1 });
    };
    expect(readSightingKeys(base, { exec })).toBeUndefined();
  });
});
