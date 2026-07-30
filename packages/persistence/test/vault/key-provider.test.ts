import type * as FsModule from 'node:fs';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  createKeyProvider,
  FileKeyProvider,
  KeychainKeyProvider,
  VAULT_KEY_FILENAME,
  VaultKeyEpochMissingError,
} from '../../src/vault/key-provider.ts';

// Lets a test simulate the first-mint race: one read of the key file reports
// ENOENT even though the file exists, putting the provider on its mint path
// while a "winner's" keyring already sits at the final path.
//
// `retakeLockOnNextStat` / `retakeLockOnWrite` do the same for the rotation
// lock: another process takes the lock over at the exact instant the code under
// test is between deciding and acting on it. Both drop a fresh lock directory
// stamped with a foreign owner, which is what neither the reclaim nor the
// release may disturb.
const raceControl = vi.hoisted(() => ({
  hideKeyFileOnce: false,
  retakeLockOnNextStat: false,
  retakeLockOnWrite: false,
  touchLockOnNextStat: false,
}));

const FOREIGN_OWNER = 'another-process';

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof FsModule>();
  const retake = (lock: string): void => {
    actual.rmSync(lock, { recursive: true, force: true });
    actual.mkdirSync(lock);
    actual.writeFileSync(`${lock}/owner`, 'another-process\n');
  };
  const readFileSyncWithRace = ((...args: Parameters<typeof actual.readFileSync>) => {
    if (raceControl.hideKeyFileOnce && String(args[0]).endsWith('vault.key')) {
      raceControl.hideKeyFileOnce = false;
      const err = new Error('ENOENT (simulated race)') as NodeJS.ErrnoException;
      err.code = 'ENOENT';
      throw err;
    }
    return actual.readFileSync(...args);
  }) as typeof actual.readFileSync;
  // Fires AFTER the real stat, so the caller still receives the stale stats it
  // based its decision on and only the directory underneath has changed.
  const statSyncWithRace = ((...args: Parameters<typeof actual.statSync>) => {
    const result = actual.statSync(...args);
    const path = String(args[0]);
    if (raceControl.retakeLockOnNextStat && path.endsWith('vault.key.lock')) {
      raceControl.retakeLockOnNextStat = false;
      retake(path);
    }
    // Refreshes the lock in place: SAME directory, same inode, new mtime. This
    // is what a live holder heartbeating looks like, and it is also what inode
    // reuse looks like to a reclaimer that compares inodes alone.
    if (raceControl.touchLockOnNextStat && path.endsWith('vault.key.lock')) {
      raceControl.touchLockOnNextStat = false;
      const now = Date.now() / 1000;
      actual.utimesSync(path, now, now);
    }
    return result;
  }) as typeof actual.statSync;
  const writeFileSyncWithRace = ((...args: Parameters<typeof actual.writeFileSync>) => {
    const path = String(args[0]);
    if (raceControl.retakeLockOnWrite && path.includes('vault.key') && !path.includes('.lock')) {
      raceControl.retakeLockOnWrite = false;
      retake(path.replace(/vault\.key.*$/, 'vault.key.lock'));
    }
    actual.writeFileSync(...args);
  }) as typeof actual.writeFileSync;
  return {
    ...actual,
    readFileSync: readFileSyncWithRace,
    statSync: statSyncWithRace,
    writeFileSync: writeFileSyncWithRace,
  };
});

const POSIX_MODES = process.platform !== 'win32';

describe('FileKeyProvider', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-vault-key-'));
  });

  afterEach(() => {
    raceControl.hideKeyFileOnce = false;
    raceControl.retakeLockOnNextStat = false;
    raceControl.retakeLockOnWrite = false;
    raceControl.touchLockOnNextStat = false;
    rmSync(dir, { recursive: true, force: true });
  });

  const keyFile = (): string => join(dir, VAULT_KEY_FILENAME);
  const lockDir = (): string => join(dir, `${VAULT_KEY_FILENAME}.lock`);

  it('mints version 1 with 32 bytes of material on first use', async () => {
    const provider = new FileKeyProvider(dir);
    const key = await provider.loadOrCreate();

    expect(key.version).toBe(1);
    expect(key.material).toHaveLength(32);
  });

  it.skipIf(!POSIX_MODES)('writes the key file owner-only', async () => {
    await new FileKeyProvider(dir).loadOrCreate();

    expect(statSync(keyFile()).mode & 0o777).toBe(0o600);
  });

  it('returns the same material on a second load rather than re-minting', async () => {
    const first = await new FileKeyProvider(dir).loadOrCreate();
    const second = await new FileKeyProvider(dir).loadOrCreate();

    expect(second.version).toBe(first.version);
    expect(second.material.equals(first.material)).toBe(true);
  });

  // The property that separates this key from the fingerprint key: a pointer
  // minted under an old epoch is already out in transcripts and files, so its
  // material must survive every later rotation.
  it('retains the previous epoch after a rotation', async () => {
    const provider = new FileKeyProvider(dir);
    const v1 = await provider.loadOrCreate();
    const v2 = await provider.rotate();

    expect(v2.version).toBe(2);
    expect(v2.material.equals(v1.material)).toBe(false);

    const recovered = await provider.materialFor(1);
    expect(recovered.version).toBe(1);
    expect(recovered.material.equals(v1.material)).toBe(true);
  });

  it('retains every epoch across repeated rotations', async () => {
    const provider = new FileKeyProvider(dir);
    const v1 = await provider.loadOrCreate();
    const v2 = await provider.rotate();
    const v3 = await provider.rotate();

    expect(v3.version).toBe(3);
    expect((await provider.materialFor(1)).material.equals(v1.material)).toBe(true);
    expect((await provider.materialFor(2)).material.equals(v2.material)).toBe(true);
    expect((await provider.materialFor(3)).material.equals(v3.material)).toBe(true);
  });

  it('reports the current epoch after a rotation on a fresh load', async () => {
    await new FileKeyProvider(dir).loadOrCreate();
    const rotated = await new FileKeyProvider(dir).rotate();
    const reloaded = await new FileKeyProvider(dir).loadOrCreate();

    expect(reloaded.version).toBe(2);
    expect(reloaded.material.equals(rotated.material)).toBe(true);
  });

  // Two hook processes racing loadOrCreate on a fresh machine must converge on
  // ONE epoch-1 keyring — if each minted its own, the loser's sealed rows and
  // emitted pointers would be permanently unresolvable.
  it('gives two providers racing loadOrCreate the same version-1 material', async () => {
    const [a, b] = await Promise.all([
      new FileKeyProvider(dir).loadOrCreate(),
      new FileKeyProvider(dir).loadOrCreate(),
    ]);

    expect(a.version).toBe(1);
    expect(b.version).toBe(1);
    expect(a.material.equals(b.material)).toBe(true);
  });

  it('adopts a keyring that appears between the absence check and the mint', async () => {
    // The winner mints first.
    const winner = await new FileKeyProvider(dir).loadOrCreate();
    const before = readFileSync(keyFile());

    // The loser's read reports absence (simulated race), so it attempts a
    // mint — the creation-exclusive write must lose to the existing file and
    // adopt the winner's keyring, never overwrite it.
    raceControl.hideKeyFileOnce = true;
    const loser = await new FileKeyProvider(dir).loadOrCreate();

    expect(loser.version).toBe(1);
    expect(loser.material.equals(winner.material)).toBe(true);
    expect(readFileSync(keyFile()).equals(before)).toBe(true);
  });

  it.skipIf(!POSIX_MODES)('keeps the keys dir owner-only', async () => {
    await new FileKeyProvider(dir).loadOrCreate();

    expect(statSync(dir).mode & 0o777).toBe(0o700);
  });

  it.skipIf(!POSIX_MODES)('re-tightens a loosened key file on the next load', async () => {
    await new FileKeyProvider(dir).loadOrCreate();
    chmodSync(keyFile(), 0o644);

    await new FileKeyProvider(dir).loadOrCreate();

    expect(statSync(keyFile()).mode & 0o777).toBe(0o600);
  });

  it('refuses a rotation while another is in flight', async () => {
    const provider = new FileKeyProvider(dir);
    await provider.loadOrCreate();
    mkdirSync(lockDir());

    await expect(provider.rotate()).rejects.toThrow(/already in progress/);
  });

  it('reclaims a stale rotation lock and releases it afterwards', async () => {
    const provider = new FileKeyProvider(dir);
    await provider.loadOrCreate();
    mkdirSync(lockDir());
    const past = (Date.now() - 120_000) / 1000;
    utimesSync(lockDir(), past, past);

    const rotated = await provider.rotate();

    expect(rotated.version).toBe(2);
    expect(existsSync(lockDir())).toBe(false);
  });

  it('releases the rotation lock after a completed rotation', async () => {
    const provider = new FileKeyProvider(dir);
    await provider.loadOrCreate();
    await provider.rotate();

    expect(existsSync(lockDir())).toBe(false);
    // A follow-up rotation is not blocked by the previous one.
    expect((await provider.rotate()).version).toBe(3);
  });

  // Reclaiming a stale lock must be an atomic steal, not delete-then-recreate.
  // A stale lock is absorbing — nothing ages it back — so any two attempts after
  // a crashed rotation race here, with no slow rotation required. Standing in
  // for the loser: a lock that is replaced (new inode) between the staleness
  // check and the reclaim belongs to whoever put it there.
  // POSIX only: the guard rests on statSync().ino distinguishing two
  // directories, and Windows derives that from a 64-bit file reference that
  // does not survive the trip through a JS number intact. The reclaim itself is
  // still safe there — the rename is what settles the race, and an unreliable
  // inode can only make this path refuse, which is the fail-secure direction.
  it.skipIf(!POSIX_MODES)(
    'refuses to reclaim a stale lock that was taken over in the meantime',
    async () => {
      const provider = new FileKeyProvider(dir);
      await provider.loadOrCreate();
      mkdirSync(lockDir());
      const past = (Date.now() - 120_000) / 1000;
      utimesSync(lockDir(), past, past);

      // Another process takes the stale lock over between the staleness check
      // and the reclaim. Deleting the lock and re-creating it would destroy that
      // holder's claim and let both run; only a rename can settle it.
      raceControl.retakeLockOnNextStat = true;

      await expect(provider.rotate()).rejects.toThrow(/already in progress/);
      expect(readFileSync(join(lockDir(), 'owner'), 'utf8').trim()).toBe(FOREIGN_OWNER);
      // Nothing was minted: the keyring is still at its original epoch.
      expect((await provider.loadOrCreate()).version).toBe(1);
    },
  );

  // Identity is (inode, mtime), not the inode alone. A filesystem may hand a
  // freshly created directory the inode it just reclaimed from a deleted one,
  // so an inode match does not prove the lock is still the one judged stale —
  // and comparing inodes alone let a reclaim proceed against a lock that had
  // been refreshed underneath it. The mtime is what separates the two.
  it.skipIf(!POSIX_MODES)(
    'refuses to reclaim a stale lock that was refreshed in place',
    async () => {
      const provider = new FileKeyProvider(dir);
      await provider.loadOrCreate();
      mkdirSync(lockDir());
      const past = (Date.now() - 120_000) / 1000;
      utimesSync(lockDir(), past, past);

      // Same directory and same inode throughout — only the mtime moves, exactly
      // as it would if the holder were alive and heartbeating.
      raceControl.touchLockOnNextStat = true;

      await expect(provider.rotate()).rejects.toThrow(/already in progress/);
      expect(existsSync(lockDir())).toBe(true);
      expect((await provider.loadOrCreate()).version).toBe(1);
    },
  );

  // A holder reclaimed as stale while it was still alive no longer owns the
  // lock. Removing it on the way out would unlock the reclaimer.
  it('leaves a rotation lock alone when another owner holds it at release', async () => {
    const provider = new FileKeyProvider(dir);
    await provider.loadOrCreate();

    // Mid-rotation, this holder's lock is reclaimed by someone else. Its own
    // release must then be a no-op rather than clearing the new owner's lock.
    raceControl.retakeLockOnWrite = true;
    await provider.rotate();

    expect(existsSync(lockDir())).toBe(true);
    expect(readFileSync(join(lockDir(), 'owner'), 'utf8').trim()).toBe(FOREIGN_OWNER);
  });

  it('throws on a corrupt key file and leaves it untouched', async () => {
    await new FileKeyProvider(dir).loadOrCreate();
    writeFileSync(keyFile(), '{ not json');
    const before = readFileSync(keyFile());

    await expect(new FileKeyProvider(dir).loadOrCreate()).rejects.toThrow();

    // Re-minting over a damaged keyring would orphan every ciphertext and every
    // outstanding pointer, so the file must survive the failed load byte for byte.
    expect(readFileSync(keyFile()).equals(before)).toBe(true);
  });

  it('throws on a key file whose material is the wrong length', async () => {
    writeFileSync(keyFile(), JSON.stringify({ current: 1, keys: { 1: 'c2hvcnQ=' } }));

    await expect(new FileKeyProvider(dir).loadOrCreate()).rejects.toThrow(/corrupt/);
  });

  it('throws VaultKeyEpochMissingError for an epoch that was never minted', async () => {
    const provider = new FileKeyProvider(dir);
    await provider.loadOrCreate();

    await expect(provider.materialFor(9)).rejects.toBeInstanceOf(VaultKeyEpochMissingError);
  });

  it('throws VaultKeyEpochMissingError when no keyring exists at all', async () => {
    await expect(new FileKeyProvider(dir).materialFor(1)).rejects.toBeInstanceOf(
      VaultKeyEpochMissingError,
    );
  });
});

describe('KeychainKeyProvider', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-vault-key-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  const notFound = (): never => {
    throw Object.assign(new Error('item not found'), { status: 44 });
  };
  const denied = (): never => {
    throw Object.assign(new Error('keychain access denied'), { status: 1 });
  };
  const keyringJson = (material: Buffer): string =>
    JSON.stringify({ current: 1, keys: { 1: material.toString('base64') } });

  // A locked keychain or a denied ACL must fail the load, not read as absence:
  // minting over the real keyring would orphan every existing ciphertext.
  it('throws when the keychain read is denied rather than minting', async () => {
    const calls: string[][] = [];
    const provider = new KeychainKeyProvider(dir, (args) => {
      calls.push(args);
      return denied();
    });

    await expect(provider.loadOrCreate()).rejects.toThrow(/keychain read failed/);
    expect(calls.some((args) => args[0] === 'add-generic-password')).toBe(false);
  });

  it('mints on item-not-found (exit 44), without -U', async () => {
    const calls: string[][] = [];
    const provider = new KeychainKeyProvider(dir, (args) => {
      calls.push(args);
      if (args[0] === 'find-generic-password') notFound();
      return '';
    });

    const key = await provider.loadOrCreate();

    expect(key.version).toBe(1);
    const add = calls.find((args) => args[0] === 'add-generic-password');
    expect(add).toBeDefined();
    // A plain add fails on an existing item, so a lost first-mint race cannot
    // overwrite the winner's keyring; -U belongs to rotation only.
    expect(add).not.toContain('-U');
  });

  it('adopts the winning keyring when its first mint loses the race', async () => {
    const winnerMaterial = Buffer.alloc(32, 7);
    let reads = 0;
    const provider = new KeychainKeyProvider(dir, (args) => {
      if (args[0] === 'find-generic-password') {
        reads += 1;
        // First read: nothing yet. Second read (after the failed add): the
        // concurrent winner's keyring is in place.
        if (reads === 1) notFound();
        return keyringJson(winnerMaterial);
      }
      throw Object.assign(new Error('item already exists'), { status: 45 });
    });

    const key = await provider.loadOrCreate();

    expect(key.version).toBe(1);
    expect(key.material.equals(winnerMaterial)).toBe(true);
  });

  it('rotates by replacing the item in place (-U) under the rotation lock', async () => {
    const calls: string[][] = [];
    const provider = new KeychainKeyProvider(dir, (args) => {
      calls.push(args);
      if (args[0] === 'find-generic-password') return keyringJson(Buffer.alloc(32, 7));
      return '';
    });

    const rotated = await provider.rotate();

    expect(rotated.version).toBe(2);
    const add = calls.find((args) => args[0] === 'add-generic-password');
    expect(add).toContain('-U');
    expect(existsSync(join(dir, `${VAULT_KEY_FILENAME}.lock`))).toBe(false);
  });

  it('refuses a rotation while another is in flight', async () => {
    const provider = new KeychainKeyProvider(dir, () =>
      JSON.stringify({ current: 1, keys: { 1: Buffer.alloc(32, 7).toString('base64') } }),
    );
    mkdirSync(join(dir, `${VAULT_KEY_FILENAME}.lock`));

    await expect(provider.rotate()).rejects.toThrow(/already in progress/);
  });
});

describe('createKeyProvider', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-vault-key-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('returns a FileKeyProvider for file custody', () => {
    expect(createKeyProvider('file', dir)).toBeInstanceOf(FileKeyProvider);
  });

  // Custody is an open discriminant, so an unrecognized value must land on the
  // safe default rather than leaving the vault without a provider.
  it('falls back to a FileKeyProvider for an unknown custody value', () => {
    expect(createKeyProvider('hsm-cluster', dir)).toBeInstanceOf(FileKeyProvider);
  });

  it.skipIf(process.platform === 'darwin')(
    'rejects keychain custody on a platform without one',
    () => {
      expect(() => new KeychainKeyProvider(dir)).toThrow(/not available on this platform/);
    },
  );
});
