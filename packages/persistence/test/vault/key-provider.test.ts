import { randomBytes } from 'node:crypto';
import type * as FsModule from 'node:fs';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { DATA_DIR_MODE, DATA_FILE_MODE } from '../../src/paths.ts';
import {
  createKeyProvider,
  FileKeyProvider,
  KeychainKeyProvider,
  VAULT_KEY_FILENAME,
  VaultKeyEpochMissingError,
} from '../../src/vault/key-provider.ts';
import { rejectionFrom } from '../helpers/errors.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

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

// The real platform in the two forms the cases below need, both read at module
// load, before anything can have faked it: the plain value is what the
// order-independent guard compares against, and the DESCRIPTOR is what the
// restore puts back. It has to be the descriptor — `process.platform` is a
// non-writable own property, so a case that fakes it must redefine it, and
// undoing that means reinstating the original definition rather than assigning
// the old string back.
const REAL_PLATFORM: NodeJS.Platform = process.platform;
const realPlatform = Object.getOwnPropertyDescriptor(process, 'platform');
if (!realPlatform) {
  // Refuse rather than restore nothing: a fake that is never undone leaks into
  // every later case in this worker, including the temp-dir teardowns.
  throw new Error('process.platform has no own property descriptor to restore');
}

// KeychainKeyProvider's guard reads `process.platform` at CONSTRUCTION time, so
// redefining it here reaches it. Faking rather than gating is the whole point:
// `it.skipIf(process.platform === 'darwin')` runs one direction on one runner
// and leaves the other unasserted everywhere — a guard hardcoded to ALWAYS fire
// makes the backend unconstructable on macOS and no runner catches it.
function stubPlatform(value: NodeJS.Platform): void {
  Object.defineProperty(process, 'platform', { value, configurable: true });
}

// Unconditional and file-scoped rather than scoped to the block that fakes: a
// case throwing mid-body would otherwise hand its fake to every case after it.
// A no-op for every case that never faked.
afterEach(() => {
  Object.defineProperty(process, 'platform', realPlatform);
});

// The order-INDEPENDENT half of that guarantee. A single case asserting the
// platform was restored covers only the cases declared before it, so appending
// a faking case below it silently moves that case outside the guard. This runs
// before every case in the file instead.
beforeEach(() => {
  expect(process.platform).toBe(REAL_PLATFORM);
});

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

  it.skipIf(!POSIX_MODES)(
    'refuses a symlinked key path with a CODED error, naming the link',
    async () => {
      // The publish finds the path occupied (link never replaces a name) and the
      // re-read follows the dangling link to nothing, so no keyring can be
      // adopted. The error must carry a string `code`: the surfaces that render
      // key failures treat a codeless one as "the file is corrupt, delete it",
      // and the blast radius here is every pointer sealed under the lost epoch —
      // ciphertext nothing can reopen, not merely a grant that stops matching.
      const target = join(dir, 'elsewhere.key');
      symlinkSync(target, keyFile());

      const err = await new FileKeyProvider(dir).loadOrCreate().then(
        () => undefined,
        (e: unknown) => e,
      );

      expect(err).toBeDefined();
      expect((err as { code?: unknown }).code).toBe('key-unclaimable');
      expect((err as Error).message).toMatch(/symlink/);
      // Refused without creating what it pointed at.
      expect(existsSync(target)).toBe(false);
    },
  );

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
    const calls: { args: string[]; stdin: string | undefined }[] = [];
    const provider = new KeychainKeyProvider(dir, (args, stdin) => {
      calls.push({ args, stdin });
      return denied();
    });

    await expect(provider.loadOrCreate()).rejects.toThrow(/keychain read failed/);
    // A write now rides stdin as a `security -i` command, so looking for
    // `add-generic-password` in ARGV would be true however this behaved.
    expect(calls.some((c) => c.stdin !== undefined)).toBe(false);
  });

  it('mints on item-not-found (exit 44), without -U', async () => {
    const calls: { args: string[]; stdin: string | undefined }[] = [];
    const provider = new KeychainKeyProvider(dir, (args, stdin) => {
      calls.push({ args, stdin });
      if (args[0] === 'find-generic-password') notFound();
      return '';
    });

    const key = await provider.loadOrCreate();

    expect(key.version).toBe(1);
    const write = calls.find((c) => c.stdin?.startsWith('add-generic-password'));
    expect(write).toBeDefined();
    // The command itself rides stdin; argv carries only interactive mode.
    expect(write?.args).toEqual(['-i']);
    // A plain add fails on an existing item, so a lost first-mint race cannot
    // overwrite the winner's keyring; -U belongs to rotation only.
    expect(write?.stdin).not.toContain('-U');
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
    const calls: { args: string[]; stdin: string | undefined }[] = [];
    const provider = new KeychainKeyProvider(dir, (args, stdin) => {
      calls.push({ args, stdin });
      if (args[0] === 'find-generic-password') return keyringJson(Buffer.alloc(32, 7));
      return '';
    });

    const rotated = await provider.rotate();

    expect(rotated.version).toBe(2);
    const write = calls.find((c) => c.stdin?.startsWith('add-generic-password'));
    expect(write).toBeDefined();
    expect(write?.stdin).toContain('-U');
    expect(existsSync(join(dir, `${VAULT_KEY_FILENAME}.lock`))).toBe(false);
  });

  // Nothing repairs either of these. The keyring itself is re-tightened on every
  // load, so a dropped mode there is a window; the lock is created, stamped and
  // removed within one rotation, so a dropped mode there is simply a
  // group/other-readable directory and owner file for as long as the lock is
  // held. Neither carries a secret — the owner is a random token — but they sit
  // in the keys dir, and SECURITY.md's at-rest note makes no carve-out for
  // low-sensitivity files.
  //
  // Observed from INSIDE the lock through the injected `exec`, which the
  // keychain backend calls while `withRotationLock` is still holding it. The
  // file provider offers no such seam: its rotation takes, stamps and releases
  // the lock in one synchronous stretch, so by the time `rotate()` resolves
  // there is nothing left on disk to stat.
  // `ctx.skip(reason)` rather than the file's usual `it.skipIf(!POSIX_MODES)`:
  // both report as skipped rather than as a pass, but only this form carries the
  // reason into the runner's output, which is what someone reading a Windows leg
  // needs in order to tell a deliberate gate from a case that quietly vanished.
  it('holds the rotation lock and its owner file owner-only', async (ctx) => {
    if (!POSIX_MODES) {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    const lock = join(dir, `${VAULT_KEY_FILENAME}.lock`);
    let observed: { dir: number; owner: number } | undefined;
    // As in the marker case: the umask only clears bits, so 0o000 is what makes
    // a dropped `mode` argument show as 0666/0777 instead of being masked back
    // down to the very value under test on a runner whose own umask is 0o077.
    const previous = process.umask(0o000);
    try {
      const provider = new KeychainKeyProvider(dir, (args) => {
        observed ??= {
          dir: statSync(lock).mode & 0o777,
          owner: statSync(join(lock, 'owner')).mode & 0o777,
        };
        if (args[0] === 'find-generic-password') return keyringJson(Buffer.alloc(32, 7));
        return '';
      });
      await provider.rotate();
    } finally {
      process.umask(previous);
    }

    expect(observed).toBeDefined();
    expect(observed?.owner).toBe(DATA_FILE_MODE);
    expect(observed?.dir).toBe(DATA_DIR_MODE);
    // And the lock really was released, so the modes above were read from a
    // live lock rather than from a leftover one.
    expect(existsSync(lock)).toBe(false);
  });

  // The defect this backend carried: the keyring rode argv (`-w <json>`), and
  // an execFileSync error's `.message` echoes argv — so a failed write put the
  // key in an error that outlives the process and travels into logs. It rides
  // stdin now, and nothing about the payload may reach the command line.
  it('keeps the keyring off argv on both write paths', async () => {
    const calls: { args: string[]; stdin: string | undefined }[] = [];
    let reads = 0;
    const provider = new KeychainKeyProvider(dir, (args, stdin) => {
      calls.push({ args, stdin });
      if (args[0] === 'find-generic-password') {
        reads += 1;
        if (reads === 1) notFound();
        return keyringJson(Buffer.alloc(32, 9));
      }
      return '';
    });

    await provider.loadOrCreate();
    await provider.rotate();

    // Positive control: both writes really happened, on stdin.
    const writes = calls.filter((c) => c.stdin?.startsWith('add-generic-password'));
    expect(writes).toHaveLength(2);

    const argv = calls.map((c) => c.args.join(' ')).join('\n');
    expect(argv).not.toContain('add-generic-password');
    // The hex-encoded keyring is the payload's on-the-wire form; a 32-byte key
    // alone is 64 hex characters, so any such run in argv is the leak itself.
    expect(argv).not.toMatch(/[0-9a-f]{64}/);
  });

  it('refuses a rotation while another is in flight', async () => {
    const provider = new KeychainKeyProvider(dir, () =>
      JSON.stringify({ current: 1, keys: { 1: Buffer.alloc(32, 7).toString('base64') } }),
    );
    mkdirSync(join(dir, `${VAULT_KEY_FILENAME}.lock`));

    await expect(provider.rotate()).rejects.toThrow(/already in progress/);
  });

  // ─── raw-free refusals, driven WITHOUT the real binary ────────────────────
  //
  // The constructor's platform guard only fires for the real `runSecurity`, so
  // an injected exec reaches every branch below on any host. That matters: the
  // cases in keychain-real-binary.test.ts skip off darwin, which left these —
  // the raw-free throw sites, i.e. the property this whole change exists to
  // establish — unexecuted on the legs that gate every PR.
  describe('refusals, on every platform', () => {
    // The payload a leak would carry, in the form the write path actually
    // sends. Distinct per test so no assertion can pass on a stale value.
    const hexPayload = (): string => randomBytes(32).toString('hex');

    // A spawn failure whose OWN message embeds the payload, the way a real
    // execFileSync error's argv echo would. Without that the absence
    // assertions below hold because there was nothing there to leak.
    const failsCarrying = (payload: string, status: number): never => {
      throw Object.assign(new Error(`add-generic-password -X ${payload}`), { status });
    };

    it('refuses a failed FIRST MINT without echoing the payload', async () => {
      const payload = hexPayload();
      const provider = new KeychainKeyProvider(dir, (args) => {
        // Both reads come back empty, so the lost-race adoption path cannot
        // return and the mint's own failure message is what surfaces.
        if (args[0] === 'find-generic-password') notFound();
        return failsCarrying(payload, 45);
      });

      const err = await rejectionFrom(provider.loadOrCreate());

      expect(err).toBeDefined();
      expect(err?.message).toMatch(/keychain write failed/);
      // Positive control: the metadata IS there, so the absence checks below
      // are not passing on an empty or generic message.
      expect(err?.message).toContain('exit 45');
      expectNoEchoOf(err?.message, payload);
      expectNoEchoOf(err?.stack, payload);
      // Two leak shapes, and `payload` only sees the first. It catches the
      // caught error's own message riding out (the argv echo). It cannot catch
      // the OTHER shape — interpolating the write line this call built — whose
      // hex is the freshly minted keyring, a value no assertion here holds.
      // Any 64-character hex run in a message whose legitimate content is
      // `exit 45` is one of the two.
      expect(err?.message).not.toMatch(/[0-9a-f]{64}/);
    });

    it('refuses a failed ROTATION without echoing the payload', async () => {
      const payload = hexPayload();
      const material = Buffer.alloc(32, 3);
      const provider = new KeychainKeyProvider(dir, (args) => {
        if (args[0] === 'find-generic-password') return keyringJson(material);
        return failsCarrying(payload, 45);
      });

      const err = await rejectionFrom(provider.rotate());

      expect(err).toBeDefined();
      expect(err?.message).toMatch(/keychain write failed/);
      expect(err?.message).toContain('exit 45');
      expectNoEchoOf(err?.message, payload);
      expectNoEchoOf(err?.stack, payload);
      // The retained epoch is in the payload a rotation writes, so it is the
      // value that call genuinely handled.
      expectNoEchoOf(err?.message, material.toString('base64'));
      // …and the hex form that actually crosses to the child, which neither
      // base64 assertion above can see. See the mint case for why both.
      expect(err?.message).not.toMatch(/[0-9a-f]{64}/);
    });

    it('refuses a stored item that is not a keyring', async () => {
      const provider = new KeychainKeyProvider(dir, () => '{"current":"not-a-number","keys":{}}');

      const err = await rejectionFrom(provider.loadOrCreate());

      expect(err).toBeDefined();
      expect(err?.message).toMatch(/not a usable keyring/);
    });

    it('refuses a TRUNCATED keyring without quoting it back', async () => {
      const secret = randomBytes(32).toString('base64');
      const provider = new KeychainKeyProvider(dir, () => `{"current":1,"keys":{"1":"${secret}`);

      const err = await rejectionFrom(provider.loadOrCreate());

      expect(err).toBeDefined();
      // The JSON.parse branch: replaced with a fixed label rather than
      // forwarded, so nothing V8 chose to quote can ride out.
      expect(err?.message).toMatch(/malformed JSON/);
      expectNoEchoOf(err?.message, secret);
      expectNoEchoOf(err?.stack, secret);
    });

    it('describes a non-Error spawn failure without inventing detail', async () => {
      const provider = new KeychainKeyProvider(dir, () => {
        // Not an Error at all, so every field securityFailureMeta reads is
        // absent — the arm that must still produce a message rather than
        // interpolating `undefined`. Throwing a non-Error is the case under
        // test, which is why the rule is waived here rather than satisfied.
        // eslint-disable-next-line @typescript-eslint/only-throw-error -- a non-Error throw is the input under test
        throw 'a bare string';
      });

      const err = await rejectionFrom(provider.loadOrCreate());

      expect(err).toBeDefined();
      expect(err?.message).toMatch(/keychain read failed/);
    });

    it('quotes a benign keychain path into the interactive line', async () => {
      // A literal rather than a path under `dir`, and that is forced rather
      // than tidier: the exec is injected, so nothing ever opens this — but
      // `join()` under a Windows temp dir is backslash-separated, and
      // writeCommand refuses a backslash. Built from `dir`, this case cannot
      // pass on win32 at all, because every absolute path there carries the
      // character the refusal is looking for. The refusal is what the cases
      // below cover; this one is about the QUOTING, so it takes a path shaped
      // like the one the backend really operates on.
      const target = '/tmp/throwaway.keychain';
      const calls: { args: string[]; stdin: string | undefined }[] = [];
      const provider = new KeychainKeyProvider(
        dir,
        (args, stdin) => {
          calls.push({ args, stdin });
          if (args[0] === 'find-generic-password') notFound();
          return '';
        },
        target,
      );

      await provider.loadOrCreate();

      const write = calls.find((c) => c.stdin?.startsWith('add-generic-password'));
      expect(write).toBeDefined();
      // Single-quoted and last, which is where every subcommand here takes it.
      expect(write?.stdin?.trimEnd().endsWith(`'${target}'`)).toBe(true);
      // …and the read was aimed at it too, as a bare trailing argument.
      const read = calls.find((c) => c.args[0] === 'find-generic-password');
      expect(read?.args.at(-1)).toBe(target);
    });

    // Measured, not guessed: `security -i` treats a backslash as an escape even
    // inside single quotes, so a path carrying one is consumed rather than
    // carried and the write lands on a keychain other than the one named.
    it.each([
      ['a quote', "/tmp/it's.keychain"],
      ['a backslash', '/tmp/back\\slash.keychain'],
      ['a line break', '/tmp/two\nlines.keychain'],
      ['a NUL', '/tmp/nul\0byte.keychain'],
    ])('refuses a keychain path carrying %s', async (_label, target) => {
      const provider = new KeychainKeyProvider(dir, notFound, target);

      const err = await rejectionFrom(provider.loadOrCreate());

      expect(err).toBeDefined();
      expect(err?.message).toMatch(/quote, backslash, line break or NUL/);
    });
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

  /**
   * The platform guard, driven from a FAKED platform rather than gated on the
   * real one — so both directions run on every runner.
   *
   * A gated case can only ever assert the direction its host happens to be on,
   * and the direction it cannot reach is the worse of the two: a guard
   * hardcoded to ALWAYS fire makes `KeychainKeyProvider` unconstructable, which
   * silently kills keychain custody for every macOS user — the backend a
   * security-conscious user deliberately opts into. Measured before this
   * landed: replacing the `process.platform` read with `'linux'` left the whole
   * suite green on a macOS host AND on a Linux one, because the only case
   * taking the default was `it.skipIf(process.platform === 'darwin')` — which
   * expects a throw and is satisfied by a guard that is right for the wrong
   * reason.
   *
   * Neither case reaches `runSecurity`: the constructor stores `exec` and
   * returns, so construction is the whole subject here. Executing the real
   * `/usr/bin/security` is a separate gap, and it needs a macOS runner —
   * `test/vault/keychain-real-binary.test.ts` is where that lives.
   */
  describe('the platform guard, on every runner', () => {
    it('constructs with the real exec on darwin', () => {
      stubPlatform('darwin');

      expect(() => new KeychainKeyProvider(dir)).not.toThrow();
    });

    it('refuses the real exec off darwin, naming the platform', () => {
      stubPlatform('linux');

      expect(() => new KeychainKeyProvider(dir)).toThrow(
        /not available on this platform \(linux\)/,
      );
    });

    // The guard is scoped to the real binary on purpose: an injected exec
    // carries its own platform expectations, and every case above it depends on
    // that. Pinned so the guard cannot be widened to the seam by accident.
    it('lets an injected exec through off darwin', () => {
      stubPlatform('linux');

      expect(() => new KeychainKeyProvider(dir, () => '')).not.toThrow();
    });
  });
});
