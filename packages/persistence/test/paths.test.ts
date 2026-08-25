import { execFileSync } from 'node:child_process';
import fsModule from 'node:fs';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';

import { beforeEach, describe, expect, it } from 'vitest';

import {
  classifyOccupant,
  createOwnerOnlyFileSync,
  DATA_DIR_MODE,
  DATA_FILE_MODE,
  dbSidecars,
  ensureDataDirSync,
  KeyUnclaimableError,
  mkdirOwnerOnlySync,
  tightenDir,
  tightenFile,
  tightenPerms,
  writeExclusiveOwnerOnlySync,
  writeOwnerOnlyFileSync,
} from '../src/paths.ts';
import { useTempStore } from './helpers/temp-store.ts';

// The POSIX file/dir modes are the ONLY at-rest control on the store — see the
// "Data at rest" note in SECURITY.md. These tests pin the success modes (the
// directory mode was previously unasserted anywhere, and the sidecar modes were
// never asserted); the chmod-failure branch is a silent best-effort catch,
// exercised in database/settings fault cases rather than here. All mode
// assertions skip on Windows, where POSIX modes are a no-op.

// The harness owns the temp tree — its removal retries, and it demotes a
// teardown failure to the `cause` of the body's own error rather than speaking
// over it. Both matter here: several cases below tighten a directory to 0000 or
// set the macOS immutable flag, and a restore that does not run leaves a tree
// `rmSync` cannot remove.
//
// `base` is a subdirectory rather than the store's own root because these cases
// assert on the tree's exact contents (`readdirSync(base)`) and create the layout
// subdirs themselves — both of which the harness has already done to its root.
const store = useTempStore('aka-paths-');
let base: string;

beforeEach(() => {
  base = join(store.home, 'base');
  mkdirSync(base);
});

const mode = (p: string): number => statSync(p).mode & 0o777;

describe('mode constants', () => {
  it('are the documented owner-only modes (0700 dir / 0600 file)', () => {
    expect(DATA_DIR_MODE).toBe(0o700);
    expect(DATA_FILE_MODE).toBe(0o600);
  });
});

describe('ensureDataDirSync', () => {
  it('creates the directory owner-only (0700) where POSIX modes apply', () => {
    const dir = join(base, 'data');
    ensureDataDirSync(dir);
    expect(existsSync(dir)).toBe(true);
    if (process.platform !== 'win32') expect(mode(dir)).toBe(DATA_DIR_MODE);
  });

  it('tightens an existing loose directory to 0700 (chmods after mkdir)', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    const dir = join(base, 'data');
    mkdirSync(dir);
    chmodSync(dir, 0o777);
    // Unguarded because the ctx.skip at the top of this body already returned on
    // Windows; narrowing that skip means restoring a platform guard here.
    expect(mode(dir)).toBe(0o777); // precondition: genuinely loose

    ensureDataDirSync(dir);

    expect(mode(dir)).toBe(DATA_DIR_MODE);
  });

  it('creates missing parent directories and is idempotent on a re-run', () => {
    const dir = join(base, 'a', 'b', 'c');
    ensureDataDirSync(dir);
    expect(existsSync(dir)).toBe(true);
    // A second call re-tightens the leaf and must not throw.
    expect(() => {
      ensureDataDirSync(dir);
    }).not.toThrow();
    if (process.platform !== 'win32') expect(mode(dir)).toBe(DATA_DIR_MODE);
  });

  it('holds every level it creates at 0700, not just the leaf it tightens', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    // The tighten reaches the LEAF only, so the mode passed to mkdir is the one
    // thing holding the levels above it — and those are real store paths:
    // openLocalDatabase(dataDir(home)) creates ~/.aka itself as a parent when
    // the home does not exist yet, which is every first hook on a machine that
    // has never run `aka init`. Drop the mkdir mode and data/ still self-heals
    // through the tighten while ~/.aka is left at the caller's umask — 0755 on a
    // default host, 0777 under a permissive one.
    const dir = join(base, 'a', 'b', 'c');

    ensureDataDirSync(dir);

    for (const p of [join(base, 'a'), join(base, 'a', 'b'), dir]) {
      expect(mode(p)).toBe(DATA_DIR_MODE);
    }
  });

  it('never chmods THROUGH a directory symlink (a victim dir keeps its mode)', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // Fault injection: a store directory path (~/.aka, ~/.aka/data,
    // ~/.aka/settings, ~/.aka/keys) is a planted symlink to a directory the
    // invoking user owns but shares — a web root, a shared project dir. chmod
    // follows links, so without the guard the victim is silently locked to 0700
    // and group/other access breaks with no diagnostic.
    const victim = join(base, 'victim-shared');
    mkdirSync(victim);
    chmodSync(victim, 0o755);
    const link = join(base, '.aka');
    symlinkSync(victim, link);

    ensureDataDirSync(link);

    expect(mode(victim)).toBe(0o755); // victim NOT tightened through the link
    expect(lstatSync(link).isSymbolicLink()).toBe(true); // link left as-is
  });

  it('stays usable through a symlinked store dir rather than refusing it', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // The pinned decision for a symlinked store path is skip-and-surface, not
    // refuse: a home a user deliberately symlinked (a dotfiles manager, another
    // volume) must keep working, and a hook must never break on one. Naming the
    // link is the callers' job — see symlinkedStorePaths in ./store-symlinks.ts,
    // which both `aka init` and the plugin hooks report from.
    const victim = join(base, 'victim-shared');
    mkdirSync(victim);
    chmodSync(victim, 0o755);
    const link = join(base, '.aka');
    symlinkSync(victim, link);

    expect(() => {
      ensureDataDirSync(link);
    }).not.toThrow();
    expect(existsSync(link)).toBe(true);
  });

  it('still tightens a real directory created INSIDE a symlinked home', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    // Only the FINAL component is checked. Widening the guard to any symlinked
    // ancestor would leave the whole store untightened under a deliberately
    // symlinked ~/.aka — silently dropping its only at-rest control, which is a
    // worse outcome than the one being fixed. data/ here is a real inode, so it
    // is ours to hold at 0700.
    //
    // data/ must PRE-EXIST loose for this to mean anything: mkdir applies the
    // mode at creation, so on a fresh dir the assertion passes whether or not the
    // chmod ran, and an ancestor-widened guard would slip through green.
    const victim = join(base, 'victim-shared');
    mkdirSync(join(victim, 'data'), { recursive: true });
    chmodSync(join(victim, 'data'), 0o755);
    chmodSync(victim, 0o755);
    const link = join(base, '.aka');
    symlinkSync(victim, link);

    ensureDataDirSync(join(link, 'data'));

    expect(mode(join(victim, 'data'))).toBe(DATA_DIR_MODE);
    expect(mode(victim)).toBe(0o755); // and the link's own target still untouched
  });
});

describe('tightenDir', () => {
  it('sets 0700 on an existing loose directory', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    const dir = join(base, 'data');
    mkdirSync(dir);
    chmodSync(dir, 0o777);

    tightenDir(dir);

    expect(mode(dir)).toBe(DATA_DIR_MODE);
  });

  it('never chmods THROUGH a symlink (the plugin re-tightens the base every hook)', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // loadConfig re-tightens the base dir on EVERY hook, so this is the hot path
    // the guard has to hold on, not just `aka init`.
    const victim = join(base, 'victim-shared');
    mkdirSync(victim);
    chmodSync(victim, 0o755);
    const link = join(base, '.aka');
    symlinkSync(victim, link);

    tightenDir(link);

    expect(mode(victim)).toBe(0o755);
    expect(lstatSync(link).isSymbolicLink()).toBe(true);
  });
});

describe('dbSidecars', () => {
  it('names the -wal, -shm and -journal sidecars next to a database file', () => {
    const file = join(base, 'aka.db');
    // -journal covers the rollback modes SQLite falls back to when WAL is
    // unavailable (DrvFs, some network mounts) — it holds store content too.
    expect(dbSidecars(file)).toEqual([`${file}-wal`, `${file}-shm`, `${file}-journal`]);
  });
});

describe('tightenPerms', () => {
  it('sets 0600 on the db file and all of its sidecars', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    const file = join(base, 'aka.db');
    // Create the set with deliberately loose modes so the chmod is observable.
    for (const p of [file, ...dbSidecars(file)]) {
      writeFileSync(p, '');
      chmodSync(p, 0o644);
    }

    tightenPerms(file);

    for (const p of [file, ...dbSidecars(file)]) {
      expect(mode(p)).toBe(DATA_FILE_MODE);
    }
  });

  it('does not throw when the sidecars do not exist yet (fail-open)', () => {
    const file = join(base, 'aka.db');
    writeFileSync(file, '');
    // No -wal/-shm on disk — mirrors a freshly created store before its first
    // WAL write. Tightening must chmod what exists and swallow the rest.
    expect(existsSync(`${file}-wal`)).toBe(false);
    expect(() => {
      tightenPerms(file);
    }).not.toThrow();
    if (process.platform !== 'win32') expect(mode(file)).toBe(DATA_FILE_MODE);
  });

  it('never chmods THROUGH a symlink planted at a sidecar path', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // A sidecar path is as plantable as settings.json in the loose-~/.aka state,
    // and -wal/-shm/-journal do not exist until SQLite creates them, so the name
    // is free for an attacker to take first.
    const file = join(base, 'aka.db');
    writeFileSync(file, '');
    const victim = join(base, 'victim');
    writeFileSync(victim, 'SECRET');
    chmodSync(victim, 0o644);
    symlinkSync(victim, `${file}-wal`);

    tightenPerms(file);

    expect(mode(victim)).toBe(0o644); // victim NOT tightened through the link
    expect(mode(file)).toBe(DATA_FILE_MODE); // the real db still tightened
  });
});

describe('tightenFile', () => {
  it('sets 0600 on a single file (a backup copy, the exception key)', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    const file = join(base, 'aka.db.legacy.bak');
    writeFileSync(file, 'corpus copy');
    chmodSync(file, 0o644); // as VACUUM INTO / a mode-preserving rename would leave it

    tightenFile(file);

    expect(mode(file)).toBe(DATA_FILE_MODE);
  });

  it('does not throw when the file is absent (fail-open)', () => {
    expect(() => {
      tightenFile(join(base, 'nope'));
    }).not.toThrow();
  });

  it('never chmods THROUGH a symlink (self-heal must not tighten an arbitrary target)', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // Fault injection: settings.json (or the exception key) is a planted symlink
    // to a victim the attacker can read. tightenFile must skip it, not follow the
    // link and chmod the victim.
    const victim = join(base, 'victim');
    writeFileSync(victim, 'SECRET');
    chmodSync(victim, 0o644);
    const link = join(base, 'settings.json');
    symlinkSync(victim, link);

    tightenFile(link);

    expect(mode(victim)).toBe(0o644); // victim NOT tightened through the link
    expect(lstatSync(link).isSymbolicLink()).toBe(true); // link left as-is
  });
});

describe('mkdirOwnerOnlySync', () => {
  // The directory twin of the case above, and undetectable for the same reason:
  // every caller follows it with a `tightenDir`, so the finished directory is
  // 0700 whether or not the create carried a mode. The window it closes is the
  // one where something is written INTO the directory — a snapshot staging area
  // takes a full copy of the prompt corpus, and the rotation lock is stamped
  // straight after the mkdir. Same instrument: under a 0o000 umask the create
  // keeps exactly what it asked for (0700 with the mode, 0777 without it), where
  // a runner's own 0o077 would hand back 0700 either way.
  it('creates the directory owner-only, by the create itself and not a later chmod', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    const dir = join(base, 'staging');
    const previous = process.umask(0o000);
    try {
      mkdirOwnerOnlySync(dir);
      expect(mode(dir)).toBe(DATA_DIR_MODE);
    } finally {
      process.umask(previous);
    }
  });

  // Non-recursive by default, because that EEXIST is what the rotation lock uses
  // to pick exactly one winner — a `recursive: true` default would silently turn
  // every claim into a success and put two writers in the section.
  it('refuses an existing directory, so a caller can use EEXIST to claim it', () => {
    const dir = join(base, 'lock');
    mkdirOwnerOnlySync(dir);

    expect(() => {
      mkdirOwnerOnlySync(dir);
    }).toThrow(expect.objectContaining({ code: 'EEXIST' }));
  });

  // The recursive create and its idempotency hold on every platform, so this is
  // a positive conditional rather than a skip: only the mode half is gated. A
  // `ctx.skip` at the tail would throw away a result that genuinely held and
  // report the case as uncovered where it was not.
  it('creates missing parents when asked, and is then idempotent', () => {
    const dir = join(base, 'a', 'b', 'c');
    // Under the same 0o000 umask as the case above, and for the same reason: on
    // a runner whose own umask is 0o077, mkdir's default 0o777 is masked down to
    // 0o700 — equal to DATA_DIR_MODE — so every assertion below would hold with
    // the create mode deleted. The idempotency half needs no umask and is left
    // outside it.
    const previous = process.umask(0o000);
    try {
      mkdirOwnerOnlySync(dir, true);
      if (process.platform !== 'win32') {
        // Every level it created, not just the leaf it tightens.
        expect(mode(join(base, 'a'))).toBe(DATA_DIR_MODE);
        expect(mode(join(base, 'a', 'b'))).toBe(DATA_DIR_MODE);
        expect(mode(dir)).toBe(DATA_DIR_MODE);
      }
    } finally {
      process.umask(previous);
    }

    expect(() => {
      mkdirOwnerOnlySync(dir, true);
    }).not.toThrow();
  });
});

describe('writeExclusiveOwnerOnlySync', () => {
  // The one place a store file is created, and the only place its CREATE mode
  // can be asserted at all: every caller re-tightens what it publishes, so on a
  // published file the end state is 0600 whether or not the create carried a
  // mode. Deleting `mode` there leaves a window — the file exists with its
  // contents already in it, at the umask, until the chmod lands — and no
  // assertion on the finished file can see it. Asserting the primitive is what
  // makes that half deletable-with-consequences.
  //
  // The umask is the instrument. It only ever CLEARS bits, so under 0o000
  // nothing is taken off a create: with the mode the file is 0600, without it
  // 0666. A developer or runner whose umask is already 0o077 would get 0600
  // either way and the case would pass over the mutant, which is why the umask
  // is set here rather than inherited. Restored in a `finally` because it is
  // process-global.
  it('creates the file owner-only, by the create itself and not a later chmod', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    const file = join(base, 'minted');
    const previous = process.umask(0o000);
    try {
      writeExclusiveOwnerOnlySync(file, 'material\n');
      expect(mode(file)).toBe(DATA_FILE_MODE);
    } finally {
      process.umask(previous);
    }
    expect(readFileSync(file, 'utf8')).toBe('material\n');
  });

  // The other half of the contract, and the reason the exclusive create is not
  // interchangeable with a plain write: an occupied path is refused rather than
  // replaced, so a planted symlink is never written through.
  it('refuses an occupied path rather than replacing it', () => {
    const file = join(base, 'incumbent');
    writeFileSync(file, 'first');

    // EEXIST specifically, not merely "something threw": a bare toThrow is
    // satisfied by an ENOENT from a bad parent or an EACCES from the mode, so it
    // would stay green over a change that never reached the O_EXCL guarantee
    // this case is named for.
    expect(() => {
      writeExclusiveOwnerOnlySync(file, 'second');
    }).toThrow(expect.objectContaining({ code: 'EEXIST' }));
    expect(readFileSync(file, 'utf8')).toBe('first');
  });

  it('never writes THROUGH a symlink planted at the path', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    const victim = join(base, 'victim');
    writeFileSync(victim, 'SECRET');
    const link = join(base, 'planted');
    symlinkSync(victim, link);

    // O_EXCL reports an existing symlink as EEXIST — pinned, because the victim
    // assertion below holds for any throw at all and cannot tell a refusal from
    // an unrelated failure.
    expect(() => {
      writeExclusiveOwnerOnlySync(link, 'attacker payload');
    }).toThrow(expect.objectContaining({ code: 'EEXIST' }));
    expect(readFileSync(victim, 'utf8')).toBe('SECRET');
  });
});

describe('writeOwnerOnlyFileSync', () => {
  it('writes the content and lands the file at 0600', () => {
    const file = join(base, 'settings.json');
    writeOwnerOnlyFileSync(file, 'hello\n');
    expect(readFileSync(file, 'utf8')).toBe('hello\n');
    if (process.platform !== 'win32') expect(mode(file)).toBe(DATA_FILE_MODE);
  });

  it('clears a stale same-pid tmp from an earlier crash and still lands 0600', () => {
    const file = join(base, 'settings.json');
    // A crash between the (per-pid) tmp write and the rename can leave the tmp
    // behind. The exclusive `wx` create would EEXIST on it, so the writer removes
    // it first; the fresh create then lands 0600.
    const tmp = `${file}.${String(process.pid)}.tmp`;
    writeFileSync(tmp, 'stale');
    chmodSync(tmp, 0o666);

    writeOwnerOnlyFileSync(file, 'fresh\n');

    expect(readFileSync(file, 'utf8')).toBe('fresh\n');
    if (process.platform !== 'win32') expect(mode(file)).toBe(DATA_FILE_MODE);
  });

  it('replaces an existing loose target and ends 0600', () => {
    const file = join(base, 'settings.json');
    writeFileSync(file, 'old');
    chmodSync(file, 0o644);

    writeOwnerOnlyFileSync(file, 'new\n');

    expect(readFileSync(file, 'utf8')).toBe('new\n');
    if (process.platform !== 'win32') expect(mode(file)).toBe(DATA_FILE_MODE);
  });

  it('never writes through or installs a symlink planted at the tmp path', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // Fault injection: an attacker with write access to the (loose) dir plants a
    // symlink at our tmp path pointing at a victim file. The write must not follow
    // it (no arbitrary overwrite) and must not install it as `file`.
    const file = join(base, 'settings.json');
    const victim = join(base, 'victim');
    writeFileSync(victim, 'SECRET');
    chmodSync(victim, 0o600);
    symlinkSync(victim, `${file}.${String(process.pid)}.tmp`);

    writeOwnerOnlyFileSync(file, 'new\n');

    expect(readFileSync(victim, 'utf8')).toBe('SECRET'); // victim untouched
    expect(lstatSync(file).isSymbolicLink()).toBe(false); // file is a real inode
    expect(readFileSync(file, 'utf8')).toBe('new\n');
    expect(mode(file)).toBe(DATA_FILE_MODE);
    expect(mode(victim)).toBe(0o600); // and never chmod'd through the link
  });

  it('leaves no orphan tmp behind when the rename fails', () => {
    // A per-process tmp that isn't cleaned on failure would accumulate forever
    // (hook processes are SIGKILLed at a timeout) — and writeKeyFile routes here,
    // so the orphans would be raw key material. Force a rename failure by making
    // the destination a directory.
    const file = join(base, 'settings.json');
    mkdirSync(file);

    expect(() => {
      writeOwnerOnlyFileSync(file, 'data\n');
    }).toThrow();

    expect(readdirSync(base).filter((f) => f.includes('.tmp'))).toEqual([]);
  });

  it('refuses to follow a planted tmp symlink the unlink could not clear (O_EXCL, not the rm)', (ctx) => {
    // Isolates `wx`: chflags makes the dir immutable so the leading rmSync can't
    // remove the planted symlink, so ONLY the exclusive create can prevent the
    // write from following it. Without `flag: 'wx'` the write overwrites the
    // victim. macOS-only, since it needs chflags to fail the unlink, so the only
    // CI leg that executes it is `macOS · Full suite` in ci.yml (a local run on a
    // Mac executes it too, and is the quickest way to reproduce a failure here).
    // That leg runs the WHOLE workspace for this reason among others; filtering
    // `persistence` out of it leaves nothing anywhere exercising `wx`.
    //
    // The skip is what makes that legible. This case reaches no assertion off
    // macOS, and an early `return` there is reported as a PASS — so every other
    // leg would read as having covered the one property only this case pins,
    // and deleting `flag: 'wx'` would keep them all green.
    if (process.platform !== 'darwin') {
      ctx.skip('needs chflags to fail the unlink, which is macOS-only');
      return;
    }
    const file = join(base, 'settings.json');
    const victim = join(base, 'victim');
    writeFileSync(victim, 'SECRET');
    chmodSync(victim, 0o600);
    symlinkSync(victim, `${file}.${String(process.pid)}.tmp`);
    execFileSync('chflags', ['uchg', base]);
    try {
      expect(() => {
        writeOwnerOnlyFileSync(file, 'PWNED\n');
      }).toThrow(/EEXIST/);
      expect(readFileSync(victim, 'utf8')).toBe('SECRET'); // wx refused to follow
    } finally {
      execFileSync('chflags', ['nouchg', base]);
    }
  });
});

describe('createOwnerOnlyFileSync', () => {
  // The exclusive twin of writeOwnerOnlyFileSync, and the one primitive both
  // machine-local keys publish their FIRST copy through. Its whole job is two
  // properties at once — exactly one caller wins, and no reader ever sees a
  // partial file — so both are pinned here rather than in either key's suite.
  const file = (): string => join(base, 'exception.key');

  it('creates the file and reports that it won', () => {
    expect(createOwnerOnlyFileSync(file(), 'first\n')).toBe(true);
    expect(readFileSync(file(), 'utf8')).toBe('first\n');
  });

  it('refuses an occupied path and leaves the incumbent byte-for-byte', () => {
    createOwnerOnlyFileSync(file(), 'first\n');

    expect(createOwnerOnlyFileSync(file(), 'second\n')).toBe(false);
    expect(readFileSync(file(), 'utf8')).toBe('first\n');
  });

  it('publishes only a COMPLETE file — the final path is never seen empty', () => {
    // The reason this exists rather than a bare exclusive open at the final
    // path: `open(O_CREAT|O_EXCL)` publishes an empty inode and fills it on the
    // next syscall, so a concurrent reader can take a live key for a corrupt
    // one. Watching every intermediate state is what distinguishes the two.
    //
    // `intercepts` is the positive control, and it carries the whole case. The
    // size assertion below reads a FILTERED array, so an empty `seen` satisfies
    // it — and an empty `seen` is precisely what a watcher that never fired
    // produces. Nothing here makes the write route through `fs.writeSync`; that
    // is an implementation detail of `writeFileSync` on the current runtime, so
    // a Node release that stops routing through it would leave every assertion
    // green while this watched nothing at all. Counting the interceptions is
    // what turns that silence into a failure. On the healthy tmp+link path the
    // count is non-zero while `seen` stays empty — the write lands on the tmp,
    // so the final path legitimately does not exist yet to be measured.
    const seen: number[] = [];
    let intercepts = 0;
    const target = file();
    const realWriteSync = fsModule.writeSync;
    fsModule.writeSync = ((...args: Parameters<typeof realWriteSync>) => {
      intercepts += 1;
      if (existsSync(target)) seen.push(statSync(target).size);
      return realWriteSync(...args);
    }) as typeof realWriteSync;
    try {
      createOwnerOnlyFileSync(target, 'complete\n');
    } finally {
      fsModule.writeSync = realWriteSync;
    }

    expect(intercepts).toBeGreaterThan(0);
    expect(seen.filter((size) => size === 0)).toEqual([]);
    expect(readFileSync(target, 'utf8')).toBe('complete\n');
  });

  it('leaves no tmp behind on either outcome', () => {
    createOwnerOnlyFileSync(file(), 'first\n');
    createOwnerOnlyFileSync(file(), 'second\n');

    expect(readdirSync(base).sort()).toEqual(['exception.key']);
  });

  it('leaves nothing at the final path when the write itself fails', () => {
    // A failed publish must not strand a half-made file at the name every later
    // reader resolves — that would brick the key permanently.
    const dirAtPath = join(base, 'exception.key');
    mkdirSync(dirAtPath);

    expect(() => createOwnerOnlyFileSync(join(dirAtPath, 'x', 'y'), 'data\n')).toThrow();
    expect(readdirSync(dirAtPath)).toEqual([]);
  });

  it.skipIf(process.platform === 'win32')('writes the file owner-only', () => {
    createOwnerOnlyFileSync(file(), 'data\n');

    expect(mode(file())).toBe(DATA_FILE_MODE);
  });

  it.skipIf(process.platform === 'win32')('refuses a symlink at the final path', () => {
    // link() will not replace an existing name, and the target is never created
    // through it — so a planted link cannot capture the key.
    const victim = join(base, 'victim');
    symlinkSync(victim, file());

    expect(createOwnerOnlyFileSync(file(), 'PWNED\n')).toBe(false);
    expect(existsSync(victim)).toBe(false);
  });
});

describe('classifyOccupant', () => {
  // Both machine-local keys use this to word the failure when a publish found
  // the path occupied and the re-read then found nothing there. The three states
  // carry different remedies, so collapsing any two sends operators after the
  // wrong thing — which is what "cannot inspect" reported as "was removed" did.
  it('names a symlink, so the remedy can be "remove it"', () => {
    const link = join(base, 'exception.key');
    symlinkSync(join(base, 'nowhere'), link);

    expect(classifyOccupant(link)).toEqual({ kind: 'symlink' });
  });

  it('reports an absent path as gone, carrying no cause', () => {
    // ENOENT is the removal itself, not a failed lookup: the caller is telling
    // us the path WAS occupied, so its absence now is the whole diagnosis.
    const result = classifyOccupant(join(base, 'exception.key'));

    expect(result).toEqual({ kind: 'gone' });
    expect(result.cause).toBeUndefined();
  });

  it('reports a real file as gone — the path changed under the read', () => {
    const target = join(base, 'exception.key');
    writeFileSync(target, 'data\n');

    expect(classifyOccupant(target)).toEqual({ kind: 'gone' });
  });

  it.skipIf(process.platform === 'win32')(
    'reports an unreadable path as unknown, and keeps the errno',
    (ctx) => {
      // The case the old boolean folded into "was removed". It is the one state
      // where the path may be perfectly intact and the lookup is what failed.
      const dir = join(base, 'locked');
      mkdirSync(dir);
      const target = join(dir, 'exception.key');
      writeFileSync(target, 'data\n');
      // Registered BEFORE the tighten, so the widen runs even on the paths the
      // in-body restores below cannot reach: a `classifyOccupant` that throws,
      // or an assertion that fails ahead of one. Removing an entry needs write
      // and execute on its PARENT, so a 0000 directory left behind is a tree
      // `rmSync` refuses — and the rm's own EACCES is then the only thing
      // reported, in place of whatever actually went wrong here.
      store.onCleanup(() => {
        try {
          chmodSync(dir, 0o700);
        } catch {
          // Already widened by the body, or a platform that never applied it.
        }
      });
      chmodSync(dir, 0o000);

      let readable = true;
      try {
        lstatSync(target);
      } catch {
        readable = false;
      }
      if (readable) {
        chmodSync(dir, 0o700);
        ctx.skip('lstat still succeeds under a 0000 dir (running as root?)');
      }

      const result = classifyOccupant(target);
      chmodSync(dir, 0o700);

      expect(result.kind).toBe('unknown');
      expect((result.cause as NodeJS.ErrnoException | undefined)?.code).toBe('EACCES');
    },
  );
});

describe('KeyUnclaimableError', () => {
  it('carries a string code, so a renderer never reads it as a corrupt file', () => {
    // Both key surfaces branch on `typeof code === 'string'` to decide whether
    // to advise deleting the file. A codeless error takes the destructive
    // branch, which here would discard a key the winner had just published.
    const err = new KeyUnclaimableError('occupied');

    expect(err.code).toBe('key-unclaimable');
    expect(typeof err.code).toBe('string');
  });

  it('omits `cause` entirely when there is none', () => {
    // `{ cause: undefined }` defines the property anyway, so the error would
    // answer `'cause' in err` while carrying nothing — a diagnosis that reads as
    // captured-then-lost rather than never-taken.
    const err = new KeyUnclaimableError('occupied');

    expect(Object.prototype.hasOwnProperty.call(err, 'cause')).toBe(false);
  });

  it('keeps a cause when given one', () => {
    const underlying = new Error('EACCES');

    const err = new KeyUnclaimableError('occupied', underlying);

    expect(Object.prototype.hasOwnProperty.call(err, 'cause')).toBe(true);
    expect(err.cause).toBe(underlying);
  });
});
