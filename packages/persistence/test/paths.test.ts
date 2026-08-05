import { execFileSync } from 'node:child_process';
import fsModule from 'node:fs';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  createOwnerOnlyFileSync,
  DATA_DIR_MODE,
  DATA_FILE_MODE,
  dbSidecars,
  ensureDataDirSync,
  tightenDir,
  tightenFile,
  tightenPerms,
  writeOwnerOnlyFileSync,
} from '../src/paths.ts';

// The POSIX file/dir modes are the ONLY at-rest control on the store — see the
// "Data at rest" note in SECURITY.md. These tests pin the success modes (the
// directory mode was previously unasserted anywhere, and the sidecar modes were
// never asserted); the chmod-failure branch is a silent best-effort catch,
// exercised in database/settings fault cases rather than here. All mode
// assertions skip on Windows, where POSIX modes are a no-op.

let base: string;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-paths-'));
});

afterEach(() => {
  rmSync(base, { recursive: true, force: true });
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
    if (process.platform === 'win32') return;
    expect(mode(dir)).toBe(DATA_DIR_MODE);
  });

  it('tightens an existing loose directory to 0700 (chmods after mkdir)', () => {
    const dir = join(base, 'data');
    mkdirSync(dir);
    chmodSync(dir, 0o777);
    if (process.platform !== 'win32') {
      expect(mode(dir)).toBe(0o777); // precondition: genuinely loose
    }

    ensureDataDirSync(dir);

    if (process.platform === 'win32') return;
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
    if (process.platform === 'win32') return;
    expect(mode(dir)).toBe(DATA_DIR_MODE);
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
    // volume) must keep working, and a hook must never break on one. `aka init`
    // is what names the link — see symlinkedStorePaths in the CLI.
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
  it('sets 0600 on the db file and all of its sidecars', () => {
    const file = join(base, 'aka.db');
    // Create the set with deliberately loose modes so the chmod is observable.
    for (const p of [file, ...dbSidecars(file)]) {
      writeFileSync(p, '');
      chmodSync(p, 0o644);
    }

    tightenPerms(file);

    if (process.platform === 'win32') return;
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
    if (process.platform === 'win32') return;
    expect(mode(file)).toBe(DATA_FILE_MODE);
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
  it('sets 0600 on a single file (a backup copy, the exception key)', () => {
    const file = join(base, 'aka.db.legacy.bak');
    writeFileSync(file, 'corpus copy');
    chmodSync(file, 0o644); // as VACUUM INTO / a mode-preserving rename would leave it

    tightenFile(file);

    if (process.platform === 'win32') return;
    expect(mode(file)).toBe(DATA_FILE_MODE);
  });

  it('does not throw when the file is absent (fail-open)', () => {
    expect(() => {
      tightenFile(join(base, 'nope'));
    }).not.toThrow();
  });

  it('never chmods THROUGH a symlink (self-heal must not tighten an arbitrary target)', () => {
    if (process.platform === 'win32') return;
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

describe('writeOwnerOnlyFileSync', () => {
  it('writes the content and lands the file at 0600', () => {
    const file = join(base, 'settings.json');
    writeOwnerOnlyFileSync(file, 'hello\n');
    expect(readFileSync(file, 'utf8')).toBe('hello\n');
    if (process.platform === 'win32') return;
    expect(mode(file)).toBe(DATA_FILE_MODE);
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
    if (process.platform === 'win32') return;
    expect(mode(file)).toBe(DATA_FILE_MODE);
  });

  it('replaces an existing loose target and ends 0600', () => {
    const file = join(base, 'settings.json');
    writeFileSync(file, 'old');
    chmodSync(file, 0o644);

    writeOwnerOnlyFileSync(file, 'new\n');

    expect(readFileSync(file, 'utf8')).toBe('new\n');
    if (process.platform === 'win32') return;
    expect(mode(file)).toBe(DATA_FILE_MODE);
  });

  it('never writes through or installs a symlink planted at the tmp path', () => {
    if (process.platform === 'win32') return;
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

  it('refuses to follow a planted tmp symlink the unlink could not clear (O_EXCL, not the rm)', () => {
    // Isolates `wx`: chflags makes the dir immutable so the leading rmSync can't
    // remove the planted symlink, so ONLY the exclusive create can prevent the
    // write from following it. Without `flag: 'wx'` the write overwrites the
    // victim. macOS-only (needs chflags to fail the unlink); no macOS CI, so this
    // runs locally.
    if (process.platform !== 'darwin') return;
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
    const seen: number[] = [];
    const target = file();
    const realWriteSync = fsModule.writeSync;
    fsModule.writeSync = function watched(...args: Parameters<typeof realWriteSync>) {
      if (existsSync(target)) seen.push(statSync(target).size);
      return realWriteSync.apply(this, args);
    } as typeof realWriteSync;
    try {
      createOwnerOnlyFileSync(target, 'complete\n');
    } finally {
      fsModule.writeSync = realWriteSync;
    }

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
