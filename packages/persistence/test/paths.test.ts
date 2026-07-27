import { execFileSync } from 'node:child_process';
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
  DATA_DIR_MODE,
  DATA_FILE_MODE,
  dbSidecars,
  ensureDataDirSync,
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
