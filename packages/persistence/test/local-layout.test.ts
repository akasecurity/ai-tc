import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';

import { beforeEach, describe, expect, it } from 'vitest';

import {
  dataDir,
  dbPath,
  ensureDataDir,
  ensureLayoutDirSync,
  migrateLegacyLayout,
  settingsDir,
} from '../src/local-layout.ts';
import { useTempStore } from './helpers/temp-store.ts';

// The harness owns the temp tree, for the retrying removal and the teardown
// failure it demotes to a `cause` rather than reporting in place of the body's
// own error — cases below leave a directory at 0777 and one at 0755, and the
// async symlink cases leave a dangling-free symlink the removal unlinks rather
// than recurses into.
//
// `base` is a subdirectory rather than the store's own root: this suite is what
// tests the layout helpers, so it has to create `settings/` and `data/` itself
// (one case pre-creates a LOOSE settings/ and asserts the migration tightens it),
// and the harness has already created both under its root.
const store = useTempStore('aka-datadir-');
let base: string;

beforeEach(() => {
  base = join(store.home, 'base');
  mkdirSync(base);
});

const mode = (p: string): number => statSync(p).mode & 0o777;

describe('layout helpers', () => {
  it('compose settings/, data/, and the db path from a base', () => {
    expect(settingsDir(base)).toBe(join(base, 'settings'));
    expect(dataDir(base)).toBe(join(base, 'data'));
    expect(dbPath(base)).toBe(join(base, 'data', 'aka.db'));
  });
});

describe('ensureLayoutDirSync', () => {
  it('creates the directory owner-only (0700) where POSIX modes apply', () => {
    const dir = dataDir(base);
    ensureLayoutDirSync(dir);
    expect(existsSync(dir)).toBe(true);
    if (process.platform !== 'win32') expect(mode(dir)).toBe(0o700);
  });

  it('tightens an existing loose base directory to 0700', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    // An ~/.aka created by an older release (or the user) with looser
    // permissions must be tightened, not left as it was found.
    const home = join(base, 'loose-home');
    mkdirSync(home);
    chmodSync(home, 0o755);
    ensureLayoutDirSync(home);
    expect(mode(home)).toBe(0o700);
  });

  it('leaves the whole ~/.aka layout owner-only (0700 base, settings/, data/) — the `aka init` shape', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    // Mirrors what `aka init` composes: ensure the base, then settings/, then
    // data/ (the last via openLocalDatabase). All three are the store's only
    // at-rest control and must all end 0700.
    const home = join(base, 'home');
    ensureLayoutDirSync(home);
    ensureLayoutDirSync(settingsDir(home));
    ensureLayoutDirSync(dataDir(home));
    expect(mode(home)).toBe(0o700);
    expect(mode(settingsDir(home))).toBe(0o700);
    expect(mode(dataDir(home))).toBe(0o700);
  });
});

// The async twin is published API of BOTH @akasecurity/persistence and
// @akasecurity/plugin-sdk, so a consumer can call it even though nothing in this
// repository does. Three properties are under test here: the mode passed to
// mkdir (which is all that reaches the levels ABOVE the leaf), the shared
// tightenDir (all that reaches a leaf that pre-existed), and the DELEGATION to
// that shared helper rather than a chmod of its own — the last is what carries
// the symlink guard onto this path, and is the divergence the shared helper was
// introduced to prevent.
//
// Every case passes an explicit dir. Never call `ensureDataDir()` bare to cover
// its default parameter: that resolves to the real ~/.aka and would create and
// chmod the developer's own home, outside the temp store entirely.
describe('ensureDataDir (async)', () => {
  it('creates the directory owner-only (0700) where POSIX modes apply', async () => {
    const dir = dataDir(base);

    await ensureDataDir(dir);

    expect(existsSync(dir)).toBe(true);
    if (process.platform !== 'win32') expect(mode(dir)).toBe(0o700);
  });

  it('tightens an existing loose directory to 0700 (chmods after mkdir)', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    // A dir that already existed with looser permissions must be tightened, not
    // left as it was found — mkdir applies its mode at CREATION only, so on a
    // pre-existing dir the tighten is the only thing that can reach it.
    const dir = join(base, 'loose-data');
    mkdirSync(dir);
    chmodSync(dir, 0o777);
    // Unguarded because the ctx.skip at the top of this body already returned on
    // Windows; narrowing that skip means restoring a platform guard here.
    expect(mode(dir)).toBe(0o777); // precondition: genuinely loose

    await ensureDataDir(dir);

    expect(mode(dir)).toBe(0o700);
  });

  it('holds every level it creates at 0700, not just the leaf it tightens', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    // The tighten reaches the LEAF only, so the mode passed to mkdir is the one
    // thing holding the levels above it. Without a case that creates a PARENT,
    // dropping that mode is invisible: the leaf self-heals through the tighten
    // while every level above it is left at the caller's umask — 0755 on a
    // default host, 0777 under a permissive one.
    const dir = join(base, 'a', 'b', 'c');

    await ensureDataDir(dir);

    for (const p of [join(base, 'a'), join(base, 'a', 'b'), dir]) {
      // Named, so a failure says WHICH level was left loose: a leaf that
      // self-healed above a loose parent is a different defect from a leaf that
      // was never tightened, and the bare mode numbers cannot tell them apart.
      expect(mode(p), p).toBe(0o700);
    }
  });

  it('never chmods THROUGH a directory symlink (a victim dir keeps its mode)', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // The symlink guard lives in the shared tightenDir, so the async path gets
    // it only by delegating rather than chmod'ing itself. A planted store-dir
    // symlink must leave its target's mode alone, and mkdir must no-op on it
    // rather than refuse: a hook has to keep working on a hostile home.
    //
    // This asserts a chmod did NOT happen, which a tighten that never runs at
    // all satisfies equally well — the case below is its positive control.
    const victim = join(base, 'victim-shared');
    mkdirSync(victim);
    chmodSync(victim, 0o755);
    const link = join(base, '.aka');
    symlinkSync(victim, link);

    await ensureDataDir(link);

    expect(mode(victim)).toBe(0o755); // victim NOT tightened through the link
    expect(lstatSync(link).isSymbolicLink()).toBe(true); // link left as-is
  });

  it('still tightens a real directory created INSIDE a symlinked home', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // Only the FINAL component is checked, so a real inode inside a deliberately
    // symlinked home is still ours to hold at 0700 — widening the guard to any
    // symlinked ancestor would drop the store's only at-rest control instead.
    //
    // This is also the positive control for the case above: together they
    // separate "the symlink guard works" from "nothing is tightened any more",
    // which an absence assertion alone cannot do.
    //
    // data/ must PRE-EXIST loose for either half to mean anything: mkdir applies
    // its mode at creation, so on a fresh dir the assertion passes whether or
    // not the chmod ran.
    const victim = join(base, 'victim-shared');
    mkdirSync(join(victim, 'data'), { recursive: true });
    chmodSync(join(victim, 'data'), 0o755);
    chmodSync(victim, 0o755);
    const link = join(base, '.aka');
    symlinkSync(victim, link);

    await ensureDataDir(join(link, 'data'));

    expect(mode(join(victim, 'data'))).toBe(0o700);
    expect(mode(victim)).toBe(0o755); // and the link's own target still untouched
  });
});

describe('migrateLegacyLayout', () => {
  it('routes pre-layout flat files to their layout subdirs (best-effort)', () => {
    writeFileSync(join(base, 'config.json'), '{"backendUrl":"https://x","token":"t"}');
    writeFileSync(join(base, 'policy-cache.json'), '{"bundle":{}}');

    migrateLegacyLayout(base);

    expect(existsSync(join(base, 'config.json'))).toBe(false);
    expect(existsSync(join(base, 'policy-cache.json'))).toBe(false);
    // config.json is settings; policy-cache.json is a cache that lives with the
    // SQLite store under data/.
    expect(readFileSync(join(settingsDir(base), 'config.json'), 'utf8')).toContain('backendUrl');
    expect(existsSync(join(dataDir(base), 'policy-cache.json'))).toBe(true);
  });

  it('is a no-op when there is nothing to migrate', () => {
    expect(() => {
      migrateLegacyLayout(base);
    }).not.toThrow();
  });

  it('tightens a pre-existing loose destination dir to 0700 while migrating', () => {
    // A settings/ that already existed with looser permissions must be tightened
    // as the flat config.json is routed into it — it holds sensitive files.
    writeFileSync(join(base, 'config.json'), '{"backendUrl":"https://x","token":"t"}');
    mkdirSync(settingsDir(base));
    chmodSync(settingsDir(base), 0o777);

    migrateLegacyLayout(base);

    expect(existsSync(join(settingsDir(base), 'config.json'))).toBe(true);
    if (process.platform !== 'win32') expect(mode(settingsDir(base))).toBe(0o700);
  });

  it('tightens a moved legacy config.json to 0600 (it can carry a token)', () => {
    // A pre-layout config.json held the backend token; a rename preserves its
    // (possibly loose) mode, so the moved file must be tightened to 0600 too —
    // not left group/other-readable inside settings/.
    const flat = join(base, 'config.json');
    writeFileSync(flat, '{"backendUrl":"https://x","token":"t"}');
    if (process.platform !== 'win32') chmodSync(flat, 0o644);

    migrateLegacyLayout(base);

    const moved = join(settingsDir(base), 'config.json');
    expect(existsSync(moved)).toBe(true);
    if (process.platform !== 'win32') expect(mode(moved)).toBe(0o600);
  });
});
