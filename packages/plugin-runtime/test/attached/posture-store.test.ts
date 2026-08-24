import { chmod, mkdir, mkdtemp, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { createPostureStore, type PostureState, type PostureStore } from '../../src/attached/posture-store';

// read() is nullable — null means "no identity could be established this
// attempt" (see posture-store.ts). Every success-path test in this file
// expects a real value; this unwraps that or fails with a clear message
// instead of a TS18047 chain at every call site.
async function mustRead(store: PostureStore): Promise<PostureState> {
  const state = await store.read();
  if (state === null) throw new Error('expected read() to return a state, got null');
  return state;
}

// A directory this process owns cannot be made durably unwritable by chmod
// alone: ensureDataDir() unconditionally best-effort chmods it back to
// DATA_DIR_MODE on every call (see local-layout.ts), which silently defeats
// a `chmod(dir, 0o500)` before persist() ever gets to write. A FILE in the
// path, on the other hand, blocks `mkdir(..., { recursive: true })` with
// ENOTDIR regardless of ownership or mode — reliable, and not something
// ensureDataDir's own error handling swallows.
async function makeUnwritableDir(): Promise<string> {
  const blocker = await mkdtemp(join(tmpdir(), 'aka-posture-blocker-'));
  const blockerFile = join(blocker, 'not-a-dir');
  await writeFile(blockerFile, '');
  return join(blockerFile, 'settings');
}

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'aka-posture-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('createPostureStore', () => {
  it('mints a uuid deviceId on first read and keeps it stable across stores', async () => {
    const a = await mustRead(createPostureStore(dir));
    expect(a.deviceId).toMatch(/^[0-9a-f-]{36}$/);
    expect(a.lastAttemptedAtMs).toBe(0);
    const b = await mustRead(createPostureStore(dir)); // fresh instance, same dir
    expect(b.deviceId).toBe(a.deviceId);
  });

  it('markAttempted persists the timestamp against the caller-supplied deviceId', async () => {
    const store = createPostureStore(dir);
    const state = await mustRead(store);
    await store.markAttempted(state.deviceId, 1_780_000_000_000);
    const reread = await mustRead(createPostureStore(dir));
    expect(reread.lastAttemptedAtMs).toBe(1_780_000_000_000);
    expect(reread.deviceId).toBe(state.deviceId);
  });

  it('markAttempted keeps the reported deviceId even if the state file vanished mid-report', async () => {
    // The reporter reads state (deviceId A), sends the snapshot under A, then
    // marks. If markAttempted re-read the file it would mint a fresh id here and
    // strand A's row on the backend — so it must persist exactly what it was given.
    const store = createPostureStore(dir);
    const state = await mustRead(store);
    await rm(store.file, { force: true });
    await store.markAttempted(state.deviceId, 1_780_000_000_000);
    const reread = await mustRead(createPostureStore(dir));
    expect(reread.deviceId).toBe(state.deviceId);
    expect(reread.lastAttemptedAtMs).toBe(1_780_000_000_000);
  });

  // Root bypasses file permission checks entirely, which would make this
  // assert the opposite of what it's testing.
  it.skipIf(process.getuid?.() === 0)(
    'a transient permission error on an EXISTING file refuses to mint, and never overwrites it',
    async () => {
      // existsSync/plain-catch used to collapse EVERY readFile failure into
      // "no identity yet" — absence AND a one-off EACCES/EIO on a file that is
      // very much still there. That minted a fresh id and overwrote the intact
      // file, destroying the continuity this store exists to preserve. Only a
      // genuine ENOENT/ENOTDIR may mint; anything else must propagate and
      // leave the file untouched.
      const store = createPostureStore(dir);
      const original = await mustRead(store);
      await chmod(store.file, 0o000);
      try {
        await expect(store.read()).rejects.toThrow();
      } finally {
        await chmod(store.file, 0o600);
      }
      // Untouched: re-reading recovers the SAME identity, not a fresh one.
      expect((await mustRead(store)).deviceId).toBe(original.deviceId);
    },
  );

  it('a corrupt state file behaves like a fresh install (fail-open, new deviceId)', async () => {
    const store = createPostureStore(dir);
    await writeFile(store.file, '{not json', 'utf8');
    const state = await mustRead(store);
    expect(state.deviceId).toMatch(/^[0-9a-f-]{36}$/);
    expect(state.lastAttemptedAtMs).toBe(0);
  });

  it('carries over the pre-rename lastReportedAtMs stamp', async () => {
    // The field was `lastReportedAtMs` before the throttle moved from
    // advance-on-success to advance-on-attempt. Ignoring the old spelling would
    // reset every upgrading device's stamp to 0, so the whole fleet would come
    // due at once on the first session after the rollout. The two stamps mean
    // close enough for a throttle that carrying it over beats the burst.
    const store = createPostureStore(dir);
    const { deviceId } = await mustRead(store);
    await writeFile(store.file, JSON.stringify({ deviceId, lastReportedAtMs: 1_780_000_000_000 }));
    expect((await mustRead(createPostureStore(dir))).lastAttemptedAtMs).toBe(1_780_000_000_000);
  });

  it('writes 0600 via atomic tmp-swap (no .tmp left behind)', async () => {
    // NOT `${store.file}.tmp` — persist() suffixes the tmp file with a
    // randomized uuid (`${file}.${randomUUID()}.tmp`) specifically so two
    // concurrent hooks don't collide on one shared name, so that fixed
    // filename can never exist and asserting its absence passed regardless
    // of whether rename() did anything at all. Glob the directory instead,
    // and check the mode the test's own title claims but never verified.
    const store = createPostureStore(dir);
    await mustRead(store);
    const entries = await readdir(dir);
    expect(entries.filter((f) => f.includes('.tmp'))).toEqual([]);
    const mode = (await stat(store.file)).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it('a forced rename failure leaves the randomized tmp file behind — a known, accepted leak', async () => {
    // Names the property Pedro's finding pointed at rather than leaving it
    // uncovered: an atomic tmp-swap is not atomic against every failure mode.
    // If persist() dies between writeFile and rename (here: the destination
    // path is itself a directory, so rename() fails with EISDIR), the
    // already-written tmp file has no owner left to clean it up. Fail-open
    // swallows the error at every call site (markAttempted, read()'s
    // best-effort persist), so this never surfaces to the caller — it just
    // accumulates unless something else prunes ~/.aka/settings. Not fixed
    // here (out of scope for this finding); documented so a future reader
    // finds it as a known tradeoff, not a silent gap.
    const store = createPostureStore(dir);
    await mkdir(store.file, { recursive: true }); // destination is a DIR, not a file
    await expect(store.markAttempted('aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', 1)).rejects.toThrow();
    const entries = await readdir(dir);
    expect(entries.some((f) => f.includes('.tmp'))).toBe(true);
  });

  describe('read() is fail-open when persisting a new/adopted identity fails', () => {
    it('an unwritable settings dir refuses to mint a FRESH identity, rather than reporting under an unrecoverable one', async () => {
      // Unlike adoption, a fresh mint has no prior identity to fall back to:
      // returning one anyway when persist() fails would mint ANOTHER fresh id
      // next SessionStart too (nothing was ever saved), manufacturing an
      // orphan backend row every session with isRegression permanently blind.
      // null — "no report this attempt" — is the fail-open answer here.
      expect(await createPostureStore(await makeUnwritableDir()).read()).toBeNull();
    });

    it('an unwritable settings dir does not discard a successfully-read legacy identity', async () => {
      // read()'s adoption path first reads the legacy file (a success), then
      // rewrites it at the new location (a write). A propagated failure on
      // that rewrite must not throw away the identity the read already
      // recovered — that would turn an already-enrolled device silent. Unlike
      // the fresh-mint case above, there IS a prior identity here, so this
      // path stays best-effort and must still return it.
      const legacyDir = await mkdtemp(join(tmpdir(), 'aka-posture-legacy-'));
      try {
        const legacy = createPostureStore(legacyDir);
        const before = await mustRead(legacy);
        const adopted = await mustRead(createPostureStore(await makeUnwritableDir(), legacyDir));
        expect(adopted.deviceId).toBe(before.deviceId);
      } finally {
        await rm(legacyDir, { recursive: true, force: true });
      }
    });
  });

  describe('identity survives a wipe of the measured directory', () => {
    it('adopts a pre-move identity from legacyDir instead of re-enrolling', async () => {
      // An already-enrolled device upgrading past the settings/ move must keep
      // its deviceId — minting a fresh one would strand its server-side row and
      // make the next report look like a first-ever report, which is exactly
      // how a wipe goes undetected.
      const legacyDir = await mkdtemp(join(tmpdir(), 'aka-posture-legacy-'));
      try {
        const legacy = createPostureStore(legacyDir);
        const before = await mustRead(legacy);
        await legacy.markAttempted(before.deviceId, 1_780_000_000_000);

        const moved = await mustRead(createPostureStore(dir, legacyDir));
        expect(moved.deviceId).toBe(before.deviceId);
        expect(moved.lastAttemptedAtMs).toBe(1_780_000_000_000);
        // Adopted, i.e. rewritten at the new location — so the next read no
        // longer depends on the legacy dir existing at all.
        await rm(legacyDir, { recursive: true, force: true });
        expect((await mustRead(createPostureStore(dir, legacyDir))).deviceId).toBe(before.deviceId);
      } finally {
        await rm(legacyDir, { recursive: true, force: true });
      }
    });

    it('keeps the deviceId when the measured dir is destroyed', async () => {
      // The attack the regression detector exists to catch: rm -rf ~/.aka/data.
      // With the identity in settings/, the post-wipe report lands on the same
      // backend row and its preserved baseline, so the wipe is visible.
      const measuredDir = await mkdtemp(join(tmpdir(), 'aka-posture-data-'));
      try {
        const before = await mustRead(createPostureStore(dir, measuredDir));
        await rm(measuredDir, { recursive: true, force: true });
        const after = await mustRead(createPostureStore(dir, measuredDir));
        expect(after.deviceId).toBe(before.deviceId);
      } finally {
        await rm(measuredDir, { recursive: true, force: true });
      }
    });

    it('does not reach outside `dir` when no legacyDir is supplied', async () => {
      // Adoption is opt-in: a bare createPostureStore(tmp) must never read the
      // developer's real ~/.aka/data.
      const legacyDir = await mkdtemp(join(tmpdir(), 'aka-posture-legacy-'));
      try {
        const planted = await mustRead(createPostureStore(legacyDir));
        const isolated = await mustRead(createPostureStore(dir));
        expect(isolated.deviceId).not.toBe(planted.deviceId);
      } finally {
        await rm(legacyDir, { recursive: true, force: true });
      }
    });

    // Root uid bypasses file permission checks entirely, which would make
    // this assert the opposite of what it's testing.
    it.skipIf(process.getuid?.() === 0)(
      'an unreadable legacy file falls through to fresh-mint, rather than blocking read() forever',
      async () => {
        // A permission error on `file` (the current location) is right to
        // throw and protect — but the SAME throw on `legacyFile` inside
        // read() used to propagate too, and since adoption is attempted on
        // EVERY call until a current file exists, that meant a device with
        // an unreadable legacy location could never mint a fresh identity —
        // not just this session, but permanently, for as long as the legacy
        // path stayed unreadable.
        const legacyDir = await mkdtemp(join(tmpdir(), 'aka-posture-legacy-'));
        try {
          const legacyFile = join(legacyDir, 'posture-state.json');
          await writeFile(legacyFile, JSON.stringify({ deviceId: 'irrelevant' }), 'utf8');
          await chmod(legacyFile, 0o000);
          try {
            const state = await mustRead(createPostureStore(dir, legacyDir));
            expect(state.deviceId).toMatch(/^[0-9a-f-]{36}$/);
          } finally {
            await chmod(legacyFile, 0o600);
          }
        } finally {
          await rm(legacyDir, { recursive: true, force: true });
        }
      },
    );
  });
});
