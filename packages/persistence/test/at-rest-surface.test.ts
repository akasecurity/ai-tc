import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { basename, join, relative, sep } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { describe, expect, it } from 'vitest';

import { EXCEPTION_KEY_FILENAME, loadOrCreateFingerprintKey } from '../src/fingerprint.ts';
import { SNAPSHOT_STAGING_COPY, SNAPSHOT_STAGING_SUFFIX } from '../src/internal/snapshot.ts';
import { keysDir } from '../src/local-layout.ts';
import { DATA_DIR_MODE, DATA_FILE_MODE, DB_FILENAME, dbSidecars } from '../src/paths.ts';
import { applyOnboarding, SETTINGS_FILENAME } from '../src/settings.ts';
import { FileKeyProvider, VAULT_KEY_FILENAME } from '../src/vault/key-provider.ts';
import { capWarnEraEnforcementOnce } from '../src/warn-era-cap.ts';
import { useTempStore } from './helpers/temp-store.ts';

/**
 * Everything `~/.aka` actually holds, against what is claimed about it.
 *
 * `at-rest-docs.test.ts` derives each NAME from the module that writes it, which
 * is what stops a renamed constant drifting out of SECURITY.md's enumeration.
 * What it cannot do is notice a FIFTH file: the list of modules it reads is a
 * literal, so an artifact nobody thought to add to it reddens nothing — the same
 * shape as the hardcoded directory list that guard's review round removed, one
 * level up. `policy-cache.json`, the warn-era marker and the vault rotation lock
 * were all live instances.
 *
 * This is the other half, and it derives the SET rather than the names: the store
 * is exercised through its real writers and the tree is then walked, so a new
 * artifact has to be either owner-only and classified, or it fails here. That
 * makes the two guards complements — neither subsumes the other, and a file has
 * to get past both.
 */
const store = useTempStore('aka-at-rest-surface-');

/** Every path under `home`, files and directories alike, relative and posix. */
function walk(home: string): string[] {
  const out: string[] = [];
  const visit = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      out.push(relative(home, path).split(sep).join('/'));
      if (entry.isDirectory()) visit(path);
    }
  };
  visit(home);
  return out.sort();
}

/**
 * Put the store through every writer that lands something under `~/.aka`.
 *
 * Run under a 0o000 umask, which is the whole instrument for the mode assertion
 * below: a umask only ever CLEARS bits, so under 0o077 a create that passed no
 * mode at all would still come out 0600 and the assertion would hold over the
 * mutant. Under 0o000 a create keeps exactly what it asked for.
 *
 * `applyOnboarding` takes the settings file's own lock, and the vault provider
 * takes its rotation lock, so this also exercises the two lock files — which is
 * deliberate: both are artifacts under `~/.aka` and both are what item 5 of the
 * enumeration gap was about.
 */
async function exerciseStore(): Promise<void> {
  const previous = process.umask(0o000);
  let pending: Promise<unknown>[];
  try {
    // A tenant-bearing store planted before the first open, so the
    // foreign-lineage reset fires and leaves a REAL `aka.db.legacy.<ts>.<rand>.bak`
    // in the walked tree. Without it nothing here writes a `.bak` at all — the
    // pre-drop snapshot is taken only where the legacy drop would destroy rows,
    // and a store this open builds has none — which would leave the `/\.bak$/`
    // exclusion below matching nothing and so exempt from the staleness ratchet
    // for good. It is planted INSIDE the umask window on purpose: the copy is
    // made from a world-readable source, so the 0600 the walk then asserts is
    // the tightening doing the work rather than the umask.
    const foreign = new DatabaseSync(join(store.dataDir, DB_FILENAME));
    foreign.exec('CREATE TABLE events (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL)');
    foreign.exec('PRAGMA user_version = 10');
    foreign.close();

    const db = store.open();
    db.policies.upsertCategoryAction('secret', 'block');
    capWarnEraEnforcementOnce(db, 'warn', store.dataDir);
    applyOnboarding({ policy: 'warn' }, store.home);
    loadOrCreateFingerprintKey(store.dataDir);
    // Rotated as well as minted, so the keyring's REWRITE path runs and not only
    // its first-mint one — separate writers, and only the rewrite takes the
    // rotation lock. Both provider bodies run synchronously and are wrapped in
    // an already-settled promise (see asAsync), so every write below has landed
    // by the time the umask is restored; awaiting them outside the `finally` is
    // what turns a rejection into a failed test rather than an unhandled
    // rejection that fails some later one.
    const vault = new FileKeyProvider(keysDir(store.home));
    pending = [vault.loadOrCreate(), vault.rotate()];
  } finally {
    process.umask(previous);
  }
  await Promise.all(pending);
}

// A literal taken from a source module, made safe to embed in a pattern. The
// names below are DERIVED rather than spelled, so whatever the module holds has
// to survive the trip into a RegExp — a bare `.replace('.', '\\.')` escaped only
// the first dot and would mis-anchor the day a suffix grew a second one.
const escapeRe = (literal: string): string => literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * What the store may hold beyond SECURITY.md's enumerated set, and why each is
 * not in it. Every entry is still held to the owner-only modes — the exclusion
 * is from the NOTE's file list, never from the at-rest control.
 *
 * Matched against the walk's RELATIVE PATH, not the bare basename. A basename
 * match reads as tidier and is too wide in exactly the places it matters: `copy`
 * and `owner` are ordinary words, and exempting them everywhere would let a
 * future `data/copy` or `settings/owner` through the classification case
 * unnoticed — the one thing this guard exists to catch. Anchoring each to the
 * directory that gives it its meaning keeps the exemption as narrow as the
 * reason for it.
 *
 * `coveredBy` is what separates the two kinds, and the distinction is not
 * bookkeeping. An entry WITHOUT it names something that survives a write, so the
 * walk below sees it and a pattern that stopped matching is reported as stale —
 * an exclusion for an artifact nothing writes any more reads as reviewed and
 * covers nothing. An entry WITH it names something that exists only for the
 * length of one operation: a lock is released, a staging directory is removed on
 * both the success and the failure path, and a policy cache is written by a
 * different package altogether. No post-hoc walk can observe those, so the
 * staleness ratchet cannot apply to them, and what stands in for it is the suite
 * named — each of which asserts the artifact's own mode where it is live.
 */
const DOCUMENTED_EXCLUSIONS: readonly {
  pattern: RegExp;
  reason: string;
  coveredBy?: string;
}[] = [
  {
    pattern: /\.bak$/,
    reason:
      'a snapshot copy of the store; the note covers these in their own paragraph rather than in the file list, because the name carries a timestamp. Durable, and deliberately still observable to the walk: exerciseStore plants a tenant-bearing store so the foreign-lineage reset writes one, which is what keeps this entry inside the staleness ratchet',
  },
  {
    pattern: new RegExp(`\\.bak${escapeRe(SNAPSHOT_STAGING_SUFFIX)}$`),
    reason:
      'the staging directory a killed snapshot leaves; covered by its own paragraph in the note, and owner-only from before the copy starts',
    coveredBy:
      "test/internal/snapshot.test.ts — 'creates the staging directory owner-only, before anything is written into it'",
  },
  {
    pattern: new RegExp(
      `\\.bak${escapeRe(SNAPSHOT_STAGING_SUFFIX)}/${escapeRe(SNAPSHOT_STAGING_COPY)}$`,
    ),
    reason: 'the in-progress copy inside a staging directory, reachable only through it',
    coveredBy:
      "test/internal/snapshot.test.ts — 'publishes a complete copy and leaves no partial file behind'",
  },
  {
    pattern: /(?:^|\/)warn-era-capped$/,
    reason:
      'a one-time marker holding an ISO timestamp — no store content, so the note does not list it among the files that hold the corpus',
  },
  {
    pattern: /(?:^|\/)policy-cache\.json$/,
    reason:
      'a cache of the policy snapshot, rebuildable from the store; written by the plugin SDK rather than this package, and relocated into data/ by migrateLegacyLayout',
    coveredBy: 'test/local-layout.test.ts — the legacy-layout relocation',
  },
  {
    pattern: /\.lock$/,
    reason:
      'a lock held for the length of one write (settings.json, or a vault rotation), not an artifact that outlives it',
    coveredBy:
      "test/vault/key-provider.test.ts — 'holds the rotation lock and its owner file owner-only'",
  },
  {
    pattern: /\.lock\/owner$/,
    reason:
      'the holder token inside a rotation lock directory, named so a release can prove it still owns the lock',
    coveredBy:
      "test/vault/key-provider.test.ts — 'holds the rotation lock and its owner file owner-only'",
  },
  {
    pattern: /^(settings|data|keys)$/,
    reason: 'the layout directories, which the note enumerates as directories rather than files',
  },
];

/**
 * The names SECURITY.md's own file list covers, derived as that guard does.
 *
 * `dbSidecars` is given the bare filename, so what comes back is already bare —
 * no basename step, which only read as one because `DB_FILENAME` has no
 * directory in it to strip.
 */
const ENUMERATED = new Set<string>([
  DB_FILENAME,
  ...dbSidecars(DB_FILENAME),
  EXCEPTION_KEY_FILENAME,
  SETTINGS_FILENAME,
  VAULT_KEY_FILENAME,
]);

describe('the ~/.aka surface', () => {
  it('is exercised into more than the store file alone', async () => {
    await exerciseStore();
    // The precondition every case below rests on. An exerciser that wrote
    // nothing would satisfy a "every file is owner-only" claim over an empty
    // tree, and satisfy the classification claim the same way.
    const found = walk(store.home);
    expect(found.length).toBeGreaterThan(6);
    expect(found).toContain(`data/${DB_FILENAME}`);
    expect(found).toContain(`settings/${SETTINGS_FILENAME}`);
    expect(found).toContain(`${basename(keysDir(store.home))}/${VAULT_KEY_FILENAME}`);
    expect(found).toContain(`data/${EXCEPTION_KEY_FILENAME}`);
  });

  // The property the note actually claims, over the tree rather than over a
  // list: EVERY file the store writes is 0600 and every directory 0700. A file
  // added tomorrow is covered without an edit here, which is what the guard next
  // door cannot do.
  it('holds every file 0600 and every directory 0700', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    await exerciseStore();

    const loose = walk(store.home)
      .map((path) => ({ path, stat: statSync(join(store.home, path)) }))
      .filter(
        ({ stat }) => (stat.mode & 0o777) !== (stat.isDirectory() ? DATA_DIR_MODE : DATA_FILE_MODE),
      )
      .map(({ path, stat }) => `${path} is 0${(stat.mode & 0o777).toString(8)}`);

    expect(loose).toEqual([]);
  });

  // And every one of them is either in the note's list or recorded above as a
  // deliberate omission. This is the half that fails when a fifth artifact
  // appears: it cannot be quietly absent from both.
  it('writes nothing that is neither enumerated nor a recorded exclusion', async () => {
    await exerciseStore();

    const unclassified = walk(store.home).filter((path) => {
      // The note's list is a set of FILENAMES wherever the layout puts them;
      // an exclusion is anchored to the path that gives it its meaning.
      if (ENUMERATED.has(basename(path))) return false;
      return !DOCUMENTED_EXCLUSIONS.some(({ pattern }) => pattern.test(path));
    });

    expect(unclassified).toEqual([]);
  });

  // An exclusion for something the store stopped writing reads as reviewed and
  // covers nothing, so it is reported rather than left to rot. Scoped to the
  // entries that survive a write — the rest name where they are covered instead,
  // and the case below is what keeps that from being a way out of this one.
  it('records no persistent exclusion that matches nothing the store writes', async () => {
    await exerciseStore();
    const paths = walk(store.home);

    const stale = DOCUMENTED_EXCLUSIONS.filter(
      ({ pattern, coveredBy }) => coveredBy === undefined && !paths.some((p) => pattern.test(p)),
    ).map(({ pattern }) => pattern.source);

    expect(stale).toEqual([]);
  });

  // The other side of that scoping. `coveredBy` is what buys an entry out of the
  // staleness ratchet, so it has to name a case that exists — otherwise the way
  // to silence a stale exclusion is to invent a citation for it.
  //
  // Checking the FILE alone is not enough, and that is the whole point: every
  // path cited here is a file that plainly exists, so a fabricated or drifted
  // case NAME inside one sails through. The name is read out of the quotes and
  // matched against the file's own text, which is what makes a renamed case fail
  // here rather than quietly leaving the exclusion backed by nothing.
  it('names a real case for every exclusion the walk cannot observe', () => {
    const cited = DOCUMENTED_EXCLUSIONS.filter(({ coveredBy }) => coveredBy !== undefined).map(
      ({ pattern, coveredBy }) => ({
        pattern: pattern.source,
        file: (/^[\w./-]+/.exec(coveredBy ?? '') ?? [''])[0],
        // Everything between the first pair of straight quotes, when there is
        // one. An entry that cites a file and no case (the legacy-layout
        // relocation, which is a whole suite rather than one case) is held to
        // the file alone.
        name: (/'([^']+)'/.exec(coveredBy ?? '') ?? [])[1],
      }),
    );

    const missing = cited
      .filter(({ file, name }) => {
        const url = new URL(`./${file.replace(/^test\//, '')}`, import.meta.url);
        if (!existsSync(url)) return true;
        return name !== undefined && !readFileSync(url, 'utf8').includes(name);
      })
      .map(({ pattern, file, name }) => `${pattern} -> ${file}${name ? ` :: '${name}'` : ''}`);

    expect(missing).toEqual([]);
  });

  it('gives every exclusion a reason', () => {
    for (const { pattern, reason } of DOCUMENTED_EXCLUSIONS) {
      expect(reason.length, pattern.source).toBeGreaterThan(20);
    }
  });
});
