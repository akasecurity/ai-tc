import { createHash, createHmac } from 'node:crypto';
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  dataDir,
  loadOrCreateFingerprintKey,
  type LocalDatabase,
  openLocalDatabase,
} from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import type { DetectionException } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { type ActionResult, addException } from '../../app/(app)/exceptions/actions.ts';

// `addException` is the ONLY web-ui code that handles a raw secret value. It
// must verify the ruleId exists in the installed snapshot, verify the value
// scan-matches that rule, require exactly one distinct span, reduce it to a
// masked preview + keyed-HMAC fingerprint, and discard the raw — never
// persisting it, never echoing it in an error. A bug here either creates a
// dangling grant or leaks the secret, so this suite pins BOTH properties on
// every branch. It mirrors cli/test/commands/exception.test.ts: a real
// node:sqlite store, a real fingerprint key file, no mocking of the store.
//
// The action resolves its store and key location from `homedir()` (never
// process.env), so the whole test is redirected into a temp home by mocking
// `node:os`; `next/cache` is stubbed because revalidatePath needs a Next render
// context that does not exist under vitest.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});
vi.mock('next/cache', () => ({ revalidatePath: () => undefined }));

// The test values come from the bundled rule's own `examples` fixture, so no
// secret-shaped literal lives in this file and the values stay in step with the
// rule definition (mirrors the CLI suite's rationale).
const RULE_ID = 'secrets/aws-access-key';
const PACK = bundledDetections().find((p) => p.rules.some((r) => r.id === RULE_ID));
const example = PACK?.rules.find((r) => r.id === RULE_ID)?.examples?.[0];
if (PACK === undefined || example === undefined) {
  throw new Error(`bundled rule ${RULE_ID} is missing from the pack registry or has no example`);
}
// The rule's own example — legitimately present in the seeded installed_packs
// snapshot, so it is used for grant-shape assertions, not for the at-rest scan.
const VALUE: string = example;
// A SECOND, distinct value matching the SAME rule (a different valid prefix from
// the pattern's alternation). It is NOT any rule's example, so its absence from
// the store on disk proves the raw was discarded, not merely never present.
const SECOND = `ASIA${VALUE.slice(4)}`;

// A third value for the no-scan-match path: still a live-credential shape — a
// real bundled rule fires on it, so echoing it back would be a real leak — but
// matching a DIFFERENT rule than RULE_ID, which is the mistake the branch
// exists for (picking the wrong rule from a dropdown of dozens). Built from
// `secrets/github-pat`'s own example with another valid prefix from that
// pattern's `gh[psou]_` alternation, exactly the way SECOND is built: it is
// therefore not itself any rule's example, and no contiguous secret-shaped
// literal lives in this file (the repo is developed with the plugin active, and
// such a literal would be redacted out of the test source).
const FOREIGN_RULE_ID = 'secrets/github-pat';
const foreignExample = bundledDetections()
  .flatMap((p) => p.rules)
  .find((r) => r.id === FOREIGN_RULE_ID)
  ?.examples?.find((e) => e.startsWith('ghp_'));
if (foreignExample === undefined) {
  throw new Error(`bundled rule ${FOREIGN_RULE_ID} is missing or has no classic-token example`);
}
const FOREIGN = `ghu_${foreignExample.slice(4)}`;

let home: string;
let dir: string;

// web-ui memoizes the open DB handle on globalThis (app/lib/db.ts). Close and
// drop it between tests so the next addException reopens against the fresh home.
function resetSingleton(): void {
  const store = globalThis as unknown as { __akaDb?: LocalDatabase };
  store.__akaDb?.close();
  delete store.__akaDb;
}

// Every grant ever written, including terminal rows — so a rejection that
// wrongly wrote a dangling grant is caught even if the grant is already expired.
async function grants(): Promise<DetectionException[]> {
  const db = openLocalDatabase(dir);
  try {
    return await db.exceptions.list({ includeTerminal: true });
  } finally {
    db.close();
  }
}

// The raw bytes of everything the store wrote: the main DB plus every other file
// in the data dir, so an at-rest leak is caught wherever it landed.
//
// Reading the DIRECTORY rather than a hardcoded name list is what makes this
// cover more than the `-wal`/`-shm` pair. SQLite writes an `aka.db-journal`
// instead wherever WAL silently no-ops — DrvFs `/mnt/c` and some network mounts,
// per `packages/persistence/src/paths.ts` — so on those setups a WAL-only scan
// reads files the data did not go to and reports clean. A migration
// (`aka.db.pre-drop.<ts>.bak`) and the foreign-lineage reset
// (`aka.db.legacy.<ts>.bak`) leave real copies in the same directory, and a
// future sidecar is covered here without an edit.
//
// The `aka.db` presence check is deliberately NOT lenient: if `dir` ever stops
// resolving to the real store (a layout change, a renamed file, a broken
// homedir() mock) the leak scan must fail loudly rather than return '' — an
// empty string contains no secret, so a swallowed error would turn every caller
// into a silent no-op.
function storeBytes(): string {
  const names = readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name);
  if (!names.includes('aka.db')) {
    throw new Error(`no aka.db under ${dir} — the at-rest scan is not reading the real store`);
  }
  const parts: Buffer[] = [];
  for (const name of names) {
    try {
      parts.push(readFileSync(join(dir, name)));
    } catch {
      // vanished between the listing and the read (an atomic write's per-process
      // `.tmp`) — nothing to fold in
    }
  }
  return Buffer.concat(parts).toString('latin1');
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-web-ex-'));
  osHome.dir = home;
  dir = dataDir();
  // Seed the installed ruleset the way the plugin/CLI do on open — addException
  // scans against this DB snapshot, not the engine's process-global registry.
  const db = openLocalDatabase(dir);
  try {
    db.installedPacks.recordInventory(bundledDetections());
  } finally {
    db.close();
  }
  resetSingleton();
});

afterEach(() => {
  resetSingleton();
  rmSync(home, { recursive: true, force: true });
});

describe('addException — the only web code touching a raw secret', () => {
  describe('input validation rejects before any grant is written', () => {
    // Each of the three below asserts the SPECIFIC error its own guard emits,
    // not merely that the call was rejected. Both inputs are also rejected
    // downstream — an empty reason fails `justification: z.string().min(1)` in
    // the schema, an empty value falls through to the no-scan-match guard — so
    // an outcome-only assertion stays green with the action's own guard deleted,
    // and the guard becomes load-bearing silently if that downstream constraint
    // is ever relaxed for an unrelated reason.
    it('rejects an empty reason — the reason is the audit trail', async () => {
      const res = await addException({
        ruleId: RULE_ID,
        value: VALUE,
        scope: 'once',
        reason: '   ',
      });
      expect(res.ok).toBe(false);
      // Deleting the guard yields the schema's 'Could not create the exception.'
      expect(res.error).toContain('A reason is required');
      expect(await grants()).toHaveLength(0);
    });

    it('rejects an empty value — nothing to except', async () => {
      const res = await addException({ ruleId: RULE_ID, value: '', scope: 'once', reason: 'x' });
      expect(res.ok).toBe(false);
      // Deleting the guard yields the no-scan-match error instead.
      expect(res.error).toContain('No value supplied');
      expect(await grants()).toHaveLength(0);
    });

    it('rejects a whitespace-only value — the empty guard is strict, the scan rejects the rest', async () => {
      // The empty-value guard is a strict `=== ''`, deliberately not trimmed (a
      // raw value is never mutated). A whitespace-only value therefore falls
      // through to the scan step, which matches nothing and rejects it — still
      // no grant. Pin that boundary so neither guard can silently soften: this
      // must be the SCAN's error, not the empty-value guard's.
      const res = await addException({ ruleId: RULE_ID, value: '   ', scope: 'once', reason: 'x' });
      expect(res.ok).toBe(false);
      expect(res.error).toContain(`does not match rule ${RULE_ID}`);
      expect(res.error).not.toContain('No value supplied');
      expect(await grants()).toHaveLength(0);
    });

    it('rejects an unresolvable scope without echoing the value', async () => {
      const res = await addException({
        ruleId: RULE_ID,
        value: VALUE,
        scope: 'forever',
        reason: 'x',
      });
      expect(res.ok).toBe(false);
      expect(res.error).not.toContain(VALUE);
      expect(await grants()).toHaveLength(0);
    });

    it('rejects an unknown ruleId (not in the installed ruleset)', async () => {
      const res = await addException({
        ruleId: 'nope/not-a-rule',
        value: VALUE,
        scope: 'once',
        reason: 'x',
      });
      expect(res.ok).toBe(false);
      expect(res.error).toContain('nope/not-a-rule');
      expect(res.error).not.toContain(VALUE);
      expect(await grants()).toHaveLength(0);
    });

    it('rejects a rule whose pack is disabled — the snapshot is the scan authority', async () => {
      const db = openLocalDatabase(dir);
      try {
        db.installedPacks.setEnabled(PACK.namespace, PACK.packId, false);
      } finally {
        db.close();
      }
      resetSingleton();

      const res = await addException({ ruleId: RULE_ID, value: VALUE, scope: 'once', reason: 'x' });
      expect(res.ok).toBe(false);
      // Rejected because the snapshot no longer lists the rule — not because
      // the value failed some later step. Reading the engine's process-global
      // registry instead would find the rule and mint a grant.
      expect(res.error).toContain(`Unknown or disabled rule '${RULE_ID}'`);
      expect(await grants()).toHaveLength(0);
    });

    it('rejects a secret-shaped value that does not scan-match the rule, without echoing it', async () => {
      // The realistic mistake: the user picks the wrong rule from a dropdown of
      // dozens for a value that IS a live credential. The rejection must name
      // the rule and never the value.
      //
      // FOREIGN is what makes this assertion able to fail. Driving the branch
      // with an obviously-inert literal and then asserting the error omits VALUE
      // and SECOND — module constants the call never passes in — cannot fail
      // however the error is worded; interpolating `input.value` into this
      // branch left the whole suite green. The subject here is the value
      // supplied on THIS call.
      const res = await addException({
        ruleId: RULE_ID,
        value: FOREIGN,
        scope: 'once',
        reason: 'x',
      });
      expect(res.ok).toBe(false);
      // Pins the branch: a match (or any other rejection) is worded differently,
      // so this also fails loudly if FOREIGN ever starts matching RULE_ID.
      expect(res.error).toContain(`does not match rule ${RULE_ID}`);
      expect(res.error).not.toContain(FOREIGN);
      expect(await grants()).toHaveLength(0);
    });

    it('rejects a value matching multiple distinct spans — supply exactly one', async () => {
      const res = await addException({
        ruleId: RULE_ID,
        value: `${VALUE} and ${SECOND}`,
        scope: 'once',
        reason: 'x',
      });
      expect(res.ok).toBe(false);
      // The count is safe to surface; the values themselves must not be.
      expect(res.error).not.toContain(VALUE);
      expect(res.error).not.toContain(SECOND);
      expect(await grants()).toHaveLength(0);
    });
  });

  describe('permanent scope re-checks the confirmation server-side', () => {
    it('rejects permanent scope when the confirmation is missing', async () => {
      const res = await addException({
        ruleId: RULE_ID,
        value: VALUE,
        scope: 'permanent',
        reason: 'x',
      });
      expect(res.ok).toBe(false);
      expect(await grants()).toHaveLength(0);
    });

    it('rejects permanent scope when confirmation !== value (not just the dialog)', async () => {
      const res = await addException({
        ruleId: RULE_ID,
        value: VALUE,
        scope: 'permanent',
        reason: 'x',
        confirmation: `${VALUE}-typo`,
      });
      expect(res.ok).toBe(false);
      expect(res.error).not.toContain(VALUE);
      expect(await grants()).toHaveLength(0);
    });

    it('accepts permanent scope when confirmation === value', async () => {
      const res = await addException({
        ruleId: RULE_ID,
        value: VALUE,
        scope: 'permanent',
        reason: 'deliberate',
        confirmation: VALUE,
      });
      expect(res).toEqual({ ok: true });
      const all = await grants();
      expect(all).toHaveLength(1);
      expect(all[0]?.scope).toBe('permanent');
      // A permanent grant has no expiry — it lives until explicitly revoked.
      expect(all[0]?.expiresAt).toBeNull();
    });
  });

  describe('a successful grant records only the derived, non-reversible fields', () => {
    it('creates a once grant: masked preview + keyed-HMAC fingerprint, raw discarded', async () => {
      const res = await addException({
        ruleId: RULE_ID,
        value: VALUE,
        scope: 'once',
        reason: 'rotating today',
      });
      expect(res).toEqual({ ok: true });

      const grant = (await grants())[0];
      expect(grant?.ruleId).toBe(RULE_ID);
      expect(grant?.category).toBe('secret');
      expect(grant?.scope).toBe('once');
      expect(grant?.maxUses).toBe(1);
      // A `once` grant carries the 30-minute backstop expiry so an unused grant
      // cannot dangle forever, even if nothing ever consumes it.
      expect(grant?.expiresAt).not.toBeNull();
      expect(grant?.createdVia).toBe('web-add');
      expect(grant?.justification).toBe('rotating today');
      // Nothing recoverable at rest: the preview is masked and no persisted
      // field carries the raw value.
      expect(grant?.maskedValue).not.toBe(VALUE);
      expect(JSON.stringify(grant)).not.toContain(VALUE);
    });

    it('binds the grant to the detected span, not the whole input', async () => {
      // The rule span (SECOND) is embedded in surrounding text; the grant must
      // bind to the detected span so it applies at enforcement time.
      const res = await addException({
        ruleId: RULE_ID,
        value: `key = ${SECOND} ;`,
        scope: 'once',
        reason: 'x',
      });
      expect(res).toEqual({ ok: true });

      const grant = (await grants())[0];
      const key = loadOrCreateFingerprintKey(dir);
      const spanFingerprint = createHmac('sha256', key.material)
        .update(SECOND, 'utf8')
        .digest('hex');
      expect(grant?.valueFingerprint).toBe(spanFingerprint);
    });

    it('lands in the active evaluation bundle under the current key — a real detection would match it', async () => {
      // The enforcement gateway ships exactly `activeBundleEntries(key.version)`
      // to the hook (plugin-runtime standalone-gateway); at evaluation a detected
      // value is fingerprinted under the same key and matched against those
      // entries. A grant present here, keyed to fingerprint(VALUE), is therefore
      // one a live detection of VALUE will actually downgrade — the "no dangling
      // grant" property at the web layer, against the very query enforcement
      // reads (the full processText loop is pinned by the CLI suite).
      const res = await addException({ ruleId: RULE_ID, value: VALUE, scope: '1h', reason: 'x' });
      expect(res).toEqual({ ok: true });

      const key = loadOrCreateFingerprintKey(dir);
      const wanted = createHmac('sha256', key.material).update(VALUE, 'utf8').digest('hex');
      const db = openLocalDatabase(dir);
      try {
        const bundle = await db.exceptions.activeBundleEntries(key.version);
        expect(bundle.some((e) => e.ruleId === RULE_ID && e.valueFingerprint === wanted)).toBe(
          true,
        );
      } finally {
        db.close();
      }
    });

    it('rejects a duplicate active grant with a friendly message, keeping one grant', async () => {
      const first = await addException({ ruleId: RULE_ID, value: VALUE, scope: '1h', reason: 'a' });
      expect(first).toEqual({ ok: true });

      const second = await addException({
        ruleId: RULE_ID,
        value: VALUE,
        scope: '1h',
        reason: 'b',
      });
      expect(second.ok).toBe(false);
      expect(second.error).toMatch(/already exists/i);
      expect(second.error).not.toContain(VALUE);
      expect(await grants()).toHaveLength(1);
    });
  });

  describe('the raw value never reaches the store', () => {
    it('persists only masked_value + a keyed HMAC, not a plain hash', async () => {
      const res = await addException({ ruleId: RULE_ID, value: VALUE, scope: 'once', reason: 'x' });
      expect(res).toEqual({ ok: true });

      const grant = (await grants())[0];
      const key = loadOrCreateFingerprintKey(dir);
      const keyed = createHmac('sha256', key.material).update(VALUE, 'utf8').digest('hex');
      const plain = createHash('sha256').update(VALUE, 'utf8').digest('hex');
      // Keyed so a stolen DB copy leaks nothing about low-entropy values; a
      // plain hash would be dictionary-attackable offline.
      expect(grant?.valueFingerprint).toBe(keyed);
      expect(grant?.valueFingerprint).not.toBe(plain);
    });

    // The two below self-test the leak scanner itself. Without them a reader
    // narrowed back to a hardcoded name list — or one that quietly swallowed a
    // missing store — would leave the leak assertions below green while checking
    // nothing, which is the failure mode they exist to prevent.
    it('reads every file in the data dir, not a hardcoded sidecar list', () => {
      // `aka.db-journal` is what SQLite writes instead of the `-wal`/`-shm` pair
      // in the rollback modes it falls back to where WAL silently no-ops, and a
      // `.bak` copy is left by a migration drop or the foreign-lineage reset.
      // On such a setup a WAL-only scan reports clean while the raw sits in a
      // file it never opened.
      const planted: Record<string, string> = {
        'aka.db-journal': 'rollback-journal-marker',
        'aka.db.pre-drop.1.bak': 'pre-drop-backup-marker',
        'aka.db.legacy.1.bak': 'foreign-lineage-backup-marker',
      };
      for (const [name, marker] of Object.entries(planted)) {
        writeFileSync(join(dir, name), marker);
      }
      const bytes = storeBytes();
      for (const marker of Object.values(planted)) expect(bytes).toContain(marker);
    });

    it('throws rather than reporting clean when the store is not where it expects', () => {
      // An empty read contains no secret, so a scanner that swallowed a missing
      // store would turn every `not.toContain` below into a silent pass.
      //
      // Repoint `dir` rather than moving `aka.db` aside: that is the real
      // failure shape (a layout change or a broken homedir() mock resolving
      // somewhere else), and it needs no rename — which Windows refuses while
      // any handle on the file is still open, and this suite is in the Windows
      // CI leg.
      const elsewhere = mkdtempSync(join(tmpdir(), 'aka-web-ex-empty-'));
      const real = dir;
      try {
        dir = elsewhere;
        expect(() => storeBytes()).toThrow(/aka\.db/);
      } finally {
        dir = real;
        rmSync(elsewhere, { recursive: true, force: true });
      }
    });

    it('leaves no trace of the raw value in the database file on disk', async () => {
      // Guard: SECOND is not any rule's example, so it is absent from the seeded
      // snapshot — its post-add absence proves addException discarded the raw,
      // not that it was never written.
      expect(storeBytes()).not.toContain(SECOND);

      const res = await addException({
        ruleId: RULE_ID,
        value: SECOND,
        scope: 'once',
        reason: 'x',
      });
      expect(res).toEqual({ ok: true });

      resetSingleton(); // close the handle so the WAL is checkpointed into the file

      // Positive control FIRST: the grant's fingerprint is stored as TEXT, so its
      // hex must appear in the bytes just read. This proves the scan below is
      // reading the actual store that received the write — without it, a reader
      // that came back empty would satisfy `not.toContain` while proving nothing.
      const fingerprint = (await grants())[0]?.valueFingerprint;
      expect(fingerprint).toBeDefined();
      expect(storeBytes()).toContain(fingerprint);
      expect(storeBytes()).not.toContain(SECOND);
    });

    it('locks the minted exception.key to 0600 — it is what keeps the fingerprints non-reversible', async () => {
      const res = await addException({ ruleId: RULE_ID, value: VALUE, scope: 'once', reason: 'x' });
      expect(res).toEqual({ ok: true });
      // The add path mints the fingerprint key on first use. A looser mode would
      // let another local account read the key and reverse the stored HMACs, so
      // pin 0600 (POSIX only — Windows ACLs do not carry these mode bits).
      if (process.platform !== 'win32') {
        expect(statSync(join(dir, 'exception.key')).mode & 0o777).toBe(0o600);
      }
    });
  });

  describe('failure is secure', () => {
    it('a corrupt exception.key yields recovery guidance and no grant', async () => {
      writeFileSync(join(dir, 'exception.key'), 'this is not a valid key file\n');

      const res = await addException({ ruleId: RULE_ID, value: VALUE, scope: 'once', reason: 'x' });
      expect(res.ok).toBe(false);
      expect(res.error).toContain('exception.key'); // recovery guidance, not a stack trace
      expect(res.error).not.toContain(VALUE); // fails secure without echoing the secret
      expect(await grants()).toHaveLength(0);
    });
  });

  describe('no rejection path echoes the raw value (the exemplary property)', () => {
    it('omits every raw value from every rejection error', async () => {
      const errors: string[] = [];
      // `supplied` is what THIS call passed in — the only values that call could
      // possibly echo. Asserting a branch only against module constants it never
      // received passes however the error is worded, which is exactly how the
      // no-scan-match echo went unnoticed here; every case names its own inputs.
      const record = (r: ActionResult, ...supplied: string[]): void => {
        expect(r.ok).toBe(false);
        expect(r.error).toBeDefined();
        const error = r.error ?? '';
        for (const value of supplied) expect(error).not.toContain(value);
        errors.push(error);
      };

      record(
        await addException({
          ruleId: RULE_ID,
          value: FOREIGN,
          scope: 'once',
          reason: 'x',
        }),
        FOREIGN,
      );
      record(
        await addException({
          ruleId: RULE_ID,
          value: `${VALUE} and ${SECOND}`,
          scope: 'once',
          reason: 'x',
        }),
        VALUE,
        SECOND,
      );
      record(
        await addException({
          ruleId: RULE_ID,
          value: VALUE,
          scope: 'permanent',
          reason: 'x',
          confirmation: 'wrong',
        }),
        VALUE,
      );

      // Duplicate: create one, then collide.
      const created = await addException({
        ruleId: RULE_ID,
        value: VALUE,
        scope: '1h',
        reason: 'x',
      });
      expect(created).toEqual({ ok: true });
      record(
        await addException({ ruleId: RULE_ID, value: VALUE, scope: '1h', reason: 'x' }),
        VALUE,
      );

      // Corrupt key (isolated to the end so it cannot poison the cases above).
      writeFileSync(join(dir, 'exception.key'), 'corrupt\n');
      resetSingleton();
      record(
        await addException({ ruleId: RULE_ID, value: SECOND, scope: 'once', reason: 'x' }),
        SECOND,
      );

      expect(errors).toHaveLength(5);
      // Cross-check: no error carries any raw value, whichever call produced it.
      for (const err of errors) {
        for (const value of [VALUE, SECOND, FOREIGN]) expect(err).not.toContain(value);
      }
    });
  });
});
