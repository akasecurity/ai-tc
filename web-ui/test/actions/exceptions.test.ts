import { createHash, createHmac } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { BLOCKED_WINDOW_MS, BLOCKED_WINDOWS, ROTATE_CONFIRMATION } from '@akasecurity/dashboard-ui';
import { maskMatch } from '@akasecurity/detections';
import {
  BLOCKED_DETECTIONS_RETENTION_MS,
  dataDir,
  fingerprintValue,
  loadOrCreateFingerprintKey,
  type LocalDatabase,
  openLocalDatabase,
  readFingerprintKey,
} from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import type { BlockedDetectionInput, DetectionException } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  type ActionResult,
  addException,
  approveBlocked,
  rotateKey,
} from '../../app/(app)/exceptions/actions.ts';

// The three exception-granting Server Actions, each covered against a real
// node:sqlite store and a real fingerprint key file — no mocking of either
// (the repository's house style; mirrors cli/test/commands/exception.test.ts):
//
//   addException   — the ONLY web-ui code that handles a raw secret value. It
//                    must verify the ruleId exists in the installed snapshot,
//                    verify the value scan-matches that rule, require exactly
//                    one distinct span, reduce it to a masked preview +
//                    keyed-HMAC fingerprint, and discard the raw — never
//                    persisting it, never echoing it in an error. A bug here
//                    either creates a dangling grant or leaks the secret, so
//                    that suite pins BOTH properties on every branch.
//   approveBlocked — grants from a ledger row, so no raw value is in play; the
//                    gates are the server-side permanent-scope confirmation
//                    and the lookup window.
//   rotateKey      — INVALIDATES every existing grant, behind a single string
//                    compare. The dialog gate is a convenience; this compare is
//                    the control, so the suite pins both what it accepts and
//                    that everything else leaves the key untouched.
//
// The actions resolve their store and key location from `homedir()` (never
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
// A THIRD value whose MASKED preview differs from the other two. maskMatch
// keeps only the first and last character of a generic secret, so SECOND — which
// changes only the prefix — previews identically to VALUE; a test that needs two
// distinguishable previews has to change an end.
const THIRD = `ASIA${VALUE.slice(4, -1)}${VALUE.endsWith('Z') ? 'Y' : 'Z'}`;

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

// The raw bytes of the store on disk (main DB + WAL/SHM sidecars), so an
// at-rest leak is caught even if it only ever reached the write-ahead log.
//
// The main DB read is deliberately NOT guarded: if `dir` ever stops resolving to
// the real store (a layout change, a renamed file, a broken homedir() mock) the
// leak scan must fail loudly rather than return '' — an empty string contains no
// secret, so a swallowed error would turn every caller into a silent no-op. Only
// the two sidecars are optional; SQLite may not have created them yet.
function storeBytes(): string {
  const parts: Buffer[] = [readFileSync(join(dir, 'aka.db'))];
  for (const name of ['aka.db-wal', 'aka.db-shm']) {
    try {
      parts.push(readFileSync(join(dir, name)));
    } catch {
      // sidecar absent — nothing to fold in
    }
  }
  return Buffer.concat(parts).toString('latin1');
}

function keyFile(): string {
  return join(dir, 'exception.key');
}

// The key file verbatim. Rejection paths assert the BYTES, not just the
// version: a rotation that minted fresh material while keeping the version
// would orphan every grant just as thoroughly, and read as unchanged.
function keyBytes(): string {
  return readFileSync(keyFile(), 'utf8');
}

// One blocked-ledger row shaped exactly as the hook writes it: the keyed
// fingerprint and masked preview of the detected value under the CURRENT key,
// and never the value itself.
const REFERENCE = 'blk-0001';

function ledgerEntry(overrides: Partial<BlockedDetectionInput> = {}): BlockedDetectionInput {
  const key = loadOrCreateFingerprintKey(dir);
  return {
    reference: REFERENCE,
    ruleId: RULE_ID,
    category: 'secret',
    valueFingerprint: fingerprintValue(key, VALUE),
    keyVersion: key.version,
    maskedValue: maskMatch(VALUE),
    sessionId: null,
    repo: null,
    ...overrides,
  };
}

// Write a ledger row through the real repository, optionally back-dated.
// `blocked_at` is stamped inside the write from `Date.now()` and
// exceptions.ts takes no injectable clock, so moving the clock across that one
// call is the only seam — which keeps the row shape in step with
// `recordBlocked` instead of hand-rolling its SQL. The handle is opened BEFORE
// the clock moves so migrations and default seeding still stamp real times.
async function seedBlocked(entry: BlockedDetectionInput, agedMs = 0): Promise<void> {
  const at = Date.now() - agedMs;
  const store = openLocalDatabase(dir);
  const clock = vi.spyOn(Date, 'now').mockReturnValue(at);
  try {
    await store.exceptions.recordBlocked(entry);
  } finally {
    clock.mockRestore();
    store.close();
  }
}

// The ledger as the page's "Recently blocked" banner queries it.
async function blockedWithin(windowMs: number): Promise<string[]> {
  const store = openLocalDatabase(dir);
  try {
    return (await store.exceptions.recentBlocked(windowMs)).map((b) => b.reference);
  } finally {
    store.close();
  }
}

// The grants a live detection would actually be matched against: the
// evaluation bundle under one key version (what plugin-runtime ships to the
// hook). "No longer matches" means absent from here, not deleted.
async function bundleIds(keyVersion: number): Promise<string[]> {
  const store = openLocalDatabase(dir);
  try {
    return (await store.exceptions.activeBundleEntries(keyVersion)).map((e) => e.id);
  } finally {
    store.close();
  }
}

// Server Action arguments arrive as untrusted JSON over an HTTP POST — the
// `string` in each signature is a compile-time claim the runtime never checks.
// Call through widened aliases so the tests can drive the boundary as it
// actually exists.
const rotateKeyRaw = rotateKey as unknown as (confirmation: unknown) => Promise<ActionResult>;
const approveBlockedRaw = approveBlocked as unknown as (input: {
  reference: string;
  scope: string;
  reason: string;
  confirmation?: unknown;
}) => Promise<ActionResult>;

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
    it('rejects an empty reason — the reason is the audit trail', async () => {
      const res = await addException({
        ruleId: RULE_ID,
        value: VALUE,
        scope: 'once',
        reason: '   ',
      });
      expect(res.ok).toBe(false);
      expect(await grants()).toHaveLength(0);
    });

    it('rejects an empty value — nothing to except', async () => {
      const res = await addException({ ruleId: RULE_ID, value: '', scope: 'once', reason: 'x' });
      expect(res.ok).toBe(false);
      expect(await grants()).toHaveLength(0);
    });

    it('rejects a whitespace-only value — the empty guard is strict, the scan rejects the rest', async () => {
      // The empty-value guard is a strict `=== ''`, deliberately not trimmed (a
      // raw value is never mutated). A whitespace-only value therefore falls
      // through to the scan step, which matches nothing and rejects it — still
      // no grant. Pin that boundary so neither guard can silently soften.
      const res = await addException({ ruleId: RULE_ID, value: '   ', scope: 'once', reason: 'x' });
      expect(res.ok).toBe(false);
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
      expect(await grants()).toHaveLength(0);
    });

    it('rejects a value that does not scan-match the rule — no dangling grant', async () => {
      const res = await addException({
        ruleId: RULE_ID,
        value: 'not-a-credential',
        scope: 'once',
        reason: 'x',
      });
      expect(res.ok).toBe(false);
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
      const record = (r: ActionResult): void => {
        expect(r.ok).toBe(false);
        if (r.error !== undefined) errors.push(r.error);
      };

      record(
        await addException({
          ruleId: RULE_ID,
          value: 'not-a-credential',
          scope: 'once',
          reason: 'x',
        }),
      );
      record(
        await addException({
          ruleId: RULE_ID,
          value: `${VALUE} and ${SECOND}`,
          scope: 'once',
          reason: 'x',
        }),
      );
      record(
        await addException({
          ruleId: RULE_ID,
          value: VALUE,
          scope: 'permanent',
          reason: 'x',
          confirmation: 'wrong',
        }),
      );

      // Duplicate: create one, then collide.
      const created = await addException({
        ruleId: RULE_ID,
        value: VALUE,
        scope: '1h',
        reason: 'x',
      });
      expect(created).toEqual({ ok: true });
      record(await addException({ ruleId: RULE_ID, value: VALUE, scope: '1h', reason: 'x' }));

      // Corrupt key (isolated to the end so it cannot poison the cases above).
      writeFileSync(join(dir, 'exception.key'), 'corrupt\n');
      resetSingleton();
      record(await addException({ ruleId: RULE_ID, value: SECOND, scope: 'once', reason: 'x' }));

      expect(errors).toHaveLength(5);
      for (const err of errors) {
        expect(err).not.toContain(VALUE);
        expect(err).not.toContain(SECOND);
      }
    });
  });
});

describe('rotateKey — one string compare from invalidating every grant', () => {
  // A grant under the current key, created through the real add path, so the
  // "stops matching" assertions run against a grant a live detection would
  // genuinely have matched a moment earlier.
  async function grantUnderCurrentKey(): Promise<{ id: string; keyVersion: number }> {
    const res = await addException({ ruleId: RULE_ID, value: VALUE, scope: '1h', reason: 'x' });
    expect(res).toEqual({ ok: true });
    const grant = (await grants())[0];
    expect(grant).toBeDefined();
    return { id: grant?.id ?? '', keyVersion: grant?.keyVersion ?? 0 };
  }

  describe('the gate rejects everything that is not the exact token', () => {
    // The compare is a strict `!==` against the literal — no trim, no
    // case-fold, no coercion. Each of these routes to loopback of the intent
    // ("the user meant rotate") but is NOT the token, and pinning them stops a
    // future "helpful" normalisation from widening a one-click destructive gate.
    const NEAR_MISSES = ['', 'Rotate', 'ROTATE', ' rotate', 'rotate ', 'rotate\n', 'rotate-key'];

    it.each(NEAR_MISSES)('rejects %j and leaves the key byte-identical', async (confirmation) => {
      const { id, keyVersion } = await grantUnderCurrentKey();
      const before = keyBytes();

      const res = await rotateKey(confirmation);
      expect(res.ok).toBe(false);
      expect(res.error).toBe('Type "rotate" to confirm.');

      expect(keyBytes()).toBe(before);
      expect(readFingerprintKey(dir)?.version).toBe(keyVersion);
      // The grant is untouched — still the one enforcement would match.
      expect(await bundleIds(keyVersion)).toContain(id);
    });

    // Server Actions are an RPC boundary: the argument is whatever JSON the
    // caller posted. A `!==` against a string rejects every non-string,
    // including an object whose `toString()` would produce the token — pin
    // that, because a switch to `==` or `String(x) ===` would accept them.
    const NON_STRINGS: [string, unknown][] = [
      ['undefined', undefined],
      ['null', null],
      ['an array', ['rotate']],
      ['an object', {}],
      ['a stringifiable object', { toString: () => 'rotate' }],
      ['a number', 1],
      ['true', true],
    ];

    it.each(NON_STRINGS)('rejects %s arriving over the wire', async (_label, confirmation) => {
      loadOrCreateFingerprintKey(dir); // a key to leave unchanged
      const before = keyBytes();
      const res = await rotateKeyRaw(confirmation);
      expect(res.ok).toBe(false);
      expect(keyBytes()).toBe(before);
    });

    it('mints nothing when there is no key file yet', async () => {
      // A rejected rotation must be totally inert. Minting here would be worse
      // than a no-op: enforcement would start fingerprinting under a key that
      // the ledger's pending rows were never written against.
      expect(readFingerprintKey(dir)).toBeNull();
      expect((await rotateKey('nope')).ok).toBe(false);
      expect(readFingerprintKey(dir)).toBeNull();
    });

    it('accepts exactly the token the dialog makes the user type', async () => {
      // The action hard-codes the literal and the dialog exports its own
      // constant. If either moves, rotation silently stops working (fail
      // closed, but broken) — so pin the two together, through the action.
      expect(ROTATE_CONFIRMATION).toBe('rotate');
      loadOrCreateFingerprintKey(dir);
      expect(await rotateKey(ROTATE_CONFIRMATION)).toEqual({ ok: true });
    });
  });

  describe('rotation is invalidation, not deletion', () => {
    it('bumps the version and mints fresh material', async () => {
      const before = readFingerprintKey(dir);
      expect(before).toBeNull(); // no key until something needs one
      const v1 = loadOrCreateFingerprintKey(dir);

      const res = await rotateKey(ROTATE_CONFIRMATION);
      expect(res).toEqual({ ok: true });

      const v2 = readFingerprintKey(dir);
      expect(v2?.version).toBe(v1.version + 1);
      expect(v2?.material.equals(v1.material)).toBe(false);
    });

    it('leaves old grants listed and unrevoked — they are audit evidence', async () => {
      const { id, keyVersion } = await grantUnderCurrentKey();

      expect(await rotateKey(ROTATE_CONFIRMATION)).toEqual({ ok: true });
      resetSingleton();

      const all = await grants();
      expect(all).toHaveLength(1);
      expect(all[0]?.id).toBe(id);
      // NOT revoked and NOT expired: nothing about the row changed. It went
      // inert purely because the key it was written under is no longer the one
      // enforcement uses.
      expect(all[0]?.revokedAt).toBeNull();
      expect(all[0]?.keyVersion).toBe(keyVersion);
    });

    it('drops old grants out of the bundle enforcement actually reads', async () => {
      const { id, keyVersion } = await grantUnderCurrentKey();
      expect(await bundleIds(keyVersion)).toContain(id);

      expect(await rotateKey(ROTATE_CONFIRMATION)).toEqual({ ok: true });
      resetSingleton();

      const rotated = readFingerprintKey(dir)?.version;
      expect(rotated).toBe(keyVersion + 1);
      // The bundle is queried under the current version, and the grant is not
      // in it — a live detection of VALUE would now be enforced, not excepted.
      expect(await bundleIds(rotated ?? 0)).not.toContain(id);
      // Still reachable under the old version: partitioned by key, not deleted.
      expect(await bundleIds(keyVersion)).toContain(id);
    });

    it('makes the same value grantable again — the documented recovery path', async () => {
      await grantUnderCurrentKey();
      expect(await rotateKey(ROTATE_CONFIRMATION)).toEqual({ ok: true });
      resetSingleton();

      // Re-granting the SAME value must not collide with the orphaned grant:
      // the fingerprint changed with the key, so the one-active-grant-per
      // (rule, fingerprint, keyVersion) index sees a different slot. This is
      // what "re-approve deliberately where still needed" depends on.
      const again = await addException({
        ruleId: RULE_ID,
        value: VALUE,
        scope: '1h',
        reason: 'still needed',
      });
      expect(again).toEqual({ ok: true });

      const key = loadOrCreateFingerprintKey(dir);
      const wanted = createHmac('sha256', key.material).update(VALUE, 'utf8').digest('hex');
      const store = openLocalDatabase(dir);
      try {
        const bundle = await store.exceptions.activeBundleEntries(key.version);
        expect(bundle.some((e) => e.valueFingerprint === wanted)).toBe(true);
      } finally {
        store.close();
      }
    });
  });

  describe('failure is secure', () => {
    it('refuses to rotate over a corrupt key and leaves the file alone', async () => {
      // The old version is unknowable, so minting a replacement could reuse a
      // version and collide new grants with orphaned ones. Rotation must fail
      // rather than guess — and must not consume the evidence on the way out.
      writeFileSync(keyFile(), 'this is not a valid key file\n');
      const before = keyBytes();

      const res = await rotateKey(ROTATE_CONFIRMATION);
      expect(res.ok).toBe(false);
      expect(res.error).toContain('exception.key'); // recovery guidance, not a stack trace
      expect(keyBytes()).toBe(before);
    });

    it('checks the confirmation before it ever touches the key file', async () => {
      writeFileSync(keyFile(), 'corrupt\n');
      const res = await rotateKey('nope');
      // The cheap, total gate runs first: a wrong confirmation reports the
      // confirmation problem, never the store's state.
      expect(res.error).toBe('Type "rotate" to confirm.');
    });
  });
});

describe('approveBlocked — granting from the ledger, no value in play', () => {
  beforeEach(async () => {
    await seedBlocked(ledgerEntry());
    resetSingleton();
  });

  // The preview the dialog shows and the confirmation box asks for.
  const MASKED = maskMatch(VALUE);

  describe('input validation rejects before any grant is written', () => {
    it('rejects an empty reason — the reason is the audit trail', async () => {
      const res = await approveBlocked({ reference: REFERENCE, scope: 'once', reason: '   ' });
      expect(res.ok).toBe(false);
      expect(await grants()).toHaveLength(0);
    });

    it('rejects an unresolvable scope', async () => {
      const res = await approveBlocked({ reference: REFERENCE, scope: 'forever', reason: 'x' });
      expect(res.ok).toBe(false);
      expect(await grants()).toHaveLength(0);
    });

    it('rejects an unknown reference with the ledger message, not a crash', async () => {
      const res = await approveBlocked({ reference: 'blk-nope', scope: 'once', reason: 'x' });
      expect(res.ok).toBe(false);
      expect(res.error).toMatch(/expired from the ledger/i);
      expect(await grants()).toHaveLength(0);
    });
  });

  describe('permanent scope re-checks the confirmation server-side', () => {
    it('rejects permanent scope when the confirmation is missing', async () => {
      const res = await approveBlocked({ reference: REFERENCE, scope: 'permanent', reason: 'x' });
      expect(res.ok).toBe(false);
      expect(await grants()).toHaveLength(0);
    });

    it('rejects permanent scope when the confirmation is wrong', async () => {
      const res = await approveBlocked({
        reference: REFERENCE,
        scope: 'permanent',
        reason: 'x',
        confirmation: `${MASKED}x`,
      });
      expect(res.ok).toBe(false);
      expect(await grants()).toHaveLength(0);
    });

    it('rejects the RAW value as the confirmation — the masked preview is what is asked for', async () => {
      const res = await approveBlocked({
        reference: REFERENCE,
        scope: 'permanent',
        reason: 'x',
        confirmation: VALUE,
      });
      expect(res.ok).toBe(false);
      expect(res.error).not.toContain(VALUE);
      expect(await grants()).toHaveLength(0);
    });

    it('rejects another entry’s masked value — the compare uses the looked-up row', async () => {
      // The caller controls `reference` and `confirmation` independently. The
      // masked value on the RIGHT of the compare is read from the store, so a
      // payload cannot bring its own matching pair.
      const key = loadOrCreateFingerprintKey(dir);
      const other = maskMatch(THIRD);
      expect(other).not.toBe(MASKED); // the case is only meaningful if they differ
      await seedBlocked({
        ...ledgerEntry(),
        reference: 'blk-0002',
        valueFingerprint: fingerprintValue(key, THIRD),
        maskedValue: other,
      });
      resetSingleton();

      const res = await approveBlocked({
        reference: REFERENCE,
        scope: 'permanent',
        reason: 'x',
        confirmation: other,
      });
      expect(res.ok).toBe(false);
      expect(await grants()).toHaveLength(0);
    });

    it('is a deliberateness gate, not proof of knowledge', () => {
      // The dialog displays the masked preview immediately above the box that
      // asks for it, and maskMatch reveals only the first and last character —
      // so distinct values routinely share a preview. The control makes a
      // permanent grant a deliberate act; it is not, and cannot be, evidence
      // that the operator knows the value. Pin the collision so the gate is not
      // mistaken for the stronger property.
      expect(SECOND).not.toBe(VALUE);
      expect(maskMatch(SECOND)).toBe(maskMatch(VALUE));
    });

    const NON_STRINGS: [string, unknown][] = [
      ['null', null],
      ['an object', {}],
      ['a stringifiable object', { toString: () => 'x' }],
    ];

    it.each(NON_STRINGS)('rejects %s arriving over the wire', async (_label, confirmation) => {
      const res = await approveBlockedRaw({
        reference: REFERENCE,
        scope: 'permanent',
        reason: 'x',
        confirmation,
      });
      expect(res.ok).toBe(false);
      expect(await grants()).toHaveLength(0);
    });

    it('accepts permanent scope when the confirmation matches exactly', async () => {
      const res = await approveBlocked({
        reference: REFERENCE,
        scope: 'permanent',
        reason: 'deliberate',
        confirmation: MASKED,
      });
      expect(res).toEqual({ ok: true });

      const all = await grants();
      expect(all).toHaveLength(1);
      expect(all[0]?.scope).toBe('permanent');
      expect(all[0]?.expiresAt).toBeNull();
    });

    it('gates ONLY permanent scope — a temporary grant ignores the confirmation', async () => {
      // Pin the exact boundary in both directions: widening the gate to every
      // scope would be a UX regression, narrowing it away from permanent would
      // be a security one.
      const res = await approveBlocked({
        reference: REFERENCE,
        scope: '1h',
        reason: 'x',
        confirmation: 'not the masked value',
      });
      expect(res).toEqual({ ok: true });
      expect((await grants())[0]?.scope).toBe('temporary');
    });
  });

  describe('the lookup window is the retention window, not the UI filter', () => {
    it('approves a row no blocked-window chip except the widest can show', async () => {
      // 12h: past the page's default chip and every narrower one, well inside
      // the 24h retention the ledger actually keeps. If the action reused the
      // chip the user happens to be on — or `recentBlocked`'s 30-minute default
      // — a row visible on the page would be unapprovable.
      const AGED_MS = 12 * 60 * 60 * 1000;
      await seedBlocked({ ...ledgerEntry(), reference: 'blk-aged' }, AGED_MS);
      resetSingleton();

      for (const chip of BLOCKED_WINDOWS) {
        const span = BLOCKED_WINDOW_MS[chip.value];
        expect(await blockedWithin(span), `chip ${chip.value}`).toSatisfy((refs: string[]) =>
          span > AGED_MS ? refs.includes('blk-aged') : !refs.includes('blk-aged'),
        );
      }
      resetSingleton();

      const res = await approveBlocked({ reference: 'blk-aged', scope: '1h', reason: 'x' });
      expect(res).toEqual({ ok: true });
      expect(await grants()).toHaveLength(1);
    });

    it('refuses a row past retention — the ledger is short-lived by design', async () => {
      await seedBlocked(
        { ...ledgerEntry(), reference: 'blk-old' },
        BLOCKED_DETECTIONS_RETENTION_MS + 60_000,
      );
      resetSingleton();

      const res = await approveBlocked({ reference: 'blk-old', scope: 'once', reason: 'x' });
      expect(res.ok).toBe(false);
      expect(res.error).toMatch(/expired from the ledger/i);
      expect(await grants()).toHaveLength(0);
    });
  });

  describe('a rotated key makes a ledger row unapprovable', () => {
    it('refuses a row fingerprinted under the previous key version', async () => {
      // The ledger (24h) outlives a rotation, so the page keeps offering
      // "Approve" on rows whose fingerprint was computed under the old key.
      // Granting from one would write a row that is inert the moment it is
      // created: enforcement fingerprints under the current key and queries the
      // bundle by that version. Reject instead of reporting success.
      expect(await rotateKey(ROTATE_CONFIRMATION)).toEqual({ ok: true });
      resetSingleton();

      const res = await approveBlocked({ reference: REFERENCE, scope: '1h', reason: 'x' });
      expect(res.ok).toBe(false);
      expect(res.error).toMatch(/could never match/i);
      expect(await grants()).toHaveLength(0);
    });

    it('refuses when the key file is missing entirely', async () => {
      // A deleted key is version-indistinguishable from the one the row was
      // written under, but the material is gone, so the fingerprint can never
      // be reproduced. Absence is rejected on its own terms.
      unlinkSync(keyFile());
      resetSingleton();

      const res = await approveBlocked({ reference: REFERENCE, scope: '1h', reason: 'x' });
      expect(res.ok).toBe(false);
      expect(res.error).toMatch(/missing/i);
      expect(await grants()).toHaveLength(0);
      // Rejecting must not mint a replacement key as a side effect — that would
      // orphan every existing grant to answer a read.
      expect(readFingerprintKey(dir)).toBeNull();
    });

    it('surfaces recovery guidance for a corrupt key instead of crashing', async () => {
      writeFileSync(keyFile(), 'this is not a valid key file\n');
      resetSingleton();

      const res = await approveBlocked({ reference: REFERENCE, scope: '1h', reason: 'x' });
      expect(res.ok).toBe(false);
      expect(res.error).toContain('exception.key');
      expect(await grants()).toHaveLength(0);
    });
  });

  describe('a successful grant copies the ledger row and nothing else', () => {
    it('binds to the stored fingerprint — the value never enters this action', async () => {
      const entry = ledgerEntry();
      const res = await approveBlocked({
        reference: REFERENCE,
        scope: '1h',
        reason: '  rotating tomorrow  ',
      });
      expect(res).toEqual({ ok: true });

      const grant = (await grants())[0];
      expect(grant?.ruleId).toBe(entry.ruleId);
      expect(grant?.category).toBe(entry.category);
      expect(grant?.valueFingerprint).toBe(entry.valueFingerprint);
      expect(grant?.keyVersion).toBe(entry.keyVersion);
      expect(grant?.maskedValue).toBe(entry.maskedValue);
      expect(grant?.createdVia).toBe('web-approve');
      expect(grant?.justification).toBe('rotating tomorrow');
      expect(JSON.stringify(grant)).not.toContain(VALUE);
    });

    it('lands in the active evaluation bundle — a real detection would match it', async () => {
      const res = await approveBlocked({ reference: REFERENCE, scope: '1h', reason: 'x' });
      expect(res).toEqual({ ok: true });

      const key = loadOrCreateFingerprintKey(dir);
      const wanted = fingerprintValue(key, VALUE);
      const store = openLocalDatabase(dir);
      try {
        const bundle = await store.exceptions.activeBundleEntries(key.version);
        expect(bundle.some((e) => e.ruleId === RULE_ID && e.valueFingerprint === wanted)).toBe(
          true,
        );
      } finally {
        store.close();
      }
    });

    it('rejects a second approve of the same row with a friendly message, keeping one grant', async () => {
      // Double-submit, or approving the same value from two ledger rows: the
      // repository throws DuplicateActiveExceptionError, and the action must
      // turn that into guidance rather than let it reach the client as a crash.
      expect(await approveBlocked({ reference: REFERENCE, scope: '1h', reason: 'a' })).toEqual({
        ok: true,
      });

      const second = await approveBlocked({ reference: REFERENCE, scope: '1h', reason: 'b' });
      expect(second.ok).toBe(false);
      expect(second.error).toMatch(/already exists/i);
      expect(second.error).not.toMatch(/duplicate-active-exception/);
      expect(await grants()).toHaveLength(1);
    });
  });
});
