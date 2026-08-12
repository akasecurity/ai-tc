import { createHash, createHmac } from 'node:crypto';
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  BLOCKED_WINDOW_MS,
  BLOCKED_WINDOWS,
  LEDGER_WINDOW_HOURS,
  ROTATE_CONFIRMATION,
  rotationBlockedLedgerNote,
} from '@akasecurity/dashboard-ui';
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
import { DetectionCategory, PointerToken } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  type ActionResult,
  addException,
  approveBlocked,
  grantRevealFromPointer,
  type RevealGrantResult,
  revokeException,
  rotateKey,
} from '../../app/(app)/exceptions/actions.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';
import { expectNoRejection } from '../helpers/no-throw.ts';
import { removeTree } from '../helpers/remove-tree.ts';
import { storeBytes } from '../helpers/store-bytes.ts';

// Every mutating Server Action on the exceptions surface, each covered against a
// real node:sqlite store and a real fingerprint key file — no mocking of either
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
//                    gates are the server-side permanent-scope confirmation,
//                    the lookup window, and the key-version check.
//   rotateKey      — INVALIDATES every existing grant, behind a single string
//                    compare. The dialog gate is a convenience; this compare is
//                    the control, so the suite pins both what it accepts and
//                    that everything else leaves the key untouched.
//   revokeException — the one that takes a bypass AWAY, so its failure mode is
//                    the opposite of the others: a grant that quietly stays
//                    active. Whether that happens is decided by a single
//                    boolean, so the suite pins that a true means the grant
//                    really left the evaluation bundle, and that every false
//                    is a refusal the caller can act on rather than a crash.
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
// A value whose MASKED preview differs from the other two. maskMatch keeps only
// the first and last character of a generic secret, so SECOND — which changes
// only the prefix — previews identically to VALUE; the approveBlocked
// confirmation tests need two distinguishable previews, so this one changes an
// end. Same rule as VALUE, unlike FOREIGN below.
const THIRD = `ASIA${VALUE.slice(4, -1)}${VALUE.endsWith('Z') ? 'Y' : 'Z'}`;

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

// expectNoEchoOf now lives in test/helpers/no-echo.ts with its own suite. It was
// inline here, which meant its run length could be widened back with nothing
// going red — every test in this file passed with ECHO_RUN set to 64. It applies
// to ERRORS here, where no part of the value has any business appearing; the
// at-rest and grant-shape assertions stay whole-value (`not.toContain`) because
// `maskMatch` deliberately keeps a fragment visible, and that fragment IS the
// masked preview, stored on purpose.

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
//
// Widening is PER-PARAMETER, not per-action: an alias that widens
// `confirmation` and leaves `reason` at `string` covers the boundary for one
// field and reads as covering the action. So each alias below widens every
// field, and the whole input is widened to `unknown` as well — a payload that
// is not an object at all is a shape no per-field alias can express, and it is
// the one that fails before any field is read.
const rotateKeyRaw = rotateKey as unknown as (confirmation: unknown) => Promise<ActionResult>;
const approveBlockedRaw = approveBlocked as unknown as (input: unknown) => Promise<ActionResult>;
// The confirmation blocks below are the exception to that rule, and deliberately
// keep a NAMED shape: they drive one field across the boundary and depend on
// every other arriving well-formed. Widened to `unknown` they would still pass
// after `reference` was renamed — the payload would fail on a missing field
// instead of reaching the confirmation gate, and `ok: false` plus zero grants
// reads the same either way. Widen the field under test, not its siblings.
const approveBlockedConfirmationRaw = approveBlocked as unknown as (input: {
  reference: string;
  scope: string;
  reason: string;
  confirmation?: unknown;
}) => Promise<ActionResult>;
const addExceptionRaw = addException as unknown as (input: unknown) => Promise<ActionResult>;
const revokeExceptionRaw = revokeException as unknown as (
  id: unknown,
  reason: unknown,
) => Promise<ActionResult>;
const grantRevealFromPointerRaw = grantRevealFromPointer as unknown as (
  input: unknown,
) => Promise<RevealGrantResult>;
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
  removeTree(home);
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
      expectNoEchoOf(res.error, VALUE);
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
      expectNoEchoOf(res.error, VALUE);
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
      // supplied on THIS call, and it is checked run by run: echoing a
      // TRUNCATED value would still hand back a live credential's prefix.
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
      expectNoEchoOf(res.error, FOREIGN);
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
      expectNoEchoOf(res.error, VALUE);
      expectNoEchoOf(res.error, SECOND);
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
      expectNoEchoOf(res.error, VALUE);
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
      expectNoEchoOf(second.error, VALUE);
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

    // `storeBytes` reads every file in the data dir, and is itself pinned by
    // test/helpers/store-bytes.test.ts — a reader narrowed back to a hardcoded
    // name list, or one that swallowed a failed read, would leave the leak
    // assertions below green while checking nothing.
    it('leaves no trace of the raw value in the database file on disk', async () => {
      // Guard: SECOND is not any rule's example, so it is absent from the seeded
      // snapshot — its post-add absence proves addException discarded the raw,
      // not that it was never written.
      expect(storeBytes(dir)).not.toContain(SECOND);

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
      //
      // One read, both assertions. The control and the absence check have to
      // describe the SAME bytes: read twice and the control can pass against one
      // snapshot while the raw is looked for in another.
      const fingerprint = (await grants())[0]?.valueFingerprint;
      expect(fingerprint).toBeDefined();
      const bytes = storeBytes(dir);
      expect(bytes).toContain(fingerprint);
      expect(bytes).not.toContain(SECOND);
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
      expectNoEchoOf(res.error, VALUE); // fails secure without echoing the secret
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
        for (const value of supplied) expectNoEchoOf(error, value);
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
        for (const value of [VALUE, SECOND, FOREIGN]) expectNoEchoOf(err, value);
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

    it('names the ledger window the count is actually taken over', () => {
      // The rotate note tells the reader the count spans the last N hours.
      // dashboard-ui cannot import the retention constant — it depends on
      // ui-kit and schema only — so the figure in that copy is a literal with
      // nothing local holding it to the truth. This suite has both sides, so it
      // is where they get pinned: widen the retention window without touching
      // the copy and the dialog starts quoting a window that no longer exists.
      expect(LEDGER_WINDOW_HOURS * 60 * 60 * 1000).toBe(BLOCKED_DETECTIONS_RETENTION_MS);
      expect(rotationBlockedLedgerNote(3)).toContain(
        `from the last ${String(LEDGER_WINDOW_HOURS)} hours`,
      );
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

    it('does not answer an UNREADABLE key with "delete it" — rotation writes too', async (ctx) => {
      // rotateKey both reads and writes the key, so this catch sees permission
      // and I/O failures, not only a corrupt parse. Answering one of those with
      // the corrupt-key guidance destroys every grant on the machine to fix a
      // chmod — the same harm the add and approve paths were split to avoid,
      // and the one place that classification was still missing.
      if (process.platform === 'win32') {
        ctx.skip('POSIX mode bits do not gate reads under Windows ACLs');
      }
      if (process.getuid?.() === 0) {
        ctx.skip('root bypasses the mode bits this case depends on');
      }
      loadOrCreateFingerprintKey(dir);
      const before = keyBytes();
      chmodSync(keyFile(), 0o000);
      try {
        const res = await rotateKey(ROTATE_CONFIRMATION);
        expect(res.ok).toBe(false);
        expect(res.error).toMatch(/permission/i);
        expect(res.error).not.toMatch(/delete .*exception\.key to mint/i);
        expect(res.error).toMatch(/do not delete/i);
      } finally {
        chmodSync(keyFile(), 0o600);
      }
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
      // The raw value was supplied by the caller, so a rejection that echoed
      // any run of it back would be a real disclosure.
      expectNoEchoOf(res.error, VALUE);
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

    // Each payload COERCES to the masked value the gate asks for, so each one
    // survives a switch from `!==` to `String(x) !==` — the mutation these exist
    // to catch. A payload that coerces to anything else is rejected either way
    // and would prove nothing, so the coercion is asserted before the call.
    const COERCING: [string, (masked: string) => unknown][] = [
      ['a single-element array', (masked) => [masked]],
      ['a stringifiable object', (masked) => ({ toString: () => masked })],
      ['a boxed String', (masked) => new String(masked)],
    ];

    it.each(COERCING)('rejects %s that coerces to the masked value', async (_label, build) => {
      const confirmation = build(MASKED);
      expect(String(confirmation)).toBe(MASKED); // the case is only meaningful if it coerces
      const res = await approveBlockedConfirmationRaw({
        reference: REFERENCE,
        scope: 'permanent',
        reason: 'x',
        confirmation,
      });
      expect(res.ok).toBe(false);
      expect(await grants()).toHaveLength(0);
    });

    // The empty-ish payloads a client can post in place of the field. `undefined`
    // is the missing-field case above; these cannot coerce to a masked value, so
    // they pin the boundary rather than the coercion.
    const EMPTYISH: [string, unknown][] = [
      ['null', null],
      ['an empty object', {}],
      ['false', false],
      ['zero', 0],
    ];

    it.each(EMPTYISH)('rejects %s arriving over the wire', async (_label, confirmation) => {
      const res = await approveBlockedConfirmationRaw({
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

    it('refuses a row whose key was DELETED and re-minted, not just rotated away', async () => {
      // The version alone is not an identity: minting restarts the counter, so
      // a key deleted at v1 and re-minted would come back as v1 and make this
      // row look current again — a grant from it would be inert the moment it
      // was created, which is the whole failure this guard exists to stop. The
      // corrupt-key guidance tells users to delete the key file, so this is the
      // path the product actively points at. The mint now takes the first
      // version the store has not already claimed, which keeps them distinct.
      const original = readFingerprintKey(dir);
      expect(original?.version).toBe(1);

      unlinkSync(keyFile());
      const reminted = loadOrCreateFingerprintKey(dir);
      expect(reminted.material.equals(original?.material ?? Buffer.alloc(0))).toBe(false);
      expect(reminted.version).not.toBe(original?.version);
      resetSingleton();

      const res = await approveBlocked({ reference: REFERENCE, scope: '1h', reason: 'x' });
      expect(res.ok).toBe(false);
      expect(res.error).toMatch(/could never match/i);
      expect(await grants()).toHaveLength(0);
    });

    it('refuses a row after the key was deleted and then ROTATED', async () => {
      // Rotation used to fall back to (missing ?? 0) + 1 — also v1 — so "delete
      // the key, then rotate" was a second route to the same collision.
      unlinkSync(keyFile());
      expect(await rotateKey(ROTATE_CONFIRMATION)).toEqual({ ok: true });
      resetSingleton();

      const res = await approveBlocked({ reference: REFERENCE, scope: '1h', reason: 'x' });
      expect(res.ok).toBe(false);
      expect(res.error).toMatch(/could never match/i);
      expect(await grants()).toHaveLength(0);
    });

    it('distinguishes an unreadable key from a corrupt one — never says "delete it"', async (ctx) => {
      // Answering a permissions failure with the corrupt-key guidance would
      // destroy every grant on the machine to fix a chmod, and the replacement
      // key is exactly what makes a stale ledger row look current again.
      if (process.platform === 'win32') {
        ctx.skip('POSIX mode bits do not gate reads under Windows ACLs');
      }
      if (process.getuid?.() === 0) {
        ctx.skip('root bypasses the mode bits this case depends on');
      }
      chmodSync(keyFile(), 0o000);
      resetSingleton();
      try {
        const res = await approveBlocked({ reference: REFERENCE, scope: '1h', reason: 'x' });
        expect(res.ok).toBe(false);
        expect(res.error).toMatch(/permission/i);
        // Not the corrupt-key guidance, and it says so explicitly.
        expect(res.error).not.toMatch(/delete .*exception\.key to mint/i);
        expect(res.error).toMatch(/do not delete/i);
        expect(await grants()).toHaveLength(0);
      } finally {
        chmodSync(keyFile(), 0o600); // so the tree can be removed
      }
    });
  });

  describe('a store that cannot be read fails closed with a message, not a crash', () => {
    it('returns an error instead of rejecting when the ledger read throws', async () => {
      // A Server Action that throws reaches the client as a framework error
      // page, not the recovery guidance every other branch here returns. The
      // store is replaced with bytes SQLite will refuse, which is the shape a
      // truncated or byte-flipped store arrives in.
      resetSingleton(); // close the handle before overwriting the file
      writeFileSync(join(dir, 'aka.db'), 'not a database\n');
      for (const sidecar of ['aka.db-wal', 'aka.db-shm']) {
        rmSync(join(dir, sidecar), { force: true });
      }

      const res = await approveBlocked({ reference: REFERENCE, scope: '1h', reason: 'x' });
      expect(res.ok).toBe(false);
      expect(res.error).toMatch(/local store/i);
    });

    it('returns an error instead of rejecting when the ruleset read throws', async () => {
      resetSingleton();
      writeFileSync(join(dir, 'aka.db'), 'not a database\n');
      for (const sidecar of ['aka.db-wal', 'aka.db-shm']) {
        rmSync(join(dir, sidecar), { force: true });
      }

      const res = await addException({ ruleId: RULE_ID, value: VALUE, scope: 'once', reason: 'x' });
      expect(res.ok).toBe(false);
      expect(res.error).toMatch(/local store/i);
      expectNoEchoOf(res.error, VALUE);
    });
  });

  describe('the guard is checked before the write, not with it', () => {
    it('a rotation landing between the check and the write still writes a grant', async () => {
      // An honest limitation pinned as a test rather than left implied. The
      // version is read, then the grant is written; a rotation from another
      // process (the CLI, another tab) in between lands a grant under the old
      // version. The window is one store write wide on a single-operator local
      // tool, and closing it needs the key read and the insert in one
      // transaction — a seam the repository does not offer. If that seam
      // arrives, this test is what should change.
      const before = readFingerprintKey(dir)?.version ?? 0;
      const res = await approveBlocked({ reference: REFERENCE, scope: '1h', reason: 'x' });
      expect(res).toEqual({ ok: true });

      expect(await rotateKey(ROTATE_CONFIRMATION)).toEqual({ ok: true });
      resetSingleton();

      const grant = (await grants())[0];
      expect(grant?.keyVersion).toBe(before);
      // The grant is real but inert — exactly what a mid-flight rotation costs.
      expect(await bundleIds(readFingerprintKey(dir)?.version ?? 0)).not.toContain(grant?.id);
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

describe('revokeException — terminal, audit-retained, and easy to no-op silently', () => {
  // The grant to revoke, created through the real add path so it is one a live
  // detection would genuinely have matched a moment earlier.
  async function activeGrant(): Promise<DetectionException> {
    const res = await addException({ ruleId: RULE_ID, value: VALUE, scope: '1h', reason: 'x' });
    expect(res).toEqual({ ok: true });
    const [grant] = await grants();
    if (grant === undefined) throw new Error('the grant under test was not created');
    return grant;
  }

  describe('revocation is terminal, and the row stays as evidence', () => {
    it('stamps the audit fields and keeps the row', async () => {
      const grant = await activeGrant();
      expect(grant.revokedAt).toBeNull();

      expect(await revokeException(grant.id, 'key rotated upstream')).toEqual({ ok: true });
      resetSingleton();

      const all = await grants();
      // Retained, not deleted — a revoked grant is the record that the bypass
      // once existed, and the retention sweep is what eventually removes it.
      expect(all).toHaveLength(1);
      expect(all[0]?.id).toBe(grant.id);
      expect(all[0]?.revokedAt).not.toBeNull();
      expect(all[0]?.revokeReason).toBe('key rotated upstream');
      // Both identities come from the same resolveCreatedBy, so pin them
      // against each other rather than against whatever account runs CI.
      expect(all[0]?.revokedBy).toBe(grant.createdBy);
      expect(all[0]?.revokedBy).not.toBe('');
    });

    it('drops the grant out of the bundle enforcement actually reads', async () => {
      // "No longer applies" has to mean absent from the evaluation bundle. A
      // revoke that only flipped a column the dashboard reads would leave the
      // hook still excepting the value.
      const grant = await activeGrant();
      expect(await bundleIds(grant.keyVersion)).toContain(grant.id);

      expect(await revokeException(grant.id, 'no longer needed')).toEqual({ ok: true });
      resetSingleton();

      expect(await bundleIds(grant.keyVersion)).not.toContain(grant.id);
      expect(await grants()).toHaveLength(1);
    });

    it('frees the value to be granted again — the duplicate error’s own advice', async () => {
      // createGrant answers a collision with "revoke it first", so the path that
      // message points at has to work: the one-active-grant-per
      // (rule, fingerprint, keyVersion) index is partial on `revoked_at IS NULL`.
      const grant = await activeGrant();
      const blocked = await addException({
        ruleId: RULE_ID,
        value: VALUE,
        scope: '1h',
        reason: 'again',
      });
      expect(blocked.ok).toBe(false);
      expect(blocked.error).toMatch(/already exists/i);

      expect(await revokeException(grant.id, 'x')).toEqual({ ok: true });
      resetSingleton();

      expect(
        await addException({ ruleId: RULE_ID, value: VALUE, scope: '1h', reason: 'again' }),
      ).toEqual({ ok: true });
      const all = await grants();
      expect(all).toHaveLength(2);
      expect(all.filter((ex) => ex.revokedAt === null)).toHaveLength(1);
    });
  });

  describe('a revoke that changes nothing says so, and changes nothing', () => {
    it('reports an unknown id as a refusal, not a crash', async () => {
      const grant = await activeGrant();

      const res = await revokeException('7d9f7a4e-0000-4000-8000-000000000000', 'x');
      expect(res.ok).toBe(false);
      expect(res.error).toMatch(/no active exception/i);

      resetSingleton();
      // The real grant is untouched — a miss must not revoke by proximity.
      expect((await grants())[0]?.revokedAt).toBeNull();
      expect(await bundleIds(grant.keyVersion)).toContain(grant.id);
    });

    it('refuses a second revoke and leaves the first revocation’s record intact', async () => {
      // The UPDATE is scoped to `revoked_at IS NULL`, so a re-revoke matches no
      // row. That is what makes the audit record immutable: without it, a later
      // revoke would overwrite the original timestamp, actor and reason — the
      // three fields the row exists to preserve.
      const grant = await activeGrant();
      expect(await revokeException(grant.id, 'the real reason')).toEqual({ ok: true });
      resetSingleton();
      const first = (await grants())[0];

      const second = await revokeException(grant.id, 'a different reason');
      expect(second.ok).toBe(false);
      expect(second.error).toMatch(/no active exception/i);

      resetSingleton();
      const after = (await grants())[0];
      expect(after?.revokedAt).toBe(first?.revokedAt);
      expect(after?.revokedBy).toBe(first?.revokedBy);
      expect(after?.revokeReason).toBe('the real reason');
    });
  });

  describe('the reason is normalised, never stored blank', () => {
    // A reason is optional here (unlike a grant's justification, which the
    // creating actions require), so "none given" has to reach the store as NULL.
    // An empty string is a different fact: it reads as "a reason was recorded"
    // to anything asking `revoke_reason IS NOT NULL`, and the column would then
    // carry two encodings of the same absence.
    const BLANK: [string, string][] = [
      ['an empty', ''],
      ['a spaces-only', '   '],
      ['a newline-only', '\n'],
      ['a tab-only', '\t'],
    ];

    it.each(BLANK)('stores %s reason as NULL', async (_label, reason) => {
      const grant = await activeGrant();
      expect(await revokeException(grant.id, reason)).toEqual({ ok: true });
      resetSingleton();

      const revoked = (await grants())[0];
      expect(revoked?.revokeReason).toBeNull();
      // The revoke itself still happened — a blank reason is not a rejection.
      expect(revoked?.revokedAt).not.toBeNull();
    });

    it('trims the surrounding whitespace off a real reason', async () => {
      const grant = await activeGrant();
      expect(await revokeException(grant.id, '  rotating this credential  ')).toEqual({ ok: true });
      resetSingleton();

      expect((await grants())[0]?.revokeReason).toBe('rotating this credential');
    });
  });

  describe('a store that cannot be read fails closed with a message, not a crash', () => {
    it('returns an error instead of rejecting when the revoke throws', async () => {
      // Corrupting the file makes db() throw while OPENING the store, so
      // revoke()'s UPDATE is never reached — that is the seam this case
      // actually drives. The sibling seam, the UPDATE itself throwing, fails
      // identically: the repository runs it synchronously and hands back an
      // already-resolved promise. Both throw out of the call rather than
      // rejecting a promise a `.catch` could see, both sit inside the action's
      // try, and the pre-fix code rejected on either — reaching the client as a
      // framework error page instead of the guidance every other action here
      // returns.
      const grant = await activeGrant();
      resetSingleton(); // close the handle before overwriting the file
      writeFileSync(join(dir, 'aka.db'), 'not a database\n');
      for (const sidecar of ['aka.db-wal', 'aka.db-shm']) {
        rmSync(join(dir, sidecar), { force: true });
      }

      const res = await revokeException(grant.id, 'x');
      expect(res.ok).toBe(false);
      expect(res.error).toMatch(/local store/i);
      // And NOT the refusal message: telling someone their grant is already
      // gone when the store simply could not be read is the wrong next step —
      // the grant is still active and still excepting the value.
      expect(res.error).not.toMatch(/no active exception/i);
    });
  });
});

// ---------------------------------------------------------------------------

describe('the untyped wire — every mutating action parses its whole input', () => {
  // A Server Action's parameter types are a compile-time claim about a runtime
  // that never checked one: the arguments arrive as JSON over an HTTP POST, and
  // a caller is free to post a number, a null, or an object carrying a hostile
  // `toString`. Reaching a `.trim()`, a `.slice()`, a template literal or a SQL
  // bind parameter, such a value throws — and a THROWN Server Action rejects,
  // so the browser gets a framework error page rather than the recoverable
  // message every branch in actions.ts is written to return. That is the same
  // outcome the store-failure guards exist to prevent, reached by another door.
  //
  // Three properties are pinned per case and each catches a different mistake:
  //   1. it does not throw      — the rejection reaches the caller at all
  //   2. it names the FIELD     — the refusal is actionable, and (below) the
  //                               name is the schema's key rather than anything
  //                               derived from the payload
  //   3. it echoes no raw value — a field arriving as the wrong type is still a
  //                               live credential
  // Plus inertness: a refused payload writes no grant.
  //
  // Property 2 is also what stops property 3 passing vacuously. `expectNoEchoOf`
  // guards against an absent error but NOT an empty one, and every
  // `not.toContain` is satisfied by `''` — so the message is required to say
  // something specific before it is asked what it omits.

  // A shape-valid vault pointer, assembled from its segments rather than
  // written out: the repo is developed with the plugin active, and a contiguous
  // pointer literal in a source file is exactly what it substitutes away. The
  // grantRevealFromPointer cases below refuse before it is ever resolved — it
  // only has to get past the shape check so those cases fail for the reason
  // they name, and safeParse pins that rather than leaving it to inspection.
  const POINTER =
    `[[aka:${DetectionCategory.enum.secret}:` +
    `${'A'.repeat(4)}.${'A'.repeat(26)}.${'A'.repeat(16)}]]`;
  if (!PointerToken.safeParse(POINTER).success) {
    throw new Error('the assembled pointer fixture no longer matches PointerToken');
  }

  // The shapes a browser can actually post in place of a string.
  //
  // The three COMPOUND shapes each carry the secret, and that is what makes the
  // echo assertion below able to fail at all: an assertion that a message omits
  // a value the case never supplied is true by construction and stays true
  // however the branch is worded. `[VALUE]` coerces to VALUE outright, and
  // `{ leak: VALUE }` surfaces it through any serialization, so a branch that
  // interpolates the field it rejected is caught in each of them.
  //
  // The four PRIMITIVE shapes have nothing echoable in them — a `42` cannot
  // disclose a credential. For those rows the echo assertion is live only
  // through the SIBLING fields, so every payload below carries VALUE in a field
  // it is not mutating wherever the action has one to spare. `rotateKey` takes a
  // single parameter and has none, so its four primitive cases are inert on the
  // echo check by construction and are covered by the compound shapes instead.
  const NON_TEXT: [string, unknown][] = [
    ['a number', 42],
    ['null', null],
    ['undefined', undefined],
    ['true', true],
    ['an object carrying the secret', { leak: VALUE }],
    ['an array carrying the secret', [VALUE]],
    ['an object whose toString yields the secret', { toString: () => VALUE }],
  ];

  // Every field on this surface that must arrive as text, with a call that puts
  // one payload into it and leaves every other field well-formed. Enumerated
  // per FIELD rather than per action: the hole this closes was per-field, so a
  // table keyed by action would have exactly the blind spot it is testing for.
  //
  // Every payload carries VALUE in some field it is NOT mutating, so the echo
  // assertion has something the call really supplied to look for even on the
  // primitive shapes. None of these actions echoes the field VALUE is parked in
  // — `approveBlocked` names no reference in "expired from the ledger",
  // `grantRevealFromPointer` names no pointer in "not a vault pointer", and
  // `revokeException` names no id in "no active exception with that id" — so
  // each of those is a live assertion that passes today and would go red the
  // moment one of them started interpolating.
  const FIELDS: [string, string, (bad: unknown) => Promise<{ ok: boolean; error?: string }>][] = [
    [
      'addException',
      'ruleId',
      (b) => addExceptionRaw({ ruleId: b, value: VALUE, scope: 'once', reason: 'r' }),
    ],
    [
      'addException',
      'value',
      (b) => addExceptionRaw({ ruleId: RULE_ID, value: b, scope: 'once', reason: VALUE }),
    ],
    [
      'addException',
      'scope',
      (b) => addExceptionRaw({ ruleId: RULE_ID, value: VALUE, scope: b, reason: 'r' }),
    ],
    [
      'addException',
      'reason',
      (b) => addExceptionRaw({ ruleId: RULE_ID, value: VALUE, scope: 'once', reason: b }),
    ],
    [
      'approveBlocked',
      'reference',
      (b) => approveBlockedRaw({ reference: b, scope: 'once', reason: VALUE }),
    ],
    [
      'approveBlocked',
      'scope',
      (b) => approveBlockedRaw({ reference: VALUE, scope: b, reason: 'r' }),
    ],
    [
      'approveBlocked',
      'reason',
      (b) => approveBlockedRaw({ reference: VALUE, scope: 'once', reason: b }),
    ],
    [
      'grantRevealFromPointer',
      'pointer',
      (b) => grantRevealFromPointerRaw({ pointer: b, scope: 'once', justification: VALUE }),
    ],
    [
      'grantRevealFromPointer',
      'scope',
      (b) => grantRevealFromPointerRaw({ pointer: POINTER, scope: b, justification: VALUE }),
    ],
    [
      'grantRevealFromPointer',
      'justification',
      (b) => grantRevealFromPointerRaw({ pointer: VALUE, scope: 'once', justification: b }),
    ],
    ['revokeException', 'id', (b) => revokeExceptionRaw(b, VALUE)],
    ['revokeException', 'reason', (b) => revokeExceptionRaw(VALUE, b)],
    // The one row with no sibling to park VALUE in — see NON_TEXT above.
    ['rotateKey', 'confirmation', (b) => rotateKeyRaw(b)],
  ];

  const CASES = FIELDS.flatMap(([action, field, call]) =>
    NON_TEXT.map(
      ([label, bad]) =>
        [action, field, label, bad, call] as [
          string,
          string,
          string,
          unknown,
          (bad: unknown) => Promise<{ ok: boolean; error?: string }>,
        ],
    ),
  );

  it.each(CASES)('%s refuses %s arriving as %s', async (_action, field, _label, bad, call) => {
    // A key on disk so rotateKey's inertness is observable, and so the
    // addException cases reach a key resolution that could succeed.
    loadOrCreateFingerprintKey(dir);
    const keyBefore = keyBytes();

    // The rejection has to arrive as a RETURN. A rejected promise here is the
    // framework error page this whole block exists to rule out, so it is
    // asserted on directly rather than allowed to fail the case as an unrelated
    // error naming a TypeError deep inside the action.
    const res = await expectNoRejection(() => call(bad));
    expect(res.ok).toBe(false);

    // Names the field — and names it from the schema's own key. Asserted
    // before the echo check so that check is never satisfied by an empty
    // message.
    expect(res.error).toContain(`'${field}'`);
    expectNoEchoOf(res.error, VALUE);

    // Refused means refused: nothing written, and the key untouched.
    expect(await grants()).toHaveLength(0);
    expect(keyBytes()).toBe(keyBefore);
  });

  // The case no per-field alias can express: the argument is not an object, so
  // the failure happens before any field is read. It is also the one shape that
  // cannot name a field, which is why the refusal has a second form.
  // Same rule as NON_TEXT: the shapes that CAN carry the secret do, so the echo
  // assertion below is not asserting the absence of something never sent. A
  // bare string posted where an object belongs is the realistic hostile form —
  // and the realistic string to post is the credential itself.
  const NON_OBJECTS: [string, unknown][] = [
    ['null', null],
    ['undefined', undefined],
    ['a number', 42],
    ['a bare string that is the secret', VALUE],
    ['an array carrying the secret', [VALUE]],
  ];

  const WHOLE_INPUT: [string, (input: unknown) => Promise<{ ok: boolean; error?: string }>][] = [
    ['addException', addExceptionRaw],
    ['approveBlocked', approveBlockedRaw],
    ['grantRevealFromPointer', grantRevealFromPointerRaw],
  ];

  it.each(
    WHOLE_INPUT.flatMap(([action, call]) =>
      NON_OBJECTS.map(
        ([label, input]) =>
          [action, label, input, call] as [
            string,
            string,
            unknown,
            (input: unknown) => Promise<{ ok: boolean; error?: string }>,
          ],
      ),
    ),
  )('%s refuses a payload that is %s', async (_action, _label, input, call) => {
    const res = await expectNoRejection(() => call(input));
    expect(res.ok).toBe(false);
    // No field can be blamed, so the refusal takes its other form — pinned so
    // the message cannot silently become an empty string, which would satisfy
    // every absence assertion below it.
    expect(res.error).toMatch(/expected shape/i);
    expectNoEchoOf(res.error, VALUE);
    expect(await grants()).toHaveLength(0);
  });

  // The control, without which every assertion above passes with the actions
  // rewritten to refuse unconditionally. A guard that refuses everything
  // satisfies "does not throw", "returns ok: false" and "echoes nothing".
  it('still accepts a well-formed payload', async () => {
    const res = await addException({
      ruleId: RULE_ID,
      value: VALUE,
      scope: 'once',
      reason: 'a real grant',
    });
    expect(res.error).toBeUndefined();
    expect(res.ok).toBe(true);
    expect(await grants()).toHaveLength(1);
  });

  // `confirmation` is optional, so `undefined` is the one non-string it must
  // accept — the field is simply absent for a non-permanent scope. Pinned
  // separately from the table above, where `undefined` is a rejection.
  it('accepts an absent confirmation on a non-permanent scope', async () => {
    const res = await addException({
      ruleId: RULE_ID,
      value: VALUE,
      scope: 'once',
      reason: 'no confirmation needed',
      confirmation: undefined,
    });
    expect(res.ok).toBe(true);
  });

  // ...but a confirmation that is PRESENT and not text is refused, rather than
  // coerced. The existing rotateKey and approveBlocked blocks pin this for
  // their own actions through the value comparison; here it is the parse.
  it.each(NON_TEXT.filter(([label]) => label !== 'undefined'))(
    'refuses a confirmation arriving as %s',
    async (_label, bad) => {
      const res = await addExceptionRaw({
        ruleId: RULE_ID,
        value: VALUE,
        scope: 'permanent',
        reason: 'r',
        confirmation: bad,
      });
      expect(res.ok).toBe(false);
      expect(res.error).toContain("'confirmation'");
      expectNoEchoOf(res.error, VALUE);
      expect(await grants()).toHaveLength(0);
    },
  );
});
