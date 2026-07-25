import { createHash, createHmac } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
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
function storeBytes(): string {
  const parts: Buffer[] = [];
  for (const name of ['aka.db', 'aka.db-wal', 'aka.db-shm']) {
    try {
      parts.push(readFileSync(join(dir, name)));
    } catch {
      // sidecar absent — nothing to fold in
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
      expect(storeBytes()).not.toContain(SECOND);
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
