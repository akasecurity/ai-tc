import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { readWorkspaceSettings } from '@akasecurity/persistence';
import type { SaveSettingsInput } from '@akasecurity/schema';
import { HISTORY_SYNC_PAYLOAD_VERSION, VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, expectTypeOf, it, vi } from 'vitest';

import { saveSettings } from '../../app/(app)/settings/actions.ts';

// `saveSettings` is the web surface that records and revokes the vault-consent
// grant. The grant must always be stamped server-side ('on' has no input path
// for a timestamp or version), a still-valid grant must survive re-saves with
// its original acknowledgedAt, and 'off' must remove the field from the
// persisted file entirely — revocation stops future vaulting without touching
// what the vault already stores.
//
// The action resolves settings.json from `homedir()` (never process.env), so
// the whole test is redirected into a temp home by mocking `node:os`;
// `next/cache` is stubbed because revalidatePath needs a Next render context
// that does not exist under vitest.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});
vi.mock('next/cache', () => ({ revalidatePath: () => undefined }));

let home: string;

function settingsFile(): string {
  return join(home, '.aka', 'settings', 'settings.json');
}

function rawSettings(): string {
  return readFileSync(settingsFile(), 'utf8');
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-web-settings-'));
  osHome.dir = home;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

const ENDPOINT = 'https://plane.example.com';

describe('saveSettings — vault-consent grant and revocation', () => {
  it("records a server-stamped grant at the current consent version on 'on'", async () => {
    const before = Date.now();
    const res = await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: 'revoked',
      historySyncConsent: 'revoked',
      vaultConsent: 'on',
      vaultInlineReveal: 'masked',
    });
    expect(res).toEqual({ ok: true });

    const consent = readWorkspaceSettings().vaultConsent;
    expect(consent?.version).toBe(VAULT_CONSENT_VERSION);
    // The timestamp is minted by the action itself, so it lands inside this
    // test's own execution window.
    const acknowledged = Date.parse(consent?.acknowledgedAt ?? '');
    expect(acknowledged).toBeGreaterThanOrEqual(before);
    expect(acknowledged).toBeLessThanOrEqual(Date.now());
  });

  // The model-judge grant. Left as an unconditional boolean this is
  // deleted fleet-wide on everyone's next unrelated save the moment
  // MODEL_JUDGE_PAYLOAD_VERSION is bumped — and today every save rewrites its
  // acknowledgedAt, so the record of when consent was given drifts forward on
  // edits that had nothing to do with it.
  it("leaves the model-judge grant and its acknowledgedAt alone on 'unchanged'", async () => {
    const { applyOnboarding } = await import('@akasecurity/persistence');
    const granted = { acknowledgedAt: '2020-01-01T00:00:00.000Z', payloadVersion: 1 };
    applyOnboarding({ modelJudgeConsent: granted }, join(home, '.aka'));

    const res = await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: 'unchanged',
      historySyncConsent: 'unchanged',
      vaultConsent: 'off',
      // A real unrelated edit, so this is a save that had to do something.
      vaultInlineReveal: 'full',
    });

    // THE POSITIVE CONTROL. Without it every assertion below is satisfied by a
    // save that was REFUSED — a malformed payload, a schema that stopped
    // accepting 'unchanged', a failed write — because those leave the seeded
    // grant untouched too, which is exactly what is being asserted.
    expect(res.ok).toBe(true);
    expect(readWorkspaceSettings().vaultInlineReveal).toBe('full');
    expect(readWorkspaceSettings().modelJudgeConsent).toEqual(granted);
  });

  // THE UNTOUCHED CASE, and the reason the answer is three-state. The form
  // submits every field on every save, so with a boolean an unrelated edit had to
  // assert something about this grant — and both assertions are wrong for a STALE
  // one. 'revoked' deletes the record and with it the paused badge, the
  // `aka status` paused line and `aka sync-history`'s stale branch, leaving a
  // user who did opt in told that they never did. 'granted' is worse: it
  // re-consents to a widened payload nobody affirmed.
  it("leaves a stale grant exactly as it was when the row is 'unchanged'", async () => {
    const stale = {
      acknowledgedAt: '2020-01-01T00:00:00.000Z',
      // One behind, so it is a real grant that authorizes nothing today.
      payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION - 1,
      endpoint: ENDPOINT,
    };
    const { applyOnboarding } = await import('@akasecurity/persistence');
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: ENDPOINT, attachedAt: '2020-01-01T00:00:00.000Z' },
        historySyncConsent: stale,
      },
      join(home, '.aka'),
    );

    const res = await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: 'revoked',
      historySyncConsent: 'unchanged',
      vaultConsent: 'off',
      // A real unrelated edit, or the save proves nothing.
      vaultInlineReveal: 'full',
    });
    expect(res.ok).toBe(true);

    // Byte-for-byte the grant that was there: still stale, so it still
    // authorizes nothing — and still present, so every surface that explains
    // WHY sharing is paused still has something to read.
    expect(readWorkspaceSettings().historySyncConsent).toEqual(stale);
    expect(readWorkspaceSettings().vaultInlineReveal).toBe('full');
  });

  // The mirror of the stale case above: a grant that is ALREADY valid for the
  // current payload version and endpoint must survive a 'granted' re-save
  // byte-for-byte — kept as-is rather than re-stamped, so its acknowledgedAt
  // does not drift on every unrelated save. The backfill DOES still run,
  // bounded to the EXISTING acknowledgedAt rather than "now" — see the sibling
  // test below, which is what actually exercises it; this one is the record
  // staying put, not the retry.
  it("keeps an already-valid grant as-is when 'granted' is saved again", async () => {
    const current = {
      acknowledgedAt: '2020-01-01T00:00:00.000Z',
      payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
      endpoint: ENDPOINT,
    };
    const { applyOnboarding } = await import('@akasecurity/persistence');
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: ENDPOINT, attachedAt: '2020-01-01T00:00:00.000Z' },
        historySyncConsent: current,
      },
      join(home, '.aka'),
    );

    const res = await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: 'revoked',
      historySyncConsent: 'granted',
      vaultConsent: 'off',
      // A real unrelated edit, or the save proves nothing about a re-stamp it
      // never had cause to make.
      vaultInlineReveal: 'full',
    });
    expect(res.ok).toBe(true);
    expect(readWorkspaceSettings().historySyncConsent).toEqual(current);
    expect(readWorkspaceSettings().vaultInlineReveal).toBe('full');
  });

  // THE RETRY ITSELF. seedCaptureBacklogOwed is best-effort and silent — a
  // locked or unwritable store at grant time must not turn a successful
  // consent into a reported failure — and `aka attach` / `aka sync-history
  // --on` get a retry for free because a human can just run either again.
  // This is the dashboard's only equivalent: choosing 'granted' again over an
  // already-valid grant, which the previous test shows leaves the RECORD
  // untouched but must still give the backfill another attempt, bounded to
  // that record's own acknowledgedAt so it recovers exactly what the original
  // grant promised.
  it("retries the capture backfill when 'granted' is saved over an already-valid grant", async () => {
    const acknowledgedAt = '2020-06-01T00:00:00.000Z';
    const current = {
      acknowledgedAt,
      payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
      endpoint: ENDPOINT,
    };
    const { applyOnboarding, dataDir, openLocalDatabase } =
      await import('@akasecurity/persistence');
    const base = join(home, '.aka');
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: ENDPOINT, attachedAt: acknowledgedAt },
        historySyncConsent: current,
      },
      base,
    );

    // A pre-attach capture, never marked owed — standing in for the row a
    // locked store dropped the first time this grant's backfill ran.
    const db1 = openLocalDatabase(dataDir(base));
    try {
      db1.auditEvents.ensureSessionRoot('s-1', '2020-05-01T00:00:00.000Z');
      db1.auditEvents.insertAuditEvent({
        id: 's-1-prompt',
        eventType: 'prompt',
        rootSessionId: 's-1',
        parentId: 's-1',
        startedAt: '2020-05-01T00:01:00.000Z',
        content: 'text of a prompt the first backfill missed',
        contentHash: 'c'.repeat(64),
        attributes: { source_tool: 'claude-code' },
      });
    } finally {
      db1.close();
    }

    const res = await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: 'revoked',
      historySyncConsent: 'granted',
      vaultConsent: 'off',
      vaultInlineReveal: 'masked',
    });
    expect(res.ok).toBe(true);

    const db2 = openLocalDatabase(dataDir(base));
    try {
      expect(
        db2.historySync.pendingCaptureRows(10, Date.parse(acknowledgedAt) + 1).map((r) => r.id),
      ).toEqual(['s-1-prompt']);
    } finally {
      db2.close();
    }
  });

  it('still revokes on an explicit revoked, stale grant or not', async () => {
    const { applyOnboarding } = await import('@akasecurity/persistence');
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: ENDPOINT, attachedAt: '2020-01-01T00:00:00.000Z' },
        historySyncConsent: {
          acknowledgedAt: '2020-01-01T00:00:00.000Z',
          payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION - 1,
          endpoint: ENDPOINT,
        },
      },
      join(home, '.aka'),
    );

    await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: 'revoked',
      historySyncConsent: 'revoked',
      vaultConsent: 'off',
      vaultInlineReveal: 'masked',
    });

    expect(readWorkspaceSettings().historySyncConsent).toBeUndefined();
  });

  it("keeps the original acknowledgedAt when 'on' is saved again", async () => {
    await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: 'revoked',
      historySyncConsent: 'revoked',
      vaultConsent: 'on',
      vaultInlineReveal: 'masked',
    });
    const first = readWorkspaceSettings().vaultConsent;
    expect(first).toBeDefined();

    // A later save of unrelated edits with consent still 'on' must not
    // re-stamp the grant — the recorded acknowledgment time is the consent
    // record, not a last-touched time. Let the clock tick past the first stamp
    // so a re-stamp could not coincide with it.
    await new Promise((resolve) => setTimeout(resolve, 5));
    const res = await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: 'revoked',
      historySyncConsent: 'revoked',
      vaultConsent: 'on',
      // The unrelated edit. It has to be a field that really changes, or the
      // second save proves nothing about a re-stamp it never had cause to make.
      vaultInlineReveal: 'off',
    });
    expect(res).toEqual({ ok: true });

    const again = readWorkspaceSettings();
    expect(again.vaultInlineReveal).toBe('off'); // the unrelated edit landed
    expect(again.vaultConsent).toEqual(first);
  });

  it("removes the field from the persisted file on 'off'", async () => {
    await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: 'revoked',
      historySyncConsent: 'revoked',
      vaultConsent: 'on',
      vaultInlineReveal: 'masked',
    });
    expect(rawSettings()).toContain('vaultConsent');

    const res = await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: 'revoked',
      historySyncConsent: 'revoked',
      vaultConsent: 'off',
      vaultInlineReveal: 'masked',
    });
    expect(res).toEqual({ ok: true });

    // Gone from the raw JSON, not merely parsed away: the absence of the key
    // is what "not granted" means to every reader of this file.
    const raw = rawSettings();
    expect(raw).not.toContain('vaultConsent');
    expect('vaultConsent' in (JSON.parse(raw) as Record<string, unknown>)).toBe(false);
    expect(readWorkspaceSettings().vaultConsent).toBeUndefined();
  });

  it('rejects an unknown consent value and leaves the file untouched', async () => {
    await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: 'revoked',
      historySyncConsent: 'revoked',
      vaultConsent: 'on',
      vaultInlineReveal: 'masked',
    });
    const before = rawSettings();

    const res = await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: 'revoked',
      historySyncConsent: 'revoked',
      vaultConsent: 'granted',
      vaultInlineReveal: 'masked',
    });
    expect(res.ok).toBe(false);
    expect(rawSettings()).toBe(before);
  });

  it('rejects a client-supplied grant object — there is no input path for a timestamp', async () => {
    // The input contract is the bare choice string. A caller that smuggles a
    // pre-built grant (back-dated acknowledgment, forged version) past the
    // type system must still be rejected at runtime, writing nothing.
    const forged = { acknowledgedAt: '2001-01-01T00:00:00.000Z', version: VAULT_CONSENT_VERSION };
    const res = await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: 'revoked',
      historySyncConsent: 'revoked',
      vaultConsent: forged as unknown as string,
      vaultInlineReveal: 'masked',
    });
    expect(res.ok).toBe(false);
    expect(() => rawSettings()).toThrow(); // nothing was ever written

    // And the contract itself admits only a string — no object shape exists.
    // The wire contract admits only a string — no object shape exists. Read off
    // the SCHEMA type, not the action's parameter: that parameter is `unknown`
    // by design, precisely so a non-object payload is refused at runtime rather
    // than throwing on the first field read.
    expectTypeOf<SaveSettingsInput['vaultConsent']>().toEqualTypeOf<string>();
  });
});

describe('stale-grant re-consent and inline reveal', () => {
  // A grant recorded against an older consent version authorizes nothing; a
  // save with 'on' selected must re-stamp it at the current version — the
  // one-save re-consent the settings notice documents.
  it("saving 'on' over a STALE grant re-stamps at the current version", async () => {
    const { applyOnboarding } = await import('@akasecurity/persistence');
    applyOnboarding(
      {
        // Any parseable version that is not the CURRENT one is a stale grant;
        // versions below 1 fail the schema, so the other-epoch simulation uses
        // the next version up — the same mismatch path either way.
        vaultConsent: {
          acknowledgedAt: '2020-01-01T00:00:00.000Z',
          version: VAULT_CONSENT_VERSION + 1,
        },
      },
      join(home, '.aka'),
    );
    const result = await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: 'revoked',
      historySyncConsent: 'revoked',
      vaultConsent: 'on',
      vaultInlineReveal: 'masked',
    });
    expect(result.ok).toBe(true);
    const persisted = readWorkspaceSettings(join(home, '.aka'));
    expect(persisted.vaultConsent?.version).toBe(VAULT_CONSENT_VERSION);
    expect(persisted.vaultConsent?.acknowledgedAt).not.toBe('2020-01-01T00:00:00.000Z');
  });

  it('persists a valid inline-reveal mode and rejects junk', async () => {
    const ok = await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: 'revoked',
      historySyncConsent: 'revoked',
      vaultConsent: 'off',
      vaultInlineReveal: 'full',
    });
    expect(ok.ok).toBe(true);
    expect(readWorkspaceSettings(join(home, '.aka')).vaultInlineReveal).toBe('full');

    const bad = await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: 'revoked',
      historySyncConsent: 'revoked',
      vaultConsent: 'off',
      vaultInlineReveal: 'loud',
    });
    expect(bad.ok).toBe(false);
  });
});
