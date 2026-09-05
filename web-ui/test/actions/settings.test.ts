import { readFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { join } from 'node:path';

import type * as Persistence from '@akasecurity/persistence';
import { readWorkspaceSettings } from '@akasecurity/persistence';
import type { SaveSettingsInput, WebChatCaptureConsentChoice } from '@akasecurity/schema';
import {
  HISTORY_SYNC_PAYLOAD_VERSION,
  VAULT_CONSENT_VERSION,
  WEB_CHAT_CAPTURE_CONSENT_VERSION,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, expectTypeOf, it, vi } from 'vitest';

import { saveSettings } from '../../app/(app)/settings/actions.ts';
import { tempHomes } from '../helpers/temp-home.ts';

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

// The seam the lock proof at the bottom of this file needs, and nothing else
// uses it: a hook that runs at the moment `saveSettings` CALLS applyOnboarding,
// which is after any read the action made for itself and before the one
// applyOnboarding makes inside its lock. Writing settings.json here therefore
// stands in for a second writer that committed in exactly that window.
//
// `applyOnboarding` alone is wrapped; every other export is the real one, so the
// store, the schema merge and the file lock are all genuine.
const beforeMerge = vi.hoisted(() => ({ run: undefined as (() => void) | undefined }));
vi.mock('@akasecurity/persistence', async (importActual) => {
  const actual = await importActual<typeof Persistence>();
  return {
    ...actual,
    applyOnboarding: (
      answers: Parameters<typeof actual.applyOnboarding>[0],
      base?: string,
      managedOverride?: Parameters<typeof actual.applyOnboarding>[2],
    ) => {
      // ONE-SHOT. The hook writes settings.json through this same export, so a
      // hook left armed re-enters itself forever; taking it before calling also
      // says what it stands in for — one other writer, committing once.
      const hook = beforeMerge.run;
      beforeMerge.run = undefined;
      hook?.();
      return actual.applyOnboarding(answers, base, managedOverride);
    },
  };
});

// Homes are removed when this FILE finishes, not after each test: the store
// app/lib/db.ts opens under them stays open, and Windows will not delete a
// directory a handle still holds. See the helper.
const newHome = tempHomes('aka-web-settings-');

let home: string;

function settingsFile(): string {
  return join(home, '.aka', 'settings', 'settings.json');
}

function rawSettings(): string {
  return readFileSync(settingsFile(), 'utf8');
}

beforeEach(() => {
  home = newHome();
  osHome.dir = home;
});

// The hook is one-shot, but a case that arms it and then refuses before
// applyOnboarding is reached would leave it armed for the next test. The home
// itself is removed by the helper when this file finishes, not here.
afterEach(() => {
  beforeMerge.run = undefined;
});

const ENDPOINT = 'https://plane.example.com';

describe('saveSettings — the redact fallback', () => {
  // The setting that decides what happens on a field a detection's Redact
  // cannot be applied to. It is a plain preference, not a consent grant: no
  // acknowledgement is stamped and nothing about it is versioned.
  it('persists each of the three values', async () => {
    for (const value of ['monitor', 'warn', 'block'] as const) {
      const res = await saveSettings({
        historicalAccess: 'session-only',
        modelJudgeConsent: 'unchanged',
        historySyncConsent: 'unchanged',
        vaultConsent: 'off',
        vaultInlineReveal: 'masked',
        webChatCaptureConsent: 'unchanged',
        redactFallback: value,
        bodyRetention: { enabled: false, retainDays: 30 },
      });
      expect(res).toEqual({ ok: true });
      expect(readWorkspaceSettings().redactFallback).toBe(value);
    }
  });

  it('refuses a value outside the vocabulary without throwing, and writes nothing', async () => {
    // A Server Action's parameter types are a claim its runtime never checks:
    // this arrives as JSON over a POST. A rejected promise here would be a
    // framework error page instead of a recoverable result — and the refusal
    // must not half-apply the rest of the payload either.
    await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: 'unchanged',
      historySyncConsent: 'unchanged',
      vaultConsent: 'off',
      vaultInlineReveal: 'masked',
      webChatCaptureConsent: 'unchanged',
      redactFallback: 'block',
      bodyRetention: { enabled: false, retainDays: 30 },
    });

    const res = await saveSettings({
      historicalAccess: 'full',
      modelJudgeConsent: 'unchanged',
      historySyncConsent: 'unchanged',
      vaultConsent: 'off',
      vaultInlineReveal: 'full',
      webChatCaptureConsent: 'unchanged',
      redactFallback: 'redact',
      bodyRetention: { enabled: false, retainDays: 30 },
    });

    expect(res.ok).toBe(false);
    const after = readWorkspaceSettings();
    expect(after.redactFallback).toBe('block');
    // The neighbouring edits in the same refused payload were not applied.
    expect(after.historicalAccess).toBe('session-only');
    expect(after.vaultInlineReveal).toBe('masked');
  });

  it('refuses a non-string, the shape the signature cannot enforce', async () => {
    const res = await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: 'unchanged',
      historySyncConsent: 'unchanged',
      vaultConsent: 'off',
      vaultInlineReveal: 'masked',
      webChatCaptureConsent: 'unchanged',
      redactFallback: 7,
      bodyRetention: { enabled: false, retainDays: 30 },
    });
    expect(res.ok).toBe(false);
    // WHICH guard refused it, not merely that something did. `ok: false` is
    // reachable from two: this field's shape schema rejecting a number, which
    // reaches `malformedInput` and names the key — or, if that schema were
    // widened, the domain enum failing later and reaching the shared refusal,
    // which names nothing. Asserting only `ok: false` holds under the mutation
    // this case's own title describes, so it has to name the field.
    expect(res.error).toContain('redactFallback');
  });
});

describe('saveSettings — vault-consent grant and revocation', () => {
  it("records a server-stamped grant at the current consent version on 'on'", async () => {
    const before = Date.now();
    const res = await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: 'revoked',
      historySyncConsent: 'revoked',
      vaultConsent: 'on',
      vaultInlineReveal: 'masked',
      webChatCaptureConsent: 'unchanged',
      redactFallback: 'warn',
      bodyRetention: { enabled: false, retainDays: 30 },
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
      webChatCaptureConsent: 'unchanged',
      redactFallback: 'warn',
      bodyRetention: { enabled: false, retainDays: 30 },
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
      webChatCaptureConsent: 'unchanged',
      redactFallback: 'warn',
      bodyRetention: { enabled: false, retainDays: 30 },
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
      webChatCaptureConsent: 'unchanged',
      redactFallback: 'warn',
      bodyRetention: { enabled: false, retainDays: 30 },
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
      webChatCaptureConsent: 'unchanged',
      redactFallback: 'warn',
      bodyRetention: { enabled: false, retainDays: 30 },
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
      webChatCaptureConsent: 'unchanged',
      redactFallback: 'warn',
      bodyRetention: { enabled: false, retainDays: 30 },
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
      webChatCaptureConsent: 'unchanged',
      redactFallback: 'warn',
      bodyRetention: { enabled: false, retainDays: 30 },
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
      webChatCaptureConsent: 'unchanged',
      redactFallback: 'warn',
      bodyRetention: { enabled: false, retainDays: 30 },
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
      webChatCaptureConsent: 'unchanged',
      redactFallback: 'warn',
      bodyRetention: { enabled: false, retainDays: 30 },
    });
    expect(rawSettings()).toContain('vaultConsent');

    const res = await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: 'revoked',
      historySyncConsent: 'revoked',
      vaultConsent: 'off',
      vaultInlineReveal: 'masked',
      webChatCaptureConsent: 'unchanged',
      redactFallback: 'warn',
      bodyRetention: { enabled: false, retainDays: 30 },
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
      webChatCaptureConsent: 'unchanged',
      redactFallback: 'warn',
      bodyRetention: { enabled: false, retainDays: 30 },
    });
    const before = rawSettings();

    const res = await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: 'revoked',
      historySyncConsent: 'revoked',
      vaultConsent: 'granted',
      vaultInlineReveal: 'masked',
      webChatCaptureConsent: 'unchanged',
      redactFallback: 'warn',
      bodyRetention: { enabled: false, retainDays: 30 },
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
      webChatCaptureConsent: 'unchanged',
      redactFallback: 'warn',
      bodyRetention: { enabled: false, retainDays: 30 },
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
      webChatCaptureConsent: 'unchanged',
      redactFallback: 'warn',
      bodyRetention: { enabled: false, retainDays: 30 },
    });
    expect(result.ok).toBe(true);
    const persisted = readWorkspaceSettings(join(home, '.aka'));
    expect(persisted.vaultConsent?.version).toBe(VAULT_CONSENT_VERSION);
    expect(persisted.vaultConsent?.acknowledgedAt).not.toBe('2020-01-01T00:00:00.000Z');
  });

  it('persists the retention horizon the user chose', async () => {
    const res = await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: 'revoked',
      historySyncConsent: 'revoked',
      vaultConsent: 'off',
      vaultInlineReveal: 'masked',
      webChatCaptureConsent: 'unchanged',
      redactFallback: 'warn',
      bodyRetention: { enabled: true, retainDays: 7 },
    });
    expect(res.ok).toBe(true);

    const saved = readWorkspaceSettings(join(home, '.aka')).bodyRetention;
    expect(saved).toEqual({ enabled: true, retainDays: 7 });
  });

  it('defaults the horizon to 30 days on a store that never set one', () => {
    // The default is the product's answer, not the form's — a machine that has
    // never opened Settings must already carry it.
    expect(readWorkspaceSettings(join(home, '.aka')).bodyRetention).toEqual({
      enabled: false,
      retainDays: 30,
    });
  });

  it('refuses a horizon outside the legal range rather than clamping it', async () => {
    // Clamping would expire a different set of bodies than the one asked for,
    // and expiry is not undoable. Both ends, and the non-integer case.
    for (const retainDays of [0, -1, 3651, 2.5]) {
      const res = await saveSettings({
        historicalAccess: 'session-only',
        modelJudgeConsent: 'revoked',
        historySyncConsent: 'revoked',
        vaultConsent: 'off',
        vaultInlineReveal: 'masked',
        webChatCaptureConsent: 'unchanged',
        redactFallback: 'warn',
        bodyRetention: { enabled: true, retainDays },
      });
      expect(res.ok, `retainDays ${String(retainDays)} was accepted`).toBe(false);
    }
    // Nothing was written by any of the refusals.
    expect(readWorkspaceSettings(join(home, '.aka')).bodyRetention.enabled).toBe(false);
  });

  it('refuses a malformed bodyRetention without throwing', async () => {
    for (const bodyRetention of [null, 'always', 42, { enabled: 'yes', retainDays: 30 }]) {
      const res = await saveSettings({
        historicalAccess: 'session-only',
        modelJudgeConsent: 'revoked',
        historySyncConsent: 'revoked',
        vaultConsent: 'off',
        vaultInlineReveal: 'masked',
        webChatCaptureConsent: 'unchanged',
        bodyRetention,
      });
      expect(res.ok).toBe(false);
      if (!res.ok) expect(res.error).toBeTruthy();
    }
  });

  it('persists a valid inline-reveal mode and rejects junk', async () => {
    const ok = await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: 'revoked',
      historySyncConsent: 'revoked',
      vaultConsent: 'off',
      vaultInlineReveal: 'full',
      webChatCaptureConsent: 'unchanged',
      redactFallback: 'warn',
      bodyRetention: { enabled: false, retainDays: 30 },
    });
    expect(ok.ok).toBe(true);
    expect(readWorkspaceSettings(join(home, '.aka')).vaultInlineReveal).toBe('full');

    const bad = await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: 'revoked',
      historySyncConsent: 'revoked',
      vaultConsent: 'off',
      vaultInlineReveal: 'loud',
      webChatCaptureConsent: 'unchanged',
      redactFallback: 'warn',
      bodyRetention: { enabled: false, retainDays: 30 },
    });
    expect(bad.ok).toBe(false);
  });
});

// The browser extension's web-chat capture writes down a class of thing nothing
// wrote down before — per-turn model and token metadata, the tool calls a reply
// made, and the reply's own text — so it carries its own versioned grant. This
// surface is where a person gives and withdraws it.
//
// Every case here uses a payload the ACTION was given, never a module constant
// standing in for one, and every one that asserts an absence carries a positive
// control beside it: a refused save leaves a seeded grant untouched too, which
// is exactly what several of these assert.
describe('saveSettings — the web-chat capture grant', () => {
  // The full payload with one field varied, so no case can pass because it
  // quietly omitted something.
  const payload = (
    webChatCaptureConsent: WebChatCaptureConsentChoice,
    overrides: Partial<Record<string, unknown>> = {},
  ): Record<string, unknown> => ({
    historicalAccess: 'session-only',
    modelJudgeConsent: 'unchanged',
    historySyncConsent: 'unchanged',
    vaultConsent: 'off',
    vaultInlineReveal: 'masked',
    webChatCaptureConsent,
    redactFallback: 'warn',
    bodyRetention: { enabled: false, retainDays: 30 },
    ...overrides,
  });

  const seed = async (block: unknown): Promise<void> => {
    const { applyOnboarding } = await import('@akasecurity/persistence');
    applyOnboarding({ webChatCapture: block as never }, join(home, '.aka'));
  };

  it("records a server-stamped grant at the current version on 'granted'", async () => {
    const before = Date.now();
    const res = await saveSettings(payload('granted'));
    expect(res).toEqual({ ok: true });

    const block = readWorkspaceSettings().webChatCapture;
    expect(block?.consent?.version).toBe(WEB_CHAT_CAPTURE_CONSENT_VERSION);
    // Minted by the action itself, so it lands inside this test's own window —
    // there is no input path for a caller to supply one.
    const acknowledged = Date.parse(block?.consent?.acknowledgedAt ?? '');
    expect(acknowledged).toBeGreaterThanOrEqual(before);
    expect(acknowledged).toBeLessThanOrEqual(Date.now());
    // And the two modes come out at the schema's own defaults rather than being
    // invented here: reply text only where a scan found something, no account
    // data.
    expect(block?.responses).toBe('with-findings');
    expect(block?.account).toBe(false);
  });

  it("keeps the original acknowledgedAt when 'granted' is saved again", async () => {
    await saveSettings(payload('granted'));
    const first = readWorkspaceSettings().webChatCapture?.consent;
    expect(first).toBeDefined();

    // Let the clock move, so a re-stamp could not coincide with the first.
    await new Promise((resolve) => setTimeout(resolve, 5));
    const res = await saveSettings(payload('granted', { vaultInlineReveal: 'off' }));
    expect(res).toEqual({ ok: true });

    const again = readWorkspaceSettings();
    expect(again.vaultInlineReveal).toBe('off'); // the unrelated edit landed
    expect(again.webChatCapture?.consent).toEqual(first);
  });

  it("drops the grant from the persisted file on 'revoked', keeping the modes", async () => {
    await saveSettings(payload('granted'));
    expect(rawSettings()).toContain('webChatCapture');

    const res = await saveSettings(payload('revoked'));
    expect(res).toEqual({ ok: true });

    // Gone from the raw JSON, not merely parsed away: the absence of the key is
    // what "not granted" means to every reader of this file.
    const stored = (JSON.parse(rawSettings()) as { webChatCapture?: Record<string, unknown> })
      .webChatCapture;
    expect(stored).toBeDefined();
    expect('consent' in (stored ?? {})).toBe(false);
    expect(readWorkspaceSettings().webChatCapture?.consent).toBeUndefined();
    // Revoking stops future recording; it says nothing about what is already
    // stored, and it must not reset the answers beside it either.
    expect(stored?.responses).toBe('with-findings');
  });

  it("leaves the grant and its acknowledgedAt alone on 'unchanged'", async () => {
    const granted = {
      responses: 'with-findings',
      account: false,
      consent: { acknowledgedAt: '2020-01-01T00:00:00.000Z', version: 1 },
    };
    await seed(granted);

    // A real unrelated edit, or this save had no cause to touch anything.
    const res = await saveSettings(payload('unchanged', { vaultInlineReveal: 'full' }));

    // THE POSITIVE CONTROL. Without it every assertion below is satisfied by a
    // save that was REFUSED, which leaves the seeded block untouched too.
    expect(res.ok).toBe(true);
    expect(readWorkspaceSettings().vaultInlineReveal).toBe('full');
    expect(readWorkspaceSettings().webChatCapture).toEqual(granted);
  });

  // The response mode and the account answer have no control on this page yet.
  // The action still has to write the whole block, because applyOnboarding
  // merges at the TOP level — so a block written without them REPLACES what was
  // there, and a machine set from anywhere else loses its answer to an unrelated
  // save here.
  it('carries the response mode and the account answer forward', async () => {
    await seed({
      responses: 'always',
      account: true,
      consent: { acknowledgedAt: '2020-01-01T00:00:00.000Z', version: 1 },
    });

    const res = await saveSettings(payload('unchanged', { historicalAccess: 'full' }));
    expect(res.ok).toBe(true);
    expect(readWorkspaceSettings().historicalAccess).toBe('full'); // positive control

    const block = readWorkspaceSettings().webChatCapture;
    expect(block?.responses).toBe('always');
    expect(block?.account).toBe(true);
  });

  it('refuses a payload that omits the answer, rather than reading it as a revocation', async () => {
    // The defect this field's requiredness exists to prevent: modelJudgeConsent
    // was optional and an absent field was read as `false`, so any caller that
    // simply did not mention it silently revoked a live grant.
    const granted = {
      responses: 'with-findings',
      account: false,
      consent: { acknowledgedAt: '2020-01-01T00:00:00.000Z', version: 1 },
    };
    await seed(granted);
    const before = rawSettings();

    const withoutTheAnswer = { ...payload('granted') };
    delete withoutTheAnswer.webChatCaptureConsent;
    const res = await saveSettings(withoutTheAnswer);

    expect(res.ok).toBe(false);
    expect(res.error).toContain('webChatCaptureConsent');
    // The grant is still there, byte for byte — an omitting caller revoked
    // nothing.
    expect(readWorkspaceSettings().webChatCapture).toEqual(granted);
    expect(rawSettings()).toBe(before);
  });

  it('rejects a client-supplied grant object — there is no input path for a timestamp', async () => {
    const forged = {
      acknowledgedAt: '2001-01-01T00:00:00.000Z',
      version: WEB_CHAT_CAPTURE_CONSENT_VERSION,
    };
    const res = await saveSettings(payload('granted', { webChatCaptureConsent: forged }));
    expect(res.ok).toBe(false);
    expect(res.error).toContain('webChatCaptureConsent');
    expect(() => rawSettings()).toThrow(); // nothing was ever written

    // And the contract itself admits only the three answers — no object shape
    // exists for a caller to smuggle a back-dated acknowledgement through. Read
    // off the SCHEMA type, not the action's parameter, which is `unknown` by
    // design so a non-object payload is refused rather than throwing.
    expectTypeOf<SaveSettingsInput['webChatCaptureConsent']>().toEqualTypeOf<
      'granted' | 'revoked' | 'unchanged'
    >();
  });

  it("saving 'granted' over a STALE grant re-stamps at the current version", async () => {
    await seed({
      responses: 'with-findings',
      account: false,
      // Any parseable version that is not the current one is stale; versions
      // below 1 fail the schema, so this simulates the other epoch upward.
      consent: {
        acknowledgedAt: '2020-01-01T00:00:00.000Z',
        version: WEB_CHAT_CAPTURE_CONSENT_VERSION + 1,
      },
    });

    const res = await saveSettings(payload('granted'));
    expect(res.ok).toBe(true);
    const consent = readWorkspaceSettings().webChatCapture?.consent;
    expect(consent?.version).toBe(WEB_CHAT_CAPTURE_CONSENT_VERSION);
    expect(consent?.acknowledgedAt).not.toBe('2020-01-01T00:00:00.000Z');
  });
});

// The grant is derived INSIDE applyOnboarding's write lock, over the settings
// that lock is about to merge into — not read out beforehand and carried in.
// The difference is invisible on a quiet machine and is the whole point on a
// busy one: the plugin's wizard, the CLI and this dashboard are three processes
// over one settings.json, so a value read before the lock can be written back
// over an answer another writer committed in between.
describe('saveSettings derives the web-chat grant inside the write lock', () => {
  const payload = (
    webChatCaptureConsent: WebChatCaptureConsentChoice,
  ): Record<string, unknown> => ({
    historicalAccess: 'session-only',
    modelJudgeConsent: 'unchanged',
    historySyncConsent: 'unchanged',
    vaultConsent: 'off',
    vaultInlineReveal: 'masked',
    webChatCaptureConsent,
    redactFallback: 'warn',
    bodyRetention: { enabled: false, retainDays: 30 },
  });

  it('does not resurrect a grant a concurrent revoke removed', async () => {
    const { applyOnboarding } = await import('@akasecurity/persistence');
    // A live grant, which is what the page rendered and what an 'unchanged'
    // save is about to preserve.
    applyOnboarding(
      {
        webChatCapture: {
          responses: 'with-findings',
          account: false,
          consent: {
            acknowledgedAt: '2020-01-01T00:00:00.000Z',
            version: WEB_CHAT_CAPTURE_CONSENT_VERSION,
          },
        },
      },
      join(home, '.aka'),
    );

    // The second writer, committing between the request being built and the
    // merge. A grant derived before the lock is the one above; a grant derived
    // inside it is this one — absent.
    beforeMerge.run = () => {
      applyOnboarding(
        { webChatCapture: { responses: 'with-findings', account: false } },
        join(home, '.aka'),
      );
    };

    const res = await saveSettings(payload('unchanged'));
    expect(res.ok).toBe(true);

    // The revocation stands. Reading the grant out before the call would carry
    // it across this write and reinstate consent the user had just withdrawn,
    // with the save reporting success either way.
    expect(readWorkspaceSettings().webChatCapture?.consent).toBeUndefined();
  });

  it('the same save DOES keep a grant nothing revoked', async () => {
    // The positive control: without it the case above is satisfied by an action
    // that drops the grant on every 'unchanged' save.
    const { applyOnboarding } = await import('@akasecurity/persistence');
    const consent = {
      acknowledgedAt: '2020-01-01T00:00:00.000Z',
      version: WEB_CHAT_CAPTURE_CONSENT_VERSION,
    };
    applyOnboarding(
      { webChatCapture: { responses: 'with-findings', account: false, consent } },
      join(home, '.aka'),
    );

    const res = await saveSettings(payload('unchanged'));
    expect(res.ok).toBe(true);
    expect(readWorkspaceSettings().webChatCapture?.consent).toEqual(consent);
  });
});
