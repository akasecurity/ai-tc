import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { readWorkspaceSettings } from '@akasecurity/persistence';
import type { SaveSettingsInput } from '@akasecurity/schema';
import { VAULT_CONSENT_VERSION } from '@akasecurity/schema';
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

describe('saveSettings — vault-consent grant and revocation', () => {
  it("records a server-stamped grant at the current consent version on 'on'", async () => {
    const before = Date.now();
    const res = await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: false,
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

  it("keeps the original acknowledgedAt when 'on' is saved again", async () => {
    await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: false,
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
      modelJudgeConsent: false,
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
      modelJudgeConsent: false,
      vaultConsent: 'on',
      vaultInlineReveal: 'masked',
    });
    expect(rawSettings()).toContain('vaultConsent');

    const res = await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: false,
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
      modelJudgeConsent: false,
      vaultConsent: 'on',
      vaultInlineReveal: 'masked',
    });
    const before = rawSettings();

    const res = await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: false,
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
      modelJudgeConsent: false,
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
      modelJudgeConsent: false,
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
      modelJudgeConsent: false,
      vaultConsent: 'off',
      vaultInlineReveal: 'full',
    });
    expect(ok.ok).toBe(true);
    expect(readWorkspaceSettings(join(home, '.aka')).vaultInlineReveal).toBe('full');

    const bad = await saveSettings({
      historicalAccess: 'session-only',
      modelJudgeConsent: false,
      vaultConsent: 'off',
      vaultInlineReveal: 'loud',
    });
    expect(bad.ok).toBe(false);
  });
});
