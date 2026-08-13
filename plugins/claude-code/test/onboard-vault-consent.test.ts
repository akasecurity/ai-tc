/**
 * The vault-consent grant/revoke contract on the onboarding writer, proven
 * end-to-end against the REAL shipped script (onboard.js) in a throwaway ~/.aka
 * home.
 *
 * Grant: `onboard.js --vault-consent grant` records a VaultConsent stamped by
 * the writer itself — the flag carries no timestamp or version, so a caller can
 * never supply either. Revoke: the vaultConsent key is removed from the
 * persisted file entirely, so future vaulting stops; entries already stored are
 * untouched (purging the vault is the eraser).
 *
 * Hermetic: every write lands under a temp home; no developer store is touched.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { isVaultConsentValid, VAULT_CONSENT_VERSION, WorkspaceSettings } from '@akasecurity/schema';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PLUGIN_ROOT, SetupJourney } from './journey/harness.ts';

function readRawSettings(journey: SetupJourney): Record<string, unknown> {
  return JSON.parse(readFileSync(journey.settingsPath, 'utf8')) as Record<string, unknown>;
}

describe('grant — records a writer-stamped VaultConsent', () => {
  let journey: SetupJourney;
  let stdout: string;
  let beforeMs: number;
  let afterMs: number;
  let persisted: WorkspaceSettings;

  beforeAll(() => {
    journey = new SetupJourney();
    beforeMs = Date.now();
    stdout = journey.onboardVaultConsent('grant').stdout;
    afterMs = Date.now();
    persisted = WorkspaceSettings.parse(readRawSettings(journey));
  });

  afterAll(() => {
    journey.cleanup();
  });

  it('persists a vaultConsent the schema validates as a current grant', () => {
    expect(persisted.vaultConsent?.version).toBe(VAULT_CONSENT_VERSION);
    expect(isVaultConsentValid(persisted.vaultConsent)).toBe(true);
  });

  it('stamps a parseable ISO acknowledgedAt inside the run window', () => {
    const acknowledgedAt = persisted.vaultConsent?.acknowledgedAt;
    expect(acknowledgedAt).toBeDefined();
    const stampedMs = Date.parse(acknowledgedAt ?? '');
    expect(Number.isNaN(stampedMs)).toBe(false);
    expect(stampedMs).toBeGreaterThanOrEqual(beforeMs);
    expect(stampedMs).toBeLessThanOrEqual(afterMs);
  });

  it('confirms on stdout in plain language', () => {
    expect(stdout).toContain(
      'Okay — detected secrets will be kept recoverable in your local encrypted vault.',
    );
  });

  it('changes neither historicalAccess nor policy — the fields are independent', () => {
    // The grant answer carries only vaultConsent; the other consent/preference
    // fields stay at whatever the merge read (here: never-set defaults).
    const defaults = WorkspaceSettings.parse({});
    expect(persisted.historicalAccess).toBe(defaults.historicalAccess);
    expect(persisted.policy).toBe(defaults.policy);
  });

  it('leaves a previously recorded historical grant untouched', () => {
    const separate = new SetupJourney();
    try {
      separate.onboardHistorical('full');
      separate.onboardVaultConsent('grant');
      const after = WorkspaceSettings.parse(readRawSettings(separate));
      expect(after.historicalAccess).toBe('full');
      expect(isVaultConsentValid(after.vaultConsent)).toBe(true);
    } finally {
      separate.cleanup();
    }
  });
});

describe('grant — the stamp cannot be smuggled in from the caller', () => {
  let journey: SetupJourney;
  let beforeMs: number;
  let afterMs: number;

  beforeAll(() => {
    journey = new SetupJourney();
  });

  afterAll(() => {
    journey.cleanup();
  });

  it('ignores extra args carrying an attacker-chosen timestamp or version', () => {
    // The flag surface has no timestamp/version input at all — these extra args
    // fall through the parser as unknown flags. Prove it by asserting the
    // persisted stamp is the writer's own (inside the run window), not 1999.
    beforeMs = Date.now();
    execFileSync(
      process.execPath,
      [
        join(PLUGIN_ROOT, 'scripts', 'onboard.js'),
        '--vault-consent',
        'grant',
        '--acknowledgedAt',
        '1999-01-01T00:00:00.000Z',
        '--version',
        '999',
      ],
      {
        env: { HOME: journey.home, USERPROFILE: journey.home },
        encoding: 'utf8',
      },
    );
    afterMs = Date.now();

    const persisted = WorkspaceSettings.parse(readRawSettings(journey));
    expect(persisted.vaultConsent?.version).toBe(VAULT_CONSENT_VERSION);
    const stampedMs = Date.parse(persisted.vaultConsent?.acknowledgedAt ?? '');
    expect(stampedMs).toBeGreaterThanOrEqual(beforeMs);
    expect(stampedMs).toBeLessThanOrEqual(afterMs);
  });
});

describe('revoke — clears the grant without touching anything else', () => {
  let journey: SetupJourney;

  beforeAll(() => {
    journey = new SetupJourney();
  });

  afterAll(() => {
    journey.cleanup();
  });

  it('after a grant, removes the vaultConsent key from the persisted file', () => {
    journey.onboardVaultConsent('grant');
    expect(readRawSettings(journey)).toHaveProperty('vaultConsent');

    const result = journey.onboardVaultConsent('revoke');
    expect(result.status).toBe(0);
    const raw = readRawSettings(journey);
    expect('vaultConsent' in raw).toBe(false);
    expect(isVaultConsentValid(undefined)).toBe(false);
    expect(WorkspaceSettings.parse(raw).vaultConsent).toBeUndefined();
  });

  it('states the revocation boundary on stdout — stored entries stay until purge', () => {
    const result = journey.onboardVaultConsent('revoke');
    expect(result.stdout).toContain('new detections will no longer be vaulted');
    expect(result.stdout).toContain('Anything already stored stays until you purge the vault.');
  });
});

describe('revoke — when no grant was ever recorded', () => {
  let journey: SetupJourney;

  beforeAll(() => {
    journey = new SetupJourney();
  });

  afterAll(() => {
    journey.cleanup();
  });

  it('exits 0, persists no vaultConsent key, and changes nothing else', () => {
    const result = journey.onboardVaultConsent('revoke');
    expect(result.status).toBe(0);
    const raw = readRawSettings(journey);
    expect('vaultConsent' in raw).toBe(false);
    // Beyond the onboardedAt completion stamp the write is a no-op merge —
    // every other field still parses to its never-set default.
    const persisted = WorkspaceSettings.parse(raw);
    const defaults = WorkspaceSettings.parse({});
    expect({ ...persisted, onboardedAt: undefined }).toEqual(defaults);
  });
});

describe('an invalid --vault-consent value', () => {
  let journey: SetupJourney;

  beforeAll(() => {
    journey = new SetupJourney();
  });

  afterAll(() => {
    journey.cleanup();
  });

  it('fails with the expected message and leaves the settings file untouched', () => {
    journey.onboardVaultConsent('grant');
    const bytesBefore = readFileSync(journey.settingsPath, 'utf8');

    const result = journey.onboardVaultConsent('maybe' as 'grant');
    expect(result.status).toBe(1);
    expect(result.stdout).toContain('invalid --vault-consent "maybe" (expected grant or revoke)');
    expect(readFileSync(journey.settingsPath, 'utf8')).toBe(bytesBefore);
  });

  it('writes no settings file at all when none existed', () => {
    const fresh = new SetupJourney();
    try {
      const result = fresh.onboardVaultConsent('nonsense' as 'grant');
      expect(result.status).toBe(1);
      expect(existsSync(fresh.settingsPath)).toBe(false);
    } finally {
      fresh.cleanup();
    }
  });
});
