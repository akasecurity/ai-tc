/**
 * The two-leg scan-consent contract over the
 * simplified single-question consent surface, proven end-to-end against the REAL
 * shipped scripts (onboard.js, backfill.js) in a throwaway ~/.aka home.
 *
 * Leg 1 (Yes, scan): `onboard.js --historical full` records a consent that is
 * identical — modulo the onboardedAt stamp — to what the prior historical-review
 * flow recorded. Both go through the same applyOnboarding writer and persist the
 * single historicalAccess='full' grant with no additional or broadened scope
 * field; the grant is revocable at the same onboarding surface.
 *
 * Leg 2 (Not now): with no 'full' grant recorded, backfill.js refuses to read.
 * Its consent gate takes the skip branch, no transcript is scanned, and the
 * machine channel reports an intentional zero-finding skip — so declining really
 * means declining (zero historical access).
 *
 * Hermetic: every write lands under a temp home; no developer store is touched.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { applyOnboarding, readWorkspaceSettings } from '@akasecurity/persistence';
import { WorkspaceSettings } from '@akasecurity/schema';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { SetupJourney } from './journey/harness.ts';

// The onboardedAt stamp is a wall-clock time that differs between two runs, so
// strip it before comparing the recorded consent scope across surfaces.
function consentScope(settings: WorkspaceSettings): Omit<WorkspaceSettings, 'onboardedAt'> {
  const scope = { ...settings };
  delete scope.onboardedAt;
  return scope;
}

describe('Leg 1 — "Yes, scan" records the historical-review consent without broadening it', () => {
  let journey: SetupJourney;
  let baselineHome: string;
  let onboardStdout: string;
  // The consent the single-question surface persisted, read back from disk.
  let persistedRaw: Record<string, unknown>;
  let persisted: WorkspaceSettings;
  // What the prior historical-review flow records for the same 'full' answer:
  // the same applyOnboarding writer, into an independent temp home.
  let baseline: WorkspaceSettings;

  beforeAll(() => {
    journey = new SetupJourney();
    onboardStdout = journey.onboardHistorical('full').stdout;
    persistedRaw = JSON.parse(readFileSync(journey.settingsPath, 'utf8')) as Record<
      string,
      unknown
    >;
    persisted = WorkspaceSettings.parse(persistedRaw);

    baselineHome = mkdtempSync(join(tmpdir(), 'aka-consent-baseline-'));
    baseline = applyOnboarding({ historicalAccess: 'full' }, join(baselineHome, '.aka'));
  });

  afterAll(() => {
    journey.cleanup();
    rmSync(baselineHome, { recursive: true, force: true });
  });

  it('records the historicalAccess=full grant', () => {
    expect(persisted.historicalAccess).toBe('full');
    expect(onboardStdout).toContain('historicalAccess=full');
  });

  it('records a consent scope provably identical to the prior historical-review flow', () => {
    expect(consentScope(persisted)).toEqual(consentScope(baseline));
  });

  it('persists no scope field beyond the schema — nothing broadened', () => {
    // The persisted object carries exactly the WorkspaceSettings fields, so the
    // single-question surface grants no extra scope key. historicalAccess is the
    // sole consent-bearing field; the schema encodes the one-time/revocable
    // semantics in that enum value, not in any additional marker.
    expect(Object.keys(persistedRaw).sort()).toEqual(Object.keys(WorkspaceSettings.shape).sort());
  });

  it('leaves the full-access grant revocable at the same onboarding surface', () => {
    journey.onboardHistorical('session-only');
    expect(readWorkspaceSettings(join(journey.home, '.aka')).historicalAccess).toBe('session-only');
  });
});

describe('Leg 2 — "Not now" performs zero historical access', () => {
  let journey: SetupJourney;
  let backfillHuman: string;
  let backfillMachine: string;

  beforeAll(() => {
    journey = new SetupJourney();
    // There IS prior history to read, so "no read" is a real refusal rather than
    // an empty directory. The Not-now leg never grants 'full', so it stays unread.
    journey.seedTranscript();
    backfillHuman = journey.backfill().stdout;
    backfillMachine = journey.backfillTriage().stdout;
  });

  afterAll(() => {
    journey.cleanup();
  });

  it('leaves historical consent unset — never full', () => {
    // The user granted no historical access, so no settings.json consent was
    // written; the fail-open reader resolves the default, which is not 'full'.
    expect(existsSync(journey.settingsPath)).toBe(false);
    expect(readWorkspaceSettings(join(journey.home, '.aka')).historicalAccess).not.toBe('full');
  });

  it('backfill takes the consent-gate skip branch and reads no transcript', () => {
    expect(backfillHuman).toBe('Historical scan skipped — full review was not granted.\n');
    // The scan-complete summary is the only output a real read produces; its
    // absence witnesses that the transcript scan was never reached.
    expect(backfillHuman).not.toContain('Historical scan complete');
    expect(backfillHuman).not.toContain('Scanned');
  });

  it('the machine channel reports an intentional zero-finding skip, not a scan', () => {
    expect(JSON.parse(backfillMachine.trim())).toEqual({
      done: true,
      count: 0,
      status: 'skipped:no-consent',
    });
  });
});
