/**
 * The standing-posture prompt wired into the built remediation entry's
 * 'Redact only' route, driven from the BUILT
 * `scripts/remediate.js` rather than a hand-assembled module composition.
 *
 * Reuses the production-entry seeding pattern (`remediation-production-entry.
 * journey.test.ts`): a real transcript artifact leaking a live key, run through
 * the real Yes-scan spine (intro -> onboard -> backfill -> the calibration
 * preview) so the captured frame text is the one the wizard actually threads
 * into remediate.js. 'Redact only' now REQUIRES a `--posture` argument; this
 * proves it redacts the real key AND persists the chosen level to the policies
 * store, read back on a fresh connection, and that a missing `--posture` fails
 * loud without redacting the key or touching the store.
 */
import { readFileSync } from 'node:fs';

import { openLocalDatabase } from '@akasecurity/persistence';
import { type BuiltinPolicyId, CalibrationFrame } from '@akasecurity/schema';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { renderRedactionConfirmation } from '../../src/remediation/render.ts';
import { readFrameJsonBlock } from '../../src/setup-frame-json.ts';
import { planPathFromPreview, SetupJourney, SURFACED_KEY } from '../journey/harness.ts';

// The 'secret' posture read straight from the policies store on a FRESH
// connection, so a same-connection write can never mask a missed persist.
function readPosture(storeDir: string): string | undefined {
  const db = openLocalDatabase(storeDir);
  try {
    return db.policies.getCategoryAction('secret');
  } finally {
    db.close();
  }
}

describe("'Redact only' through the built remediate.js persists the standing posture", () => {
  let journey: SetupJourney;
  let transcriptPath: string;
  let preview: string;

  beforeAll(() => {
    journey = new SetupJourney();
    transcriptPath = journey.seedTranscript();

    journey.intro();
    journey.onboardHistorical('full');
    journey.onboardModelJudge();
    const triage = journey.backfillTriage().stdout;
    preview = journey.applyPreview(triage).stdout;
    CalibrationFrame.parse(readFrameJsonBlock(preview));
    journey.applyConfirm(planPathFromPreview(preview));
  }, 120_000);

  afterAll(() => {
    journey.cleanup();
  });

  it('a redact route with no --posture fails loud — nothing persisted, the key untouched', () => {
    const postureBefore = readPosture(journey.storeDir);

    const result = journey.remediationRoute(preview, 'redact-only');

    expect(result.status).not.toBe(0);
    expect(result.stdout).not.toContain('✓ Redacted');
    expect(result.stdout).not.toContain("Set 'secret' posture");
    expect(readFileSync(transcriptPath, 'utf8')).toContain(SURFACED_KEY);
    expect(readPosture(journey.storeDir)).toBe(postureBefore);
  });

  it('a redact route with a malformed --posture fails loud — nothing persisted, the key untouched', () => {
    const postureBefore = readPosture(journey.storeDir);

    // A `--posture` value outside the palette is a wizard-wiring bug, not a
    // session fault: it must fail loud, never redact.
    const result = journey.remediationRoute(preview, 'redact-only', 'bogus' as BuiltinPolicyId);

    expect(result.status).not.toBe(0);
    expect(result.stdout).not.toContain('✓ Redacted');
    expect(result.stdout).not.toContain("Set 'secret' posture");
    expect(readFileSync(transcriptPath, 'utf8')).toContain(SURFACED_KEY);
    expect(readPosture(journey.storeDir)).toBe(postureBefore);
  });

  it('validates --posture before reading the frame — an unreadable frame with no --posture still fails loud', () => {
    const postureBefore = readPosture(journey.storeDir);

    // An unparseable frame AND a missing --posture: the posture guard fires
    // first (fail loud), never degrading to the fail-open frame-read note.
    const result = journey.remediationRoute('not a calibration frame', 'redact-only');

    expect(result.status).not.toBe(0);
    expect(result.stdout).not.toContain('the surfaced findings were unavailable');
    expect(readFileSync(transcriptPath, 'utf8')).toContain(SURFACED_KEY);
    expect(readPosture(journey.storeDir)).toBe(postureBefore);
  });

  it('redacts the real leaked key and persists the chosen posture, read back on a fresh connection', () => {
    // Runs AFTER the missing-posture negative case above, which does not
    // mutate, so the raw key is still on disk here.
    expect(readFileSync(transcriptPath, 'utf8')).toContain(SURFACED_KEY);
    const postureBefore = readPosture(journey.storeDir);

    const out = journey.remediationRoute(preview, 'redact-only', 'redact').stdout;

    expect(out).toContain(renderRedactionConfirmation(1));
    expect(out).toContain("✓ From now on, I'll treat secrets like these as redact.");
    const after = readFileSync(transcriptPath, 'utf8');
    expect(after).not.toContain(SURFACED_KEY);
    expect(after).toContain('[REDACTED:SECRET]');

    // Persisted durably to the policies store — an observable change from the
    // seeded baseline, read on a FRESH connection rather than the one the
    // write landed on.
    expect(postureBefore).not.toBe('redact');
    expect(readPosture(journey.storeDir)).toBe('redact');
  });
});
