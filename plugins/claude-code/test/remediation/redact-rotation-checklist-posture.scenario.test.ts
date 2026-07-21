/**
 * The standing-posture prompt wired into the built remediation entry's
 * 'Redact + rotation checklist' route (the post-redact leg), driven
 * from the BUILT `scripts/remediate.js` rather than a hand-assembled module
 * composition. A distinct route handler from 'Redact only'
 * (`redact-only-posture.scenario.test.ts`) — proving that branch's posture
 * insertion does not prove this one's.
 *
 * Reuses the production-entry seeding pattern: a real transcript artifact
 * leaking a live key, run through the real Yes-scan spine (intro -> onboard ->
 * backfill -> the calibration preview). The route is driven with a
 * caller-supplied cwd pointed at an isolated temporary git repository, so the
 * deliverable resolver — which resolves the repo root from the script's own
 * cwd — writes rotation-checklist.md there and never into the ai-tc working
 * tree, over ONE invocation carrying both the chosen option and the standing
 * posture level (never a second call re-running the redact route, which would
 * strike an already-redacted key and corrupt the count).
 *
 * A second describe block below co-exercises the M (transcripts) != N (keys)
 * property the module-seam fixture (`test/journey/remediation.journey.test.ts`)
 * proves — three real, distinct-provider keys spread across two real transcript
 * artifacts, seeded via `seedMultiKeyTranscripts` and run through the same real
 * Yes-scan spine — so the built-script posture leg and the multi-transcript
 * shape are proven together rather than only at separate seams.
 */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { openLocalDatabase } from '@akasecurity/persistence';
import { type BuiltinPolicyId, CalibrationFrame } from '@akasecurity/schema';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { readFrameJsonBlock } from '../../src/setup-frame-json.ts';
import {
  MULTI_KEY_GITHUB_KEY,
  MULTI_KEY_STRIPE_KEY,
  planPathFromPreview,
  SetupJourney,
  SURFACED_KEY,
} from '../journey/harness.ts';

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

describe("'Redact + rotation checklist' through the built remediate.js persists the standing posture", () => {
  let journey: SetupJourney;
  let transcriptPath: string;
  let preview: string;
  // The isolated temp git repository the built script is spawned with as its
  // cwd — the deliverable resolver's write target — never the ai-tc working tree.
  let repoRoot: string;

  beforeAll(() => {
    journey = new SetupJourney();
    transcriptPath = journey.seedTranscript();

    journey.intro();
    journey.onboardHistorical('full');
    const triage = journey.backfillTriage().stdout;
    preview = journey.applyPreview(triage).stdout;
    CalibrationFrame.parse(readFrameJsonBlock(preview));
    journey.applyConfirm(planPathFromPreview(preview));

    repoRoot = mkdtempSync(join(tmpdir(), 'aka-redact-checklist-repo-'));
    mkdirSync(join(repoRoot, '.git'));
  }, 120_000);

  afterAll(() => {
    rmSync(repoRoot, { recursive: true, force: true });
    journey.cleanup();
  });

  it('a redact route with no --posture fails loud — nothing persisted, no checklist, the key untouched', () => {
    const postureBefore = readPosture(journey.storeDir);

    const result = journey.remediationRoute(
      preview,
      'redact-rotation-checklist',
      undefined,
      repoRoot,
    );

    expect(result.status).not.toBe(0);
    expect(readFileSync(transcriptPath, 'utf8')).toContain(SURFACED_KEY);
    expect(readPosture(journey.storeDir)).toBe(postureBefore);
    expect(existsSync(join(repoRoot, 'rotation-checklist.md'))).toBe(false);
  });

  it('a redact route with a malformed --posture fails loud — nothing persisted, no checklist, the key untouched', () => {
    const postureBefore = readPosture(journey.storeDir);

    // A `--posture` value outside the palette is a wizard-wiring bug, not a
    // session fault: it must fail loud, never redact or draft the checklist.
    const result = journey.remediationRoute(
      preview,
      'redact-rotation-checklist',
      'bogus' as BuiltinPolicyId,
      repoRoot,
    );

    expect(result.status).not.toBe(0);
    expect(readFileSync(transcriptPath, 'utf8')).toContain(SURFACED_KEY);
    expect(readPosture(journey.storeDir)).toBe(postureBefore);
    expect(existsSync(join(repoRoot, 'rotation-checklist.md'))).toBe(false);
  });

  it('validates --posture before reading the frame — an unreadable frame with no --posture still fails loud', () => {
    const postureBefore = readPosture(journey.storeDir);

    // An unparseable frame AND a missing --posture: the posture guard fires
    // first (fail loud), never degrading to the fail-open frame-read note.
    const result = journey.remediationRoute(
      'not a calibration frame',
      'redact-rotation-checklist',
      undefined,
      repoRoot,
    );

    expect(result.status).not.toBe(0);
    expect(result.stdout).not.toContain('the surfaced findings were unavailable');
    expect(readFileSync(transcriptPath, 'utf8')).toContain(SURFACED_KEY);
    expect(readPosture(journey.storeDir)).toBe(postureBefore);
    expect(existsSync(join(repoRoot, 'rotation-checklist.md'))).toBe(false);
  });

  it('redacts the real leaked key, persists the chosen posture, and drafts the checklist at the isolated repo root — in one invocation, in order', () => {
    // Runs AFTER the missing --posture case above (which does not mutate), so
    // the raw key is still on disk.
    expect(readFileSync(transcriptPath, 'utf8')).toContain(SURFACED_KEY);
    const postureBefore = readPosture(journey.storeDir);
    expect(postureBefore).not.toBe('redact');

    const out = journey.remediationRoute(
      preview,
      'redact-rotation-checklist',
      'redact',
      repoRoot,
    ).stdout;

    // The posture confirmation prints, then the resolved summary. The redaction
    // is reported EXACTLY ONCE — inside the resolved summary, in its
    // transcript-count form — never repeated as a standalone confirmation ahead
    // of the posture line.
    const postureIdx = out.indexOf("✓ From now on, I'll treat secrets like these as redact.");
    const summaryIdx = out.indexOf('Leaked secrets — resolved');
    expect(postureIdx).toBeGreaterThanOrEqual(0);
    expect(summaryIdx).toBeGreaterThan(postureIdx);
    const redactionConfirmations = out.match(/✓ Redacted \d+ key/g) ?? [];
    expect(redactionConfirmations).toHaveLength(1);
    expect(out.indexOf('✓ Redacted 1 key across 1 transcript')).toBe(
      summaryIdx + 'Leaked secrets — resolved\n'.length,
    );

    const after = readFileSync(transcriptPath, 'utf8');
    expect(after).not.toContain(SURFACED_KEY);
    expect(after).toContain('[REDACTED:SECRET]');

    // The posture is durable — read on a fresh connection.
    expect(readPosture(journey.storeDir)).toBe('redact');

    // The deliverable landed at the isolated repo root the script was spawned
    // with as its cwd, never the ai-tc working tree.
    expect(out).toContain('✓ Redacted 1 key across 1 transcript');
    expect(out).toContain('✓ I drafted a rotation checklist for you (repo root).');
    const checklistPath = join(repoRoot, 'rotation-checklist.md');
    expect(existsSync(checklistPath)).toBe(true);
    expect(readFileSync(checklistPath, 'utf8')).not.toContain(SURFACED_KEY);
  });
});

describe("'Redact + rotation checklist' through the built remediate.js: the per-transcript count is independent of the redacted-key count", () => {
  let journey: SetupJourney;
  let transcriptPaths: readonly [string, string];
  let preview: string;
  // The isolated temp git repository the built script is spawned with as its
  // cwd — never the ai-tc working tree.
  let repoRoot: string;

  beforeAll(() => {
    journey = new SetupJourney();
    // Three real, distinct-provider keys spread across TWO transcript artifacts
    // (one holds two, the other one) — the same M (transcripts) != N (keys)
    // shape RemediationDrive.seedSecretLeaks() proves at the module seam, here
    // run through the real Yes-scan spine so it can drive the BUILT script.
    transcriptPaths = journey.seedMultiKeyTranscripts();

    journey.intro();
    journey.onboardHistorical('full');
    const triage = journey.backfillTriage().stdout;
    preview = journey.applyPreview(triage).stdout;
    CalibrationFrame.parse(readFrameJsonBlock(preview));
    journey.applyConfirm(planPathFromPreview(preview));

    repoRoot = mkdtempSync(join(tmpdir(), 'aka-redact-checklist-multi-key-repo-'));
    mkdirSync(join(repoRoot, '.git'));
  }, 120_000);

  afterAll(() => {
    rmSync(repoRoot, { recursive: true, force: true });
    journey.cleanup();
  });

  it('redacts all three real keys, reports a transcript count distinct from the key count, and persists the posture on a fresh connection', () => {
    const [transcriptA, transcriptB] = transcriptPaths;
    expect(readFileSync(transcriptA, 'utf8')).toContain(MULTI_KEY_STRIPE_KEY);
    expect(readFileSync(transcriptA, 'utf8')).toContain(SURFACED_KEY);
    expect(readFileSync(transcriptB, 'utf8')).toContain(MULTI_KEY_GITHUB_KEY);
    const postureBefore = readPosture(journey.storeDir);
    expect(postureBefore).not.toBe('redact');

    const out = journey.remediationRoute(
      preview,
      'redact-rotation-checklist',
      'redact',
      repoRoot,
    ).stdout;

    // N (3 keys) and M (2 transcripts) are independently real: three raw values
    // struck across exactly two artifacts, never N relabelled as M.
    expect(out).toContain('✓ Redacted 3 keys across 2 transcripts');
    expect(out).toContain('✓ I drafted a rotation checklist for you (repo root).');

    const afterA = readFileSync(transcriptA, 'utf8');
    const afterB = readFileSync(transcriptB, 'utf8');
    expect(afterA).not.toContain(MULTI_KEY_STRIPE_KEY);
    expect(afterA).not.toContain(SURFACED_KEY);
    expect(afterB).not.toContain(MULTI_KEY_GITHUB_KEY);
    expect(afterA).toContain('[REDACTED:SECRET]');
    expect(afterB).toContain('[REDACTED:SECRET]');

    // The posture is durable — read on a FRESH connection, so the write is not a
    // same-connection artifact.
    expect(readPosture(journey.storeDir)).toBe('redact');

    // The deliverable landed at the isolated repo root, never the ai-tc working
    // tree, and carries no raw key.
    const checklistPath = join(repoRoot, 'rotation-checklist.md');
    expect(existsSync(checklistPath)).toBe(true);
    const written = readFileSync(checklistPath, 'utf8');
    expect(written).not.toContain(MULTI_KEY_STRIPE_KEY);
    expect(written).not.toContain(SURFACED_KEY);
    expect(written).not.toContain(MULTI_KEY_GITHUB_KEY);
  });
});
