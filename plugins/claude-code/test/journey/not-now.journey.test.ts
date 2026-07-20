/**
 * /aka:setup calibration wizard, Not-now branch, proven end-to-end against the
 * REAL script chain — the analog of yes-scan.journey.test.ts for the Not-now branch.
 *
 * This owns no behavior — the underlying units do — it just runs the shipped
 * Not-now scripts in wizard-step order and asserts each frame's rendered output
 * and the final store state. The Not-now leg grants ZERO historical access, so
 * unlike the Yes-scan spine it runs no backfill/scan even though a transcript is
 * seeded — the history is there to be ignored, which is what makes the empty
 * final store a real proof of non-ingestion. The chain is intro.js (0.1) →
 * start-light.js (0.3b) → onboard.js --floor (0.5, the
 * start-light posture write). The chosen posture lands in the policies store
 * (~/.aka/data/aka.db), where onboard.ts writes it — settings.json is never
 * touched on the floor-only path, so no historical-review consent is recorded.
 *
 * The applying-frame confirmation is the Not-now analog of the Yes-path
 * apply-suppressions --confirmed line: it reports only the categories tuned (no
 * suppression pass ran, no scan produced counts), so it carries neither a
 * 'routine dismissed' count nor the calibration headline.
 *
 * Frame 0.6 (firstrun.js, the no-scan installed summary) is not yet asserted
 * here — its honest empty-state degradation is not implemented on this spine
 * (see the TODO below). These e2e assertions stop at the applying frame 0.5.
 */
import { existsSync, readFileSync } from 'node:fs';

import { openLocalDatabase } from '@akasecurity/persistence';
import { severityFloorPosture } from '@akasecurity/plugin-sdk';
import { builtinPolicyToAction, DetectionCategory } from '@akasecurity/schema';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { RE_TUNE_HINT, renderCategoriesTuned, renderPostureGrid } from '../../src/render.ts';
import { readFrameJsonBlock } from '../../src/setup-frame-json.ts';
import { PLUGIN_ROOT, SetupJourney } from './harness.ts';

// The real installed plugin version, so the provenance assertion tracks the
// shipped manifest instead of a hardcoded literal.
const MANIFEST = JSON.parse(readFileSync(`${PLUGIN_ROOT}/.claude-plugin/plugin.json`, 'utf8')) as {
  version: string;
};

// Reading the per-category posture the floor write established, straight from the
// store the scripts wrote to (the honest final-state seam — the same read the
// Yes-scan journey uses).
function readPosture(storeDir: string): Record<string, string | undefined> {
  const db = openLocalDatabase(storeDir);
  try {
    const out: Record<string, string | undefined> = {};
    for (const category of DetectionCategory.options) {
      out[category] = db.policies.getCategoryAction(category);
    }
    return out;
  } finally {
    db.close();
  }
}

describe('Not-now start-light path, end-to-end', () => {
  let journey: SetupJourney;
  // Frame outputs captured once across the whole Not-now spine run.
  let intro: string;
  let startLight: string;
  let applied: string;

  beforeAll(() => {
    journey = new SetupJourney();
    // Seed a real transcript on disk BEFORE the spine runs. The Not-now leg
    // declines the scan, so this history exists but must never be read — an empty
    // store at the end is then proof of non-ingestion, not of an empty home.
    journey.seedTranscript();

    // Kickoff intro (0.1).
    intro = journey.intro().stdout;

    // Start-light card (0.3b) — the full 8×4 default posture matrix. Reads no store,
    // records no consent.
    startLight = journey.startLight().stdout;

    // Apply the chosen posture (0.5). Keeping the default posture is the --floor
    // write — NO backfill, NO applyPreview, NO suppression pass.
    applied = journey.onboardStartLight().stdout;

    // TODO: assert frame 0.6 (firstrun.js) no-scan empty-state landing here — the
    // honest degraded stats/handoff copy rendered over a store with no scanned
    // findings. Not yet implemented on this spine.
  }, 120_000);

  afterAll(() => {
    journey.cleanup();
  });

  it('intro: renders the canonical identity and the version·repo provenance line', () => {
    expect(intro).toContain('AKA Security');
    expect(intro).toContain(`v${MANIFEST.version} · github.com/akasecurity/ai-tc`);
  });

  it('start-light (0.3b): heading, the 8×4 default posture grid, per-pack rationale, and the re-tune hint', () => {
    // The Not-now branch's start-light card — the copy is unit-owned in
    // render.test.ts / start-light.test.ts; this asserts the frame renders it
    // end-to-end from the built script.
    expect(startLight).toContain('Start light — set your packs');
    // The full 8×4 default posture matrix, rendered from the severity-floor defaults.
    expect(startLight).toContain(renderPostureGrid(severityFloorPosture()));
    // Per-pack rationale — a shipped reason line for each pack, never omitted.
    expect(startLight).toContain('live credentials are the costliest thing to leak');
    // The frame closes with the re-tune hint.
    expect(startLight).toContain(RE_TUNE_HINT);
  });

  it('applying (0.5): honest no-scan confirmation — categories tuned, no routine/calibration counts', () => {
    // The applying confirmation from onboard.js --floor — the Not-now analog of
    // the Yes-path apply-suppressions --confirmed line. The tuned count is derived
    // from the posture the run actually wrote (read back from the store), so the
    // assertion carries no hardcoded count.
    const categoriesTuned = Object.values(readPosture(journey.storeDir)).filter(Boolean).length;
    expect(applied).toContain(renderCategoriesTuned(categoriesTuned));
    // No suppression pass ran, so there is no dismissed count to report.
    expect(applied).not.toContain('routine dismissed');
    // No scan ran, so the calibration headline and its counts never appear.
    expect(applied).not.toContain('Calibrated.');
    expect(applied).not.toContain('notifications');
  });

  it('frame JSON: no calibration frame is emitted on the Not-now spine through 0.5', () => {
    // The frame JSON is emitted only where a frame produces it. The Not-now frames
    // through the applying frame 0.5 emit none (no scan, no preview) — the
    // SetupHandoffOffer payload at frame 0.6 is not yet asserted here.
    expect(readFrameJsonBlock(intro)).toBeUndefined();
    expect(readFrameJsonBlock(startLight)).toBeUndefined();
    expect(readFrameJsonBlock(applied)).toBeUndefined();
  });

  it('final store: the policies store holds the default posture for all 8 packs', () => {
    // The floor write establishes the full 8-pack default posture in the policies
    // store (aka.db), where onboard.ts writes it. The store records the
    // enforcement action, so each pack's floor level maps through
    // builtinPolicyToAction (warn→'warn', monitor→'log').
    const posture = readPosture(journey.storeDir);
    const floor = severityFloorPosture();
    for (const category of DetectionCategory.options) {
      expect(posture[category], `posture for ${category}`).toBe(
        builtinPolicyToAction(floor[category]),
      );
    }
  });

  it('zero historical read: no scan side effects landed and no full-access consent was recorded', async () => {
    // A transcript WAS seeded, but historicalAccess was never set to 'full', so
    // backfill's gate would refuse — and no backfill/scan ran here at all. The
    // store must therefore carry no scanned findings and no suppression rows
    // despite there being real history on disk to find.
    const db = openLocalDatabase(journey.storeDir);
    try {
      expect(await db.findings.recentFindings()).toHaveLength(0);
      expect(await db.exceptions.list()).toHaveLength(0);
    } finally {
      db.close();
    }
    // The Not-now floor path records no historical-review consent — settings.json
    // is never written on this leg, so 'full' access was never granted.
    if (existsSync(journey.settingsPath)) {
      const settings = JSON.parse(readFileSync(journey.settingsPath, 'utf8')) as {
        historicalAccess?: string;
      };
      expect(settings.historicalAccess).not.toBe('full');
    }
  });
});
