/**
 * /aka:setup calibration wizard, Yes-scan happy path, proven end-to-end against
 * the REAL script chain.
 *
 * This owns no behavior — the underlying units do — it just runs the shipped
 * scripts in wizard-step order and asserts each step's rendered output, the frame
 * JSON, and the final store/settings state. Of note, the Yes-path applies the
 * confirmed calibration through the ACTUAL writer, apply-suppressions.js
 * --confirmed (not onboard.js --posture): that is the spine that establishes the
 * floor-overlaid 8-pack (reviewed-evidence overwrite + severity-floor fill-gaps)
 * and emits the '8 categories tuned · N routine dismissed'
 * confirmation. The AskUserQuestion issuances (the consent question and the
 * dashboard handoff) are prompt-authored setup.md territory this script-chain
 * harness cannot observe; it asserts the offer PAYLOAD instead.
 */
import { readFileSync } from 'node:fs';

import { openLocalDatabase } from '@akasecurity/persistence';
import { CalibrationFrame, DetectionCategory, SetupHandoffOffer } from '@akasecurity/schema';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { readFrameJsonBlock } from '../../src/setup-frame-json.ts';
import {
  planPathFromPreview,
  PLUGIN_ROOT,
  ROUTINE_KEY,
  SetupJourney,
  SURFACED_KEY,
} from './harness.ts';

// The real installed plugin version, so the provenance assertion tracks the
// shipped manifest instead of a hardcoded literal.
const MANIFEST = JSON.parse(readFileSync(`${PLUGIN_ROOT}/.claude-plugin/plugin.json`, 'utf8')) as {
  version: string;
};

// Reading the per-category posture the confirm write established, straight from
// the store the scripts wrote to (the honest final-state seam).
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

describe('Yes-scan happy path, end-to-end', () => {
  let journey: SetupJourney;
  // Frame outputs captured once across the whole spine run.
  let intro: string;
  let preview: string;
  let confirm: string;
  let firstRun: string;
  let calibrationFrame: CalibrationFrame;

  beforeAll(() => {
    journey = new SetupJourney();
    journey.seedTranscript();

    // Kickoff intro.
    intro = journey.intro().stdout;

    // Consent (side effect) — record the Yes-scan consent.
    journey.onboardHistorical('full');

    // Backfill triage stream → calibration preview (judge stubbed).
    const triage = journey.backfillTriage().stdout;
    preview = journey.applyPreview(triage).stdout;

    const frame = CalibrationFrame.parse(readFrameJsonBlock(preview));
    calibrationFrame = frame;

    // Apply the confirmed plan through the real writer.
    confirm = journey.applyConfirm(planPathFromPreview(preview)).stdout;

    // Installed summary, carrying the surfaced count from the calibration preview.
    firstRun = journey.firstRun(frame.counts.important).stdout;
  }, 120_000);

  afterAll(() => {
    journey.cleanup();
  });

  it('intro: renders the canonical identity and the version·repo provenance line', () => {
    expect(intro).toContain('AKA Security');
    expect(intro).toContain('We secure agent harnesses at the source.');
    expect(intro).toContain(`v${MANIFEST.version} · github.com/akasecurity/ai-tc`);
    // No provenance badge yet — that lands with the signature check.
    expect(intro).not.toContain('verified');
  });

  it('intro: the intro script also emits the "what I do" calibration card', () => {
    // The kickoff and "what I do" cards are printed by the same
    // intro run, back-to-back, before the scan offer. This asserts the wiring
    // (the copy itself is unit-owned in render.test.ts).
    expect(intro).toContain('I watch out for Claude as it works.');
    expect(intro).toContain("let's calibrate your notifications based on what Claude's been up to");
  });

  it('preview: leads with the real-count headline and the condensed recommended posture', () => {
    // The calibrated-result card the wizard shows the user — the counts are the
    // real scan's (two seeded keys: one surfaced, one routine FP), and the kind
    // parenthetical names the surfaced category's kind.
    expect(preview).toContain('Calibrated. 2 notifications, 1 important.');
    expect(preview).toContain('1 routine, 1 that matter (live keys)');
    // The condensed recommended view lists every pack with its recommended
    // level (the evidence pack took 'warn'); a full 8×4 level grid is the
    // start-light branch's, not the spine's.
    for (const category of DetectionCategory.options) {
      expect(preview).toContain(category);
    }
    expect(preview).toMatch(/secret\s+warn/);
  });

  it('preview: the backfill records real findings and the calibration preview never leaks raw keys', () => {
    // The preview's frame JSON validates as a CalibrationFrame and its counts come
    // from the real scan (two seeded keys: one surfaced, one routine FP).
    expect(calibrationFrame.counts).toEqual({ total: 2, important: 1, routine: 1 });
    expect(calibrationFrame.surfacedCategories).toEqual(['secret']);
    // The retroactive scan reads at-rest history, so the kind is not an egress leak.
    expect(calibrationFrame.findingKinds).toContainEqual({
      category: 'secret',
      count: 2,
      egress: false,
    });
    // The previewed posture is the full recommended 8-pack, so the
    // confirm write has all 8 to establish.
    expect(Object.keys(calibrationFrame.posture).sort()).toEqual(
      [...DetectionCategory.options].sort(),
    );
    // Nothing raw crosses the isolated-judge boundary into the preview stdout.
    expect(preview).not.toContain(SURFACED_KEY);
    expect(preview).not.toContain(ROUTINE_KEY);
  });

  it('apply: the ACTUAL writer confirms the floor-overlaid 8-pack', () => {
    // The applying confirmation from apply-suppressions.js --confirmed — the
    // spine writer, not onboard.js --posture.
    expect(confirm).toContain('✓ 8 categories tuned');
    expect(confirm).toContain('✓ 1 routine dismissed');
    expect(confirm).toMatch(/Ready:/);
  });

  it('final store: settings.json records the consent and all 8 packs hold a valid posture', () => {
    const settings = JSON.parse(readFileSync(journey.settingsPath, 'utf8')) as {
      historicalAccess?: string;
    };
    expect(settings.historicalAccess).toBe('full');

    const posture = readPosture(journey.storeDir);
    // Every pack got a posture (the evidence pack + the severity-floor fill).
    for (const category of DetectionCategory.options) {
      expect(posture[category], `posture for ${category}`).toBeTruthy();
    }
    // The reviewed evidence pack took its judged action; the DB stores the palette
    // level verbatim ('warn').
    expect(posture.secret).toBe('warn');
  });

  it('final store: the routine false positive dismissed on apply is a real suppression row', async () => {
    const db = openLocalDatabase(journey.storeDir);
    try {
      const active = await db.exceptions.list();
      expect(active).toHaveLength(1);
      expect(active[0]?.createdVia).toBe('setup-triage');
      expect(active[0]?.category).toBe('secret');
    } finally {
      db.close();
    }
  });

  it('installed summary: the installed card and the handoff-offer payload carry the real surfaced count', () => {
    expect(firstRun).toContain('✓ AKA Security installed');
    const offer = SetupHandoffOffer.parse(readFrameJsonBlock(firstRun));
    expect(offer.worthALook).toBe(1);
    expect(offer.options.map((o) => o.id)).toEqual(['open-dashboard', 'not-now']);
  });
});

describe('no-downgrade invariant end-to-end', () => {
  let journey: SetupJourney;

  beforeAll(() => {
    journey = new SetupJourney();
    journey.seedTranscript();

    journey.intro();
    journey.onboardHistorical('full');
    // The user had hardened an UNREVIEWED floor pack (code_context) out of band
    // before the scan. The evidence only covers `secret`, so the confirm write's
    // severity-floor fill must leave code_context alone — never reset it to the
    // weak floor.
    journey.onboardPosture({ code_context: 'block' });

    const triage = journey.backfillTriage().stdout;
    const preview = journey.applyPreview(triage).stdout;
    journey.applyConfirm(planPathFromPreview(preview));
  }, 120_000);

  afterAll(() => {
    journey.cleanup();
  });

  it('a pre-existing hardened floor pack survives a Yes-scan confirm', () => {
    const posture = readPosture(journey.storeDir);
    // Preserved, not downgraded to the floor.
    expect(posture.code_context).toBe('block');
    // The reviewed evidence pack still took its judged action, and all 8 packs hold.
    expect(posture.secret).toBe('warn');
    for (const category of DetectionCategory.options) {
      expect(posture[category], `posture for ${category}`).toBeTruthy();
    }
  });
});
