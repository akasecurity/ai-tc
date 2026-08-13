/**
 * /aka:setup calibration wizard, Not-now branch, proven end-to-end against the
 * REAL script chain — the analog of yes-scan.journey.test.ts for the Not-now journey.
 *
 * This owns no behavior — the underlying units do — it just runs the shipped
 * Not-now scripts in wizard-step order and asserts each frame's rendered output
 * and the final store state. The Not-now leg grants ZERO historical access. To
 * prove that is a real refusal and not a vacuous empty read, the harness seeds a
 * DETECTABLE transcript before the chain runs, then asserts nothing read it: the
 * chain is intro.js (0.1) → start-light.js (0.3b) → onboard.js --floor (0.5, the
 * start-light posture write) — no backfill/scan runs, so the seeded transcript
 * stays untouched and the store gains no findings. The chosen posture lands in the policies store
 * (~/.aka/data/aka.db), where onboard.ts writes it — settings.json is never
 * touched on the floor-only path, so no historical-review consent is recorded.
 *
 * The applying-frame confirmation is the Not-now analog of the Yes-path
 * apply-suppressions --confirmed line: it reports only the detection categories
 * set (no suppression pass ran, no scan produced counts), so it carries neither
 * a 'routine results set aside' count nor the calibration headline.
 *
 * Frame 0.6 (firstrun.js, the no-scan installed summary) closes the journey here:
 * driven with NO --surfaced count, its store-derived stats and 'N worth a look'
 * handoff degrade to the honest empty-state — the empty-state degradation — over a store
 * that holds no scanned findings, and no handoff frame JSON is emitted. These e2e
 * assertions run the full Not-now spine through the installed summary.
 */
import { existsSync, readFileSync, statSync } from 'node:fs';

import { openLocalDatabase } from '@akasecurity/persistence';
import { severityFloorPosture } from '@akasecurity/plugin-sdk';
import { builtinPolicyToAction, DetectionCategory } from '@akasecurity/schema';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { indent } from '../../src/present.ts';
import {
  RE_TUNE_HINT,
  renderCategoriesTuned,
  renderPosture,
  renderPostureGrid,
  STORE_UNAVAILABLE_NOTE,
} from '../../src/render.ts';
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
  let firstRun: string;
  let firstRunStatus: number;
  // The seeded prior transcript and a snapshot of it taken before the chain runs,
  // so the Not-now leg's refusal to read history is provable rather than vacuous.
  let transcriptPath: string;
  let seededTranscript: string;
  let seededMtimeMs: number;

  beforeAll(() => {
    journey = new SetupJourney();
    // Seed a DETECTABLE transcript FIRST — two leaked keys inside the retention
    // window — so "no historical read" is a real refusal over history that exists,
    // not an empty-directory no-op. The Not-now leg must leave it entirely unread.
    transcriptPath = journey.seedTranscript();
    seededTranscript = readFileSync(transcriptPath, 'utf8');
    seededMtimeMs = statSync(transcriptPath).mtimeMs;

    // Kickoff intro (0.1).
    intro = journey.intro().stdout;

    // Start-light card (0.3b) — the full 8×4 default posture matrix. Reads no store,
    // records no consent.
    startLight = journey.startLight().stdout;

    // Apply the chosen posture (0.5). Keeping the default posture is the --floor
    // write — NO backfill, NO applyPreview, NO suppression pass.
    applied = journey.onboardStartLight().stdout;

    // Installed summary (0.6), the no-scan landing: firstrun.js WITHOUT a
    // --surfaced count, so the store-derived stats and the handoff degrade to the
    // honest empty-state over a store with no scanned findings.
    const firstRunStep = journey.firstRunNoScan();
    firstRun = firstRunStep.stdout;
    firstRunStatus = firstRunStep.status;
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
    expect(startLight).toContain('Starting light — your detection categories');
    // The full 8×4 default posture matrix, rendered from the severity-floor defaults.
    expect(startLight).toContain(renderPostureGrid(severityFloorPosture()));
    // Per-pack rationale — a shipped reason line for each pack, never omitted.
    expect(startLight).toContain('keys and credentials are the costliest thing to lose');
    // The frame closes with the re-tune hint.
    expect(startLight).toContain(RE_TUNE_HINT);
  });

  it('applying (0.5): honest no-scan confirmation — detection categories set, no routine/calibration counts', () => {
    // The applying confirmation from onboard.js --floor — the Not-now analog of
    // the Yes-path apply-suppressions --confirmed line. The tuned count is derived
    // from the posture the run actually wrote (read back from the store), so the
    // assertion carries no hardcoded count.
    const categoriesTuned = Object.values(readPosture(journey.storeDir)).filter(Boolean).length;
    expect(applied).toContain(renderCategoriesTuned(categoriesTuned));
    // No suppression pass ran, so there is no routine-results count to report.
    expect(applied).not.toContain('routine result');
    // No scan ran, so the calibration headline and its counts never appear.
    expect(applied).not.toContain("I went through Claude's recent work");
    expect(applied).not.toContain('detections');
  });

  it('frame JSON: no calibration frame is emitted on the Not-now spine through 0.5', () => {
    // The frame JSON is emitted only where a frame produces it. The Not-now frames
    // through the applying frame 0.5 emit none (no scan, no preview); the frame-0.6
    // no-scan payload is asserted withheld in its own block below.
    expect(readFrameJsonBlock(intro)).toBeUndefined();
    expect(readFrameJsonBlock(startLight)).toBeUndefined();
    expect(readFrameJsonBlock(applied)).toBeUndefined();
  });

  it('installed summary (0.6): the no-scan card renders over the floor posture the run wrote', () => {
    // The installed-summary heading and, beneath it, the per-category Posture block
    // reflecting exactly the floor posture the 0.5 write established — read back
    // from the store (the honest final-state seam) and rendered into the card.
    // No scan ran, so the card carries the floor-path heading, not the scan one.
    expect(firstRun).toContain("I've started you on safe defaults");
    const posture = readPosture(journey.storeDir);
    const rows = DetectionCategory.options.flatMap((category) => {
      const action = posture[category];
      return action === undefined ? [] : [{ category, action }];
    });
    expect(firstRun).toContain(indent(renderPosture(rows)));
  });

  it('installed summary (0.6): store-derived stats and the handoff degrade to the honest no-scan empty-state', () => {
    // No scan ran, so the numeric Health/detections/recommendations tally is
    // replaced by the honest empty-state line — never a fabricated zero tally.
    // Guard every count in that tally, so a regression to a fabricated
    // `0 detections` / `0 recommendations` line fails here too, not only the
    // health score.
    expect(firstRun).toContain('Nothing needs your attention');
    expect(firstRun).not.toMatch(/Health \d+\/100/);
    expect(firstRun).not.toMatch(/\d+ detections/);
    expect(firstRun).not.toMatch(/\d+ recommendations/);
    // No surfaced count was threaded, so the 'N worth a look' dashboard handoff is
    // withheld entirely — no fabricated or placeholder count.
    expect(firstRun).not.toContain('worth a look');
    // A healthy store read the whole way — the fail-open note must be absent.
    expect(firstRun).not.toContain(STORE_UNAVAILABLE_NOTE);
  });

  it('installed summary (0.6): no handoff frame-JSON payload is emitted on the no-scan leg', () => {
    // firstrun-core omits the SetupHandoffOffer payload when no --surfaced count is
    // supplied — nothing surfaced, nothing to hand off, nothing fabricated.
    expect(readFrameJsonBlock(firstRun)).toBeUndefined();
  });

  it('installed summary (0.6): the Try line names only shipped commands and the step exits cleanly', () => {
    // The call-to-action points only at commands the plugin actually ships.
    expect(firstRun).toContain('Try: /aka:dashboard · /aka:scan');
    // A fail-open step still exits 0; a non-zero status would mean an error escaped.
    expect(firstRunStatus).toBe(0);
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

  it('zero historical read: the seeded transcript is left unread and no scan side effects landed', async () => {
    // A detectable transcript WAS seeded and historicalAccess was never set to
    // 'full', so backfill's gate would refuse — and no backfill/scan ran here at
    // all. The store must therefore carry no scanned findings and no suppression
    // rows despite the leaked keys sitting in the seeded history.
    const db = openLocalDatabase(journey.storeDir);
    try {
      expect(await db.findings.recentFindings()).toHaveLength(0);
      expect(await db.exceptions.list()).toHaveLength(0);
    } finally {
      db.close();
    }
    // The seeded transcript is byte-for-byte untouched — the Not-now leg neither
    // rewrote nor deleted it, and (with zero findings above) never scanned it.
    expect(existsSync(transcriptPath)).toBe(true);
    expect(readFileSync(transcriptPath, 'utf8')).toBe(seededTranscript);
    expect(statSync(transcriptPath).mtimeMs).toBe(seededMtimeMs);
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
