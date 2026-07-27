/**
 * /aka:setup, model-judge consent DECLINED — proven end-to-end against the REAL
 * script chain.
 *
 * The distinct model-judge consent (step 3) is what authorizes the only egress
 * in the product: apply-suppressions' `claude -p` judge. Every other journey
 * test grants it, and the adapter's own unit tests inject the gate as a plain
 * boolean — so the wiring that reads the real settings.json
 * (apply-suppressions.ts: `loadConfig().settings.modelJudgeConsent`) is never
 * exercised in the refusing direction. Inverting that boolean, or reading the
 * wrong field, would leave every other test green.
 *
 * This leg closes that gap at the process boundary. Historical access IS granted
 * (so the backfill really reads the seeded transcript and produces hits — the
 * refusal is not a vacuous empty scan), the model-judge consent is NOT, and the
 * preview then has to skip the judge:
 *
 *   intro.js → onboard.js --historical full → backfill.js --triage
 *            → apply-suppressions.js (preview, no consent)
 *
 * The load-bearing assertion is `judgeWasInvoked()`: the harness puts a stub
 * `claude` first on the child PATH which touches a sentinel when executed, so
 * this proves no judge subprocess ever ran — not merely that a mock went
 * uncalled. Nothing can reach the model API on this path.
 */
import { readFileSync } from 'node:fs';

import { openLocalDatabase } from '@akasecurity/persistence';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { SetupJourney, SURFACED_KEY } from './harness.ts';

describe('/aka:setup journey — model-judge consent declined', () => {
  const journey = new SetupJourney();
  let triageStream = '';
  let preview: ReturnType<SetupJourney['applyPreview']>;

  beforeAll(() => {
    journey.seedTranscript();
    journey.intro();
    // Historical access granted: the scan may READ local transcripts. That grant
    // deliberately does NOT carry model-judge consent — the two are separate.
    journey.onboardHistorical('full');
    triageStream = journey.backfillTriage().stdout;
    preview = journey.applyPreview(triageStream);
  });

  afterAll(() => {
    journey.cleanup();
  });

  it('reads real history, so the skip is a refusal and not an empty scan', () => {
    // The backfill genuinely found the seeded key: there WAS something to judge.
    expect(triageStream).toContain(SURFACED_KEY);
  });

  it('never spawns the judge subprocess — nothing reaches the model API', () => {
    expect(journey.judgeWasInvoked()).toBe(false);
  });

  it('says plainly that nothing was sent, without claiming a clean bill of health', () => {
    expect(preview.stdout).toContain(
      "I didn't send anything to the model — model-judge consent wasn't granted.",
    );
    // The scan-ran-clean copy would report a clean result for a judgment that
    // never ran. Hits existed; they were simply never rated.
    expect(preview.stdout).not.toContain('nothing needs your attention');
  });

  it('still emits a parseable zero-count frame so the wizard can degrade', () => {
    // The wizard reaches this pipe expecting a frame; a bare line would leave it
    // mid-flow with nothing to read.
    const frame = /<<<AKA_FRAME_JSON\s*([\s\S]*?)\s*AKA_FRAME_JSON>>>/.exec(preview.stdout);
    expect(frame?.[1]).toBeDefined();
    const parsed = JSON.parse(frame?.[1] ?? '{}') as { counts?: { total?: number } };
    expect(parsed.counts?.total).toBe(0);
  });

  it('writes no calibration plan — there is no judged result to confirm', () => {
    expect(preview.stdout).not.toContain('Plan saved to:');
  });

  it('records the historical grant but no model-judge consent in settings.json', () => {
    const settings = JSON.parse(readFileSync(journey.settingsPath, 'utf8')) as {
      historicalAccess?: string;
      modelJudgeConsent?: unknown;
    };
    // The two grants are independent: reading history was allowed, sending was not.
    expect(settings.historicalAccess).toBe('full');
    expect(settings.modelJudgeConsent).toBeUndefined();
  });

  it('suppresses nothing in the store — no verdict means no dismissals', async () => {
    const db = openLocalDatabase(journey.storeDir);
    try {
      const active = await db.exceptions.list();
      expect(active).toHaveLength(0);
    } finally {
      db.close();
    }
  });
});

// The control for the leg above. `judgeWasInvoked() === false` only means
// something if the sentinel would have been written had the judge run — so drive
// the identical chain WITH consent and assert the spawn is detected. Without
// this, a broken sentinel would make the no-consent assertion vacuously green:
// the exact failure mode that let the disclosure drift in the first place.
describe('/aka:setup journey — model-judge consent granted (control)', () => {
  const journey = new SetupJourney();

  afterAll(() => {
    journey.cleanup();
  });

  it('does spawn the judge once consent is recorded', () => {
    journey.seedTranscript();
    journey.intro();
    journey.onboardHistorical('full');
    expect(journey.judgeWasInvoked()).toBe(false);

    journey.onboardModelJudge();
    journey.applyPreview(journey.backfillTriage().stdout);

    expect(journey.judgeWasInvoked()).toBe(true);
  });
});
