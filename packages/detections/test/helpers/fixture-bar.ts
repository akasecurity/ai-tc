import { expect } from 'vitest';

// The documented fixture bar, in one place.
//
// Two suites gate on it — the rule-pack gate in `engine.test.ts` and the posture
// gate in `posture/config-posture.test.ts` — over fixture shapes that share only
// `shouldMatch`. Holding the number and the message here is what stops the two
// from drifting apart while both stay green.

/**
 * The minimum labeled cases of each polarity every rule ships with. Negatives
 * are what keep a pattern from over-matching, so the bar applies to both.
 */
export const MIN_FIXTURES_PER_POLARITY = 2;

const FIXTURE_BAR = String(MIN_FIXTURES_PER_POLARITY);

/** Same shape as the missing-fixture message: name the subject, say what was
 * found, and point at the authority for the bar. */
function belowFixtureBar(
  subject: string,
  polarity: 'positive' | 'negative',
  count: number,
): string {
  return (
    `Rule "${subject}" has ${String(count)} distinct ${polarity} fixture${count === 1 ? '' : 's'} — ` +
    `expected at least ${FIXTURE_BAR}. Every rule must have at least ${FIXTURE_BAR} positive and ` +
    `${FIXTURE_BAR} negative fixtures per skills/write-detection-rule/SKILL.md.`
  );
}

/**
 * Assert `cases` clears the bar in both polarities.
 *
 * Counts DISTINCT cases: a repeated case exercises nothing the first one did
 * not, so it must not buy its way past a bar that exists to demand coverage.
 * `identity` maps a case to what makes it distinct — the scanned input, not the
 * label, since two differently-labeled copies of one input are still one case.
 *
 * Both polarities are asserted softly so a subject short on both reports both
 * in one run rather than one shortfall per fix-and-rerun cycle.
 */
export function expectFixtureBar<T extends { shouldMatch: boolean }>(
  subject: string,
  cases: readonly T[],
  identity: (fixture: T) => string,
): void {
  for (const polarity of ['positive', 'negative'] as const) {
    const wanted = polarity === 'positive';
    const distinct = new Set(cases.filter((c) => c.shouldMatch === wanted).map(identity)).size;
    expect
      .soft(distinct, belowFixtureBar(subject, polarity, distinct))
      .toBeGreaterThanOrEqual(MIN_FIXTURES_PER_POLARITY);
  }
}
