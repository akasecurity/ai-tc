import type { DroppedRules } from '@akasecurity/local-ops';

// What the Scan page says when the ReDoS guard removed rules from a scan.
//
// It lives here rather than beside the action because a `'use server'` module
// may only export async functions, so a helper declared there cannot be called
// from a test at all — and this sentence is the only account the user gets of
// why their detection coverage was smaller than the Detections page says.
//
// The rule it has to keep: NEVER offer a next step that leads nowhere. The
// three causes below are not interchangeable —
//
//   - a quarantined rule was measured, failed, and left a row behind, so
//     `aka detections` names it and `aka detections unquarantine` undoes it;
//   - an unmeasured one left nothing, deliberately, because caching a verdict
//     for a rule nobody timed would disable it forever on the strength of a
//     missing worker or an unlucky pass budget;
//   - a build with no worker at all is not a rule problem, it is a packaging
//     one, and the fix is to the install rather than to the ruleset.
//
// Pointing all three at `aka detections` reads as helpful and sends two of them
// to an empty list.

/**
 * One sentence naming what the guard removed and what to do about it, or
 * undefined when it removed nothing.
 *
 * `listed` is whether the quarantine cache actually holds anything right now —
 * `db().ruleProbeCache.countQuarantined() > 0`, the very value `aka detections`
 * prints from. Read it AFTER the walk: the hard bound quarantines its culprit
 * mid-scan, so a value read before would miss it.
 */
export function describeDropped(dropped: DroppedRules, listed: boolean): string | undefined {
  const parts: string[] = [];

  if (dropped.quarantined > 0) {
    parts.push(
      `${plural(dropped.quarantined)} exceeded the detection timing budget and ` +
        `${dropped.quarantined === 1 ? 'is' : 'are'} quarantined`,
    );
  }
  if (dropped.unmeasured > 0) {
    parts.push(
      dropped.isolated
        ? `${plural(dropped.unmeasured)} could not be time-checked before the check ran out of ` +
            `time, and ${dropped.unmeasured === 1 ? 'was' : 'were'} skipped for this scan`
        : `${plural(dropped.unmeasured)} could not be time-checked at all, because this ` +
            `dashboard build shipped without its scan worker`,
    );
  }
  if (dropped.bound > 0) {
    parts.push(
      `${plural(dropped.bound)} had to be dropped part-way through after a scan overran its ` +
        `time bound`,
    );
  }
  if (parts.length === 0) return undefined;

  // "Everything else in your enabled packs still ran" is true by construction —
  // the guard drops rules, never the scan. It deliberately does not claim the
  // BUILT-IN packs still ran: a user who enabled only a custom pack has no
  // built-ins to fall back on, and a reassurance that is false for them is
  // worse than none.
  const next: string[] = ['Everything else in your enabled packs still ran.'];
  if (!dropped.isolated) {
    // The one cause with a fix that is not about rules at all. Named before the
    // quarantine pointer, because reinstalling is what restores the coverage.
    next.push('Reinstall the AKA CLI to restore it.');
  }
  if (listed) next.push('Run `aka detections` to see what is quarantined.');
  return `${parts.join('; ')}. ${next.join(' ')}`;
}

function plural(n: number): string {
  return `${String(n)} rule${n === 1 ? '' : 's'}`;
}
