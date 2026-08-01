import type { DroppedRules } from '@akasecurity/local-ops';
import { describe, expect, it } from 'vitest';

import { describeDropped } from '../../app/lib/dropped-rules.ts';

/**
 * The Scan page's account of why its ruleset was smaller than the Detections
 * page says.
 *
 * The property under test is not the wording, it is that the sentence never
 * offers a next step that leads nowhere. `aka detections` prints its quarantine
 * block only when the cache is non-empty, and TWO of the three ways a rule is
 * dropped leave it empty on purpose: a rule nobody could measure — no worker,
 * or the pre-flight's pass budget spent — is excluded WITHOUT a cached verdict,
 * because caching one would disable it forever on the strength of a missing
 * file. So a notice that always ends "run `aka detections`" sends the user who
 * most needs an explanation to a command that prints nothing.
 *
 * Every case therefore asserts the pointer's presence or absence, not just the
 * count. `listed` is the caller's own read of that cache.
 */
function dropped(overrides: Partial<DroppedRules> = {}): DroppedRules {
  return { quarantined: 0, unmeasured: 0, bound: 0, isolated: true, ...overrides };
}

const POINTER = 'aka detections';
const REINSTALL = 'Reinstall the AKA CLI';

describe('describeDropped', () => {
  it('says nothing when the guard removed nothing', () => {
    expect(describeDropped(dropped(), false)).toBeUndefined();
    // Not even when the cache holds a verdict from some earlier scan: this
    // sentence reports what THIS scan lost, and an unprompted notice on a clean
    // scan is noise that trains the user to ignore it.
    expect(describeDropped(dropped(), true)).toBeUndefined();
  });

  it('points at the command when a measured rule really is quarantined', () => {
    const message = describeDropped(dropped({ quarantined: 1 }), true);
    expect(message).toContain('1 rule exceeded the detection timing budget and is quarantined');
    expect(message).toContain(POINTER);
  });

  it('does NOT point at the command for a rule that was never measured', () => {
    // The regression this file exists for. Nothing was cached, so `aka
    // detections` would print no quarantine block at all.
    const message = describeDropped(dropped({ unmeasured: 2 }), false);
    expect(message).toContain('2 rules could not be time-checked');
    expect(message).not.toContain(POINTER);
  });

  it('names a missing scan worker as a build problem, not a rule problem', () => {
    const message = describeDropped(dropped({ unmeasured: 3, isolated: false }), false);
    expect(message).toContain('shipped without its scan worker');
    expect(message).toContain(REINSTALL);
    // A packaging fault is not something `aka detections` can show or undo.
    expect(message).not.toContain(POINTER);
  });

  it('keeps the two unmeasured causes distinguishable', () => {
    // Same count, different cause, different next step — otherwise "reinstall
    // the CLI" would be advice given to someone whose install is fine.
    const isolated = describeDropped(dropped({ unmeasured: 1 }), false);
    const notIsolated = describeDropped(dropped({ unmeasured: 1, isolated: false }), false);
    expect(isolated).toContain('ran out of time');
    expect(isolated).not.toContain(REINSTALL);
    expect(notIsolated).toContain('shipped without its scan worker');
    expect(notIsolated).toContain(REINSTALL);
  });

  it('withholds the pointer after a bound that named no culprit', () => {
    // The hard bound drops every rule that was running under it, but
    // quarantines only a culprit it could attribute. When it could not, nothing
    // is cached — which the caller sees as `listed: false`.
    const named = describeDropped(dropped({ bound: 4 }), true);
    const unnamed = describeDropped(dropped({ bound: 4 }), false);
    expect(named).toContain('4 rules had to be dropped part-way through');
    expect(named).toContain(POINTER);
    expect(unnamed).toContain('4 rules had to be dropped part-way through');
    expect(unnamed).not.toContain(POINTER);
  });

  it('reports every cause at once when they coincide', () => {
    const message = describeDropped(
      dropped({ quarantined: 1, unmeasured: 2, bound: 3, isolated: false }),
      true,
    );
    expect(message).toContain('1 rule exceeded');
    expect(message).toContain('2 rules could not be time-checked');
    expect(message).toContain('3 rules had to be dropped');
    expect(message).toContain(REINSTALL);
    expect(message).toContain(POINTER);
  });

  it('never claims the built-in packs survived', () => {
    // A user who enabled only a custom pack has no built-ins to fall back on,
    // so the reassurance is scoped to what they actually enabled.
    const message = describeDropped(dropped({ quarantined: 1 }), true);
    expect(message).toContain('Everything else in your enabled packs still ran');
    expect(message).not.toContain('Built-in');
  });
});
