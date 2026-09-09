import type { SharesForwardOutcome } from '@akasecurity/local-ops';
import { RemoteFailureKind } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { describeForward, FORWARD_FAILURE_COPY } from '../../app/(app)/scan/forward-copy.ts';

/**
 * What the Scan page says about the register it forwarded.
 *
 * The property under test is not the wording, it is that every outcome is
 * accounted for and that no two failures share a sentence. A shared sentence
 * passes an "each kind renders something" check just as well and is how somebody
 * is sent to fix the wrong thing — re-attaching for a deployment that is simply
 * too old, or mailing an admin about a timeout.
 *
 * The two silent outcomes are asserted as silences rather than left untested:
 * rendering anything for them would put a line on a standalone install's page,
 * or describe an opt-out this surface does not offer.
 */
const ENDPOINT = 'Acme Prod';

describe('FORWARD_FAILURE_COPY', () => {
  it('covers every failure kind the transport can report', () => {
    // Driven from the enum rather than a list here, so a seventh kind arrives
    // as a failing case instead of as a sentence nobody wrote.
    expect(Object.keys(FORWARD_FAILURE_COPY).sort()).toEqual([...RemoteFailureKind.options].sort());
  });

  it('gives every kind its own remediation', () => {
    const lines = Object.values(FORWARD_FAILURE_COPY);
    expect(new Set(lines).size).toBe(RemoteFailureKind.options.length);
    // The 403 has a self-service remedy that a bare "ask an admin" hides: a key
    // minted before this route existed is refused until it is re-minted, and
    // re-attaching is what mints one.
    expect(FORWARD_FAILURE_COPY.forbidden).toMatch(/re-attach/);
    expect(FORWARD_FAILURE_COPY.forbidden).toMatch(/org admin/);
  });
});

describe('describeForward', () => {
  it('says nothing on a machine attached to no deployment', () => {
    expect(describeForward({ status: 'not-attached' })).toBeNull();
  });

  it('says nothing about an opt-out this page does not offer', () => {
    // `disabled` is reachable only for a caller that passes `enabled: false`,
    // which the Scan action never does. A sentence here would describe a
    // control the user cannot see.
    expect(describeForward({ status: 'disabled', endpoint: ENDPOINT })).toBeNull();
  });

  it('names the deployment and the count when the register lands', () => {
    expect(describeForward({ status: 'forwarded', endpoint: ENDPOINT, callSites: 3 })).toBe(
      'Forwarded to Acme Prod · 3 call site(s).',
    );
  });

  it('points a missing credential at the page that can fix it', () => {
    const sentence = describeForward({ status: 'no-credential', endpoint: ENDPOINT });
    expect(sentence).toBe(
      'Not forwarded to Acme Prod: no usable credential — re-attach from Settings.',
    );
    // The remedy has to be one this surface offers. `aka attach` is the CLI's
    // answer to the same state and is not reachable from a browser.
    expect(sentence).not.toContain('aka attach');
  });

  it.each(RemoteFailureKind.options)('explains a %s refusal', (kind) => {
    expect(describeForward({ status: 'failed', endpoint: ENDPOINT, kind })).toBe(
      `Not forwarded to Acme Prod: ${FORWARD_FAILURE_COPY[kind]}.`,
    );
  });

  it('renders a sentence for every status the outcome union carries', () => {
    // The union is what the state machine can return, and a status added there
    // without a branch here would fall out of the switch as `undefined` — which
    // reads as "nothing to say" and is exactly the silent gap this catches.
    const outcomes: SharesForwardOutcome[] = [
      { status: 'not-attached' },
      { status: 'disabled', endpoint: ENDPOINT },
      { status: 'no-credential', endpoint: ENDPOINT },
      { status: 'forwarded', endpoint: ENDPOINT, callSites: 1 },
      { status: 'failed', endpoint: ENDPOINT, kind: 'unreachable' },
    ];
    for (const outcome of outcomes) {
      const rendered = describeForward(outcome);
      expect(rendered, outcome.status).not.toBeUndefined();
      if (rendered !== null) expect(rendered, outcome.status).toContain(ENDPOINT);
    }
  });
});
