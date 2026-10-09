import { FORWARD_FAILURE_LINES, type SharesForwardOutcome } from '@akasecurity/local-ops';
import { RemoteFailureKind } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { describeForward } from '../../app/(app)/scan/forward-copy.ts';

/**
 * What the Scan page says about the register it forwarded, and in what tone.
 *
 * The property under test is not the wording of the failure sentences — those
 * are the shared table's, pinned where it lives — but that every outcome the
 * union carries is accounted for here, that each refusal reads as a refusal,
 * and that the two silences are silences on purpose.
 */
const ENDPOINT = 'Acme Prod';

describe('describeForward', () => {
  it('says nothing on a machine attached to no deployment', () => {
    expect(describeForward({ status: 'not-attached' })).toBeNull();
  });

  it('says nothing when the Data Shares switch is off', () => {
    // Nothing was recorded either, so there is no register to talk about.
    expect(
      describeForward({ status: 'disabled', endpoint: ENDPOINT, reason: 'data-shares-off' }),
    ).toBeNull();
  });

  it('notes a scan the user ran without forwarding', () => {
    expect(describeForward({ status: 'disabled', endpoint: ENDPOINT, reason: 'opt-out' })).toEqual({
      text: 'Not forwarded: this scan was run without forwarding.',
      tone: 'note',
    });
  });

  it('names the deployment and the count when the register lands, as a note', () => {
    expect(describeForward({ status: 'forwarded', endpoint: ENDPOINT, callSites: 3 })).toEqual({
      text: 'Forwarded to Acme Prod · 3 call site(s).',
      tone: 'note',
    });
  });

  it('points a missing credential at the page that can fix it, as a warning', () => {
    const line = describeForward({ status: 'no-credential', endpoint: ENDPOINT });
    expect(line).toEqual({
      text: 'Not forwarded to Acme Prod: no usable credential — re-attach from Settings.',
      tone: 'warning',
    });
    // The remedy has to be one this surface offers. `aka attach` is the CLI's
    // answer to the same state and is not reachable from a browser.
    expect(line?.text).not.toContain('aka attach');
  });

  it('notes a project a scoped machine keeps local, with no remedy this page cannot offer', () => {
    const line = describeForward({ status: 'not-enrolled', endpoint: ENDPOINT });
    // One outcome covers the project and any repository nested in it that the
    // scan walked into: the server answers the same for either, so the line
    // names both rather than blaming the project when a nested one is the cause.
    expect(line).toEqual({
      text: 'Not forwarded to Acme Prod: the project or a repository nested in it is not enrolled — its scans stay on this machine.',
      tone: 'note',
    });
    // Enrolling is a terminal verb with no control on this page, and a note is
    // not a refusal: the scoped machine is doing what it was asked to.
    expect(line?.text).not.toContain('aka enroll');
  });

  it.each(RemoteFailureKind.options)('explains a %s refusal, as a warning', (kind) => {
    expect(describeForward({ status: 'failed', endpoint: ENDPOINT, kind })).toEqual({
      text: `Not forwarded to Acme Prod: ${FORWARD_FAILURE_LINES[kind]}.`,
      tone: 'warning',
    });
  });

  it('answers for every status the outcome union carries', () => {
    // A status added to the union without a branch here would fall out of the
    // switch as `undefined` — which reads as "nothing to say" and is exactly the
    // silent gap this catches.
    const outcomes: SharesForwardOutcome[] = [
      { status: 'not-attached' },
      { status: 'disabled', endpoint: ENDPOINT, reason: 'opt-out' },
      { status: 'disabled', endpoint: ENDPOINT, reason: 'data-shares-off' },
      { status: 'no-credential', endpoint: ENDPOINT },
      { status: 'not-enrolled', endpoint: ENDPOINT },
      { status: 'forwarded', endpoint: ENDPOINT, callSites: 1 },
      { status: 'failed', endpoint: ENDPOINT, kind: 'unreachable' },
    ];
    for (const outcome of outcomes) {
      const line = describeForward(outcome);
      expect(line, outcome.status).not.toBeUndefined();
      if (line !== null && outcome.status !== 'disabled') {
        expect(line.text, outcome.status).toContain(ENDPOINT);
      }
    }
  });
});
