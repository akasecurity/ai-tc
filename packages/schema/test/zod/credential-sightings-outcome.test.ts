import { describe, expect, it } from 'vitest';

import { RemoteFailureKind } from '../../src/zod/control-plane.ts';
import type { CredentialSightingsOutcome, SightingSharing } from '../../src/zod/sighting-share.ts';
import {
  combineCredentialSightingsOutcomes,
  credentialSightingsLine,
  SIGHTING_SHARE_PAYLOAD_NOTE,
  sightingSharingLine,
} from '../../src/zod/sighting-share.ts';

const off: SightingSharing = {
  mode: 'scoped',
  managed: false,
  sharing: false,
  reason: 'not-opted-in',
  optedIn: false,
  locked: false,
};

const sent = (
  shared: number,
  extra: Partial<Extract<CredentialSightingsOutcome, { status: 'sent' }>> = {},
): CredentialSightingsOutcome => ({ status: 'sent', shared, keptLocal: 0, unsent: 0, ...extra });

describe('credentialSightingsLine', () => {
  it('renders the sharing state unchanged when sharing is off', () => {
    const outcome: CredentialSightingsOutcome = {
      status: 'not-shared',
      reason: 'sharing-off',
      sharing: off,
    };
    expect(credentialSightingsLine(outcome)).toBe(sightingSharingLine(off));
  });

  it('counts what was shared, in the singular and the plural', () => {
    expect(credentialSightingsLine(sent(1))).toBe(
      `Credential sightings: 1 shared with your organization. ${SIGHTING_SHARE_PAYLOAD_NOTE}`,
    );
    expect(credentialSightingsLine(sent(3))).toContain('3 shared with your organization.');
  });

  it('says when a scan found nothing to share', () => {
    expect(credentialSightingsLine(sent(0))).toBe(
      `Credential sightings: none found to share. ${SIGHTING_SHARE_PAYLOAD_NOTE}`,
    );
  });

  it('names the sightings a scoped attachment kept on the machine', () => {
    expect(credentialSightingsLine(sent(2, { keptLocal: 1 }))).toContain(
      '2 shared with your organization; 1 kept on this machine (not enrolled, or outside the project).',
    );
    expect(credentialSightingsLine(sent(0, { keptLocal: 4 }))).toContain(
      'not shared — kept on this machine (not enrolled, or outside the project).',
    );
  });

  it('gives each failure kind its own reason, and says what was delivered first', () => {
    const lines = new Set(
      RemoteFailureKind.options.map((failure) =>
        credentialSightingsLine(sent(0, { unsent: 2, failure })),
      ),
    );
    expect(lines.size).toBe(RemoteFailureKind.options.length);
    for (const line of lines) expect(line).toMatch(/^Credential sightings: not shared — /);
    expect(credentialSightingsLine(sent(2, { unsent: 3, failure: 'unreachable' }))).toContain(
      '2 shared with your organization; 3 not sent — control plane unreachable',
    );
  });

  it('names each reason nothing was sent', () => {
    expect(credentialSightingsLine({ status: 'not-shared', reason: 'opt-out' })).toContain(
      'not shared — forwarding was skipped for this scan.',
    );
    expect(credentialSightingsLine({ status: 'not-shared', reason: 'no-key' })).toContain(
      'not shared — this machine has no sighting key yet',
    );
    expect(credentialSightingsLine({ status: 'not-shared', reason: 'no-credential' })).toContain(
      're-attach with `aka attach`',
    );
    expect(credentialSightingsLine({ status: 'not-shared', reason: 'local-error' })).toContain(
      'not shared — they could not be prepared on this machine; the next scan tries again.',
    );
  });

  it('always closes with the payload note', () => {
    for (const outcome of [
      sent(1),
      sent(0, { failure: 'forbidden', unsent: 1 }),
      { status: 'not-shared', reason: 'no-key' } as const,
    ]) {
      expect(credentialSightingsLine(outcome).endsWith(SIGHTING_SHARE_PAYLOAD_NOTE)).toBe(true);
    }
  });
});

describe('combineCredentialSightingsOutcomes', () => {
  it('adds the counts of two sends and keeps the first failure', () => {
    expect(
      combineCredentialSightingsOutcomes(
        sent(2, { keptLocal: 1 }),
        sent(3, { unsent: 4, failure: 'unreachable' }),
      ),
    ).toEqual(sent(5, { keptLocal: 1, unsent: 4, failure: 'unreachable' }));
    expect(
      combineCredentialSightingsOutcomes(
        sent(0, { unsent: 1, failure: 'forbidden' }),
        sent(0, { unsent: 1, failure: 'unreachable' }),
      ),
    ).toEqual(sent(0, { unsent: 2, failure: 'forbidden' }));
  });

  it('prefers a send over a refusal, and the first refusal over a later one', () => {
    const missing = { status: 'not-shared', reason: 'no-key' } as const;
    const optOut: CredentialSightingsOutcome = { status: 'not-shared', reason: 'opt-out' };
    expect(combineCredentialSightingsOutcomes(missing, sent(1))).toEqual(sent(1));
    expect(combineCredentialSightingsOutcomes(sent(1), missing)).toEqual(sent(1));
    expect(combineCredentialSightingsOutcomes(missing, optOut)).toEqual(missing);
  });

  it('answers the other outcome when one is absent', () => {
    expect(combineCredentialSightingsOutcomes(undefined, sent(1))).toEqual(sent(1));
    expect(combineCredentialSightingsOutcomes(sent(1), undefined)).toEqual(sent(1));
  });
});
