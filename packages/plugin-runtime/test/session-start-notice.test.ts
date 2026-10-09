import { describe, expect, it } from 'vitest';

import { sessionStartNotice } from '../src/handle-session-start.ts';

// The one string a session start shows its user. The adapters put it on
// systemMessage verbatim, so its shape is the user-facing contract.
describe('sessionStartNotice', () => {
  it('is undefined when there is nothing to say', () => {
    expect(sessionStartNotice({ staleBinaryNotice: null, forwardingLine: null })).toBeUndefined();
  });

  it('is the forwarding line alone, unprefixed', () => {
    expect(
      sessionStartNotice({
        staleBinaryNotice: null,
        forwardingLine: 'AKA: local-only (not enrolled)',
      }),
    ).toBe('AKA: local-only (not enrolled)');
  });

  it('is the stale-session notice alone, with its [aka] prefix', () => {
    expect(
      sessionStartNotice({ staleBinaryNotice: 'a newer AKA is installed', forwardingLine: null }),
    ).toBe('[aka] a newer AKA is installed');
  });

  it('puts the forwarding line first, one notice per line', () => {
    expect(
      sessionStartNotice({
        staleBinaryNotice: 'a newer AKA is installed',
        forwardingLine: 'AKA: forwarding everything to Acme (machine-wide)',
      }),
    ).toBe('AKA: forwarding everything to Acme (machine-wide)\n[aka] a newer AKA is installed');
  });
});
