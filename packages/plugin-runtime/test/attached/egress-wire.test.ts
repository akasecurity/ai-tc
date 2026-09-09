import * as persistence from '@akasecurity/persistence';
import { describe, expect, it } from 'vitest';

import * as wire from '../../src/attached/egress-wire.ts';

// The projection itself is owned and tested by @akasecurity/persistence. What
// this package still has to hold is that its import site resolves to THAT
// implementation and not to a second one: the payload the attached gateway
// forwards and the payload the CLI forwards are the same bytes only while both
// go through one function. Identity (`toBe`), not behaviour — a copy would pass
// every behavioural assertion right up until the day the two drift.
describe('the attached gateway import site', () => {
  it('re-exports the projection persistence owns, not a copy of it', () => {
    expect(wire.toEgressIngestRequest).toBe(persistence.toEgressIngestRequest);
  });

  it('re-exports the key digest persistence owns, not a copy of it', () => {
    expect(wire.hashProjectKey).toBe(persistence.hashProjectKey);
  });
});
