import { DRIFT_MIN_PARSE_FAILURES } from '@akasecurity/plugin-sdk';
import { RESPONSE_TEXT_MAX_BYTES as SCHEMA_CEILING } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { RESPONSE_TEXT_MAX_BYTES as BRIDGE_CEILING, STATUS_COUNTER_CAP } from '../src/bridge.ts';

// One number, declared twice, in two packages that cannot import each other.
//
// The stored-text ceiling belongs to the schema, and the bridge is what
// enforces it — but the bridge ships inside a content-script bundle, which
// takes nothing from @akasecurity/schema: importing it would put a validation
// library into every tab of the sites this extension runs on. So the bridge
// carries a copy, and this is what keeps the copy true. A test can import both,
// because a test is Node.
//
// Without it the two drift silently in the direction that matters: raise the
// schema's and the bridge goes on cutting at the old, lower value, so the
// schema's number stops describing what is stored and nothing anywhere reports
// a shorter capture as short.

describe('the stored-text ceiling', () => {
  it('is the same number on both sides of the package wall', () => {
    expect(BRIDGE_CEILING).toBe(SCHEMA_CEILING);
  });

  it('is a real ceiling, not a zero both copies happen to share', () => {
    // Non-vacuous: two undefined imports would satisfy the equality above.
    expect(BRIDGE_CEILING).toBeGreaterThan(0);
  });
});

// A busy tab reports on a bucketed TRANSITION rather than per message — see
// bridge.ts's reportSignature. Any consumer threshold read over one of the
// bucketed counters (today, just DRIFT_MIN_PARSE_FAILURES) has to sit at or
// below the bucket cap, or a status that crossed the threshold is not
// reported until the tab closes.
describe('the report bucket cap vs a consumer threshold', () => {
  it('cannot sit below a threshold that reads it', () => {
    expect(DRIFT_MIN_PARSE_FAILURES).toBeLessThanOrEqual(STATUS_COUNTER_CAP);
  });

  it('is a real cap, not a zero both sides happen to share', () => {
    expect(STATUS_COUNTER_CAP).toBeGreaterThan(0);
  });
});
