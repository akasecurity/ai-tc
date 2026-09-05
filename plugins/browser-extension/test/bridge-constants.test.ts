import { RESPONSE_TEXT_MAX_BYTES as SCHEMA_CEILING } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { RESPONSE_TEXT_MAX_BYTES as BRIDGE_CEILING } from '../src/bridge.ts';

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
