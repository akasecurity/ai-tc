import { describe, expect, it } from 'vitest';

import { CAPTURE_EVENT_TYPES_SQL, EventKind } from '../src/index.ts';

describe('CAPTURE_EVENT_TYPES_SQL', () => {
  it('is derived from EventKind.options and cannot drift from the enum', () => {
    expect(CAPTURE_EVENT_TYPES_SQL).toBe(EventKind.options.map((k) => `'${k}'`).join(','));
  });

  it('pins the exact SQL value list every capture-kind predicate interpolates', () => {
    // Byte-exact (no spaces) so it drops into `event_type IN (...)` unchanged.
    // If EventKind is ever widened, this fails and forces a conscious review of
    // every read view that filters on capture kind.
    expect(CAPTURE_EVENT_TYPES_SQL).toBe("'prompt','response','code_change','tool_use'");
  });
});
