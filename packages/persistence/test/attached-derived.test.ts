import { describe, expect, it } from 'vitest';

import {
  ATTACHED_DERIVED_FILENAMES,
  ATTACHED_FORWARD_DROPS_FILENAME,
  ATTACHED_FORWARD_STATE_FILENAME,
  ATTACHED_HISTORY_SYNC_STATE_FILENAME,
  ATTACHED_POSTURE_REPORT_FILENAME,
  ATTACHED_SYNC_STATE_FILENAME,
  POLICY_CACHE_FILENAME,
} from '../src/attached-derived.ts';

describe('ATTACHED_DERIVED_FILENAMES', () => {
  // Both detach surfaces clear exactly this list, and the dashboard's detach
  // test iterates it for its seed and its assertion alike — so that test proves
  // the clear, never the membership. This pins the membership, EXACTLY: an
  // entry dropped would leave a file describing a deployment the machine has
  // left, and an entry added would clear something detach must leave alone.
  it('names exactly the six files an attachment leaves behind', () => {
    expect(ATTACHED_DERIVED_FILENAMES).toHaveLength(6);
    expect(new Set(ATTACHED_DERIVED_FILENAMES)).toEqual(
      new Set([
        POLICY_CACHE_FILENAME,
        ATTACHED_SYNC_STATE_FILENAME,
        ATTACHED_FORWARD_STATE_FILENAME,
        ATTACHED_FORWARD_DROPS_FILENAME,
        ATTACHED_POSTURE_REPORT_FILENAME,
        ATTACHED_HISTORY_SYNC_STATE_FILENAME,
      ]),
    );
  });
});
