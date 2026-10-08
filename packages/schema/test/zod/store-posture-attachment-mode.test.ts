import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { AttachmentMode, StorePostureSnapshot } from '../../src/zod/control-plane.ts';

// The attachment mode on the device report. A scoped attachment adds the
// member; a machine attachment sends none. So the body a machine attachment
// posts, and the body a sender older than the member posts, are both still
// the body a receiver has always accepted.

const SNAPSHOT = {
  deviceId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
  hostname: 'DevMac-01',
  capturedAt: 1_780_000_000_000,
  storePresent: true,
  schemaVersion: 14,
  findingsTotal: 5,
  findingsFirstAt: 1_700_000_000_000,
  findingsLastAt: 1_779_000_000_000,
  packs: [
    { packId: 'aka/secrets', version: '1.4.0', enabled: true, updatedAt: '1779000000000' },
    { packId: 'aka/pii', version: '0.9.0', enabled: false, updatedAt: null },
  ],
  policyCounts: {
    total: 3,
    disabled: 1,
    byAction: { warn: 2, redact: 0, block: 1, allow: 0, log: 0 },
  },
} satisfies StorePostureSnapshot;

/** The members the snapshot declared before the mode, in declaration order. */
const MEMBERS_BEFORE = [
  'deviceId',
  'hostname',
  'capturedAt',
  'storePresent',
  'schemaVersion',
  'findingsTotal',
  'findingsFirstAt',
  'findingsLastAt',
  'packs',
  'policyCounts',
  'plugin',
];

/** The members a body has to carry: every one of those but the optional `plugin`. */
const REQUIRED_BEFORE = MEMBERS_BEFORE.filter((member) => member !== 'plugin');

describe('StorePostureSnapshot.attachmentMode', () => {
  it('parses a body without the member, and leaves it absent', () => {
    const parsed = StorePostureSnapshot.parse(SNAPSHOT);
    expect(parsed).toEqual(SNAPSHOT);
    expect(Object.keys(parsed)).not.toContain('attachmentMode');
  });

  it.each(['scoped', 'machine'] as const)('parses a body that carries %s', (mode) => {
    // Only `scoped` is ever sent. `machine` parses too, so a sender that one
    // day spells it out breaks no receiver.
    expect(StorePostureSnapshot.parse({ ...SNAPSHOT, attachmentMode: mode })).toEqual({
      ...SNAPSHOT,
      attachmentMode: mode,
    });
  });

  it('is dropped, not refused, by a reader built before the member', () => {
    // An older reader's schema is this one without the member. Deriving it from
    // the live schema is the point: a `.strict()` added to the snapshot carries
    // over into the derived shape and fails here, where an older receiver would
    // refuse the whole report of every scoped device instead of ignoring the key.
    const olderReader = StorePostureSnapshot.omit({ attachmentMode: true });
    const result = olderReader.safeParse({ ...SNAPSHOT, attachmentMode: 'scoped' });
    if (!result.success) throw new Error('an older reader refused a body that carries the mode');
    expect(Object.keys(result.data)).not.toContain('attachmentMode');
    expect(result.data).toEqual(SNAPSHOT);
  });

  it.each<unknown>(['account', '', 'Scoped', null, 1])(
    'refuses the whole snapshot for a mode outside the vocabulary (%j)',
    (mode) => {
      // Why the reporter sends a constant and never the raw mode: a receiver
      // validating with this schema drops the entire report, liveness included.
      const result = StorePostureSnapshot.safeParse({ ...SNAPSHOT, attachmentMode: mode });
      expect(result.success).toBe(false);
    },
  );

  it("reuses the credential's AttachmentMode, so widening that vocabulary is a wire change", () => {
    const member = StorePostureSnapshot.shape.attachmentMode.unwrap();
    expect(member).toBe(AttachmentMode);
    expect(member.options).toEqual(['machine', 'scoped']);
  });

  it('is declared last, and optional: the members a body must carry are unchanged', () => {
    expect(Object.keys(StorePostureSnapshot.shape)).toEqual([...MEMBERS_BEFORE, 'attachmentMode']);
    // Generated against an EMPTY registry, so no shape carries an id and every
    // one is inlined. The default call files a root that has an id under $defs
    // and leaves only a $ref at the top, where `required` is undefined before
    // and after any change: a pin there would pin nothing.
    const json = z.toJSONSchema(StorePostureSnapshot, {
      metadata: z.registry<Record<string, unknown>>(),
    });
    expect(json.required).toEqual(REQUIRED_BEFORE);
    expect(json.properties?.attachmentMode).toEqual({
      type: 'string',
      enum: ['machine', 'scoped'],
    });
  });

  it('keeps the snapshot registered under its own id, and the mode under none', () => {
    // The mode publishes inline, inside the snapshot's component. An id would
    // register it as a component of its own.
    expect(StorePostureSnapshot.meta()?.id).toBe('StorePostureSnapshot');
    expect(AttachmentMode.meta()?.id).toBeUndefined();
  });
});
