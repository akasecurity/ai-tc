import type { LocalDatabase } from '@akasecurity/persistence';
import { describe, expect, it } from 'vitest';

import { readPostureBlock } from '../src/posture.ts';

// A minimal LocalDatabase stand-in: only the policies read + close() that
// readPostureBlock touches. Cast through unknown since the real interface has
// many more repositories the helper never uses.
function fakeDb(
  readPolicies: () => Promise<unknown>,
  onClose: () => void = () => undefined,
): Pick<LocalDatabase, 'policies' | 'close'> {
  return {
    policies: { readPolicies },
    close: onClose,
  } as unknown as Pick<LocalDatabase, 'policies' | 'close'>;
}

describe('readPostureBlock', () => {
  it('renders one row per category from the stored policies', async () => {
    const db = fakeDb(() =>
      Promise.resolve([
        { target: { category: 'secret' }, action: 'redact' },
        { target: { category: 'code_context' }, action: 'log' },
      ]),
    );
    const block = await readPostureBlock(db);
    expect(block).toContain('secret');
    expect(block).toContain('redact');
    // 'log' (ActionTaken) surfaces to the user as 'monitor'.
    expect(block).toContain('monitor');
  });

  it('degrades to an empty block (not a throw) when the policies read faults', async () => {
    let closed = false;
    const db = fakeDb(
      () => Promise.reject(new Error('store locked')),
      () => {
        closed = true;
      },
    );
    // The fault must NOT propagate — that would collapse the whole install card
    // into firstrun's fail-open note. It degrades to '' so only the Posture
    // section is hidden, and the handle is still closed.
    const block = await readPostureBlock(db);
    expect(block).toBe('');
    expect(closed).toBe(true);
  });

  it('closes the database handle on the happy path too', async () => {
    let closed = false;
    const db = fakeDb(
      () => Promise.resolve([]),
      () => {
        closed = true;
      },
    );
    await readPostureBlock(db);
    expect(closed).toBe(true);
  });
});
