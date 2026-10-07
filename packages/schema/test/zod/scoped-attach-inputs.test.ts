import { describe, expect, it } from 'vitest';

import type { ConnectionRefusal } from '../../src/zod/managed.ts';
import { connectionRefusalMessage } from '../../src/zod/managed.ts';
import { AttachInput } from '../../src/zod/settings-action.ts';

// Two pieces of the contract a scoped attach is written through: the refusal a
// managed machine answers a scoped attach with, worded once for the terminal and
// the page, and the mode the dashboard's attach form posts.

describe('the scoped-managed refusal', () => {
  it('names the administrator and says why the attach cannot be scoped', () => {
    const refusal: ConnectionRefusal = { reason: 'scoped-managed', organization: 'Example Org' };
    expect(connectionRefusalMessage(refusal)).toBe(
      'Example Org manages this machine, so it attaches machine-wide and cannot be limited ' +
        'to the repositories you enroll.',
    );
  });

  it('still names an administrator, at the start of the sentence, when the file names none', () => {
    const message = connectionRefusalMessage({ reason: 'scoped-managed' });
    expect(message.startsWith('Your organization manages this machine')).toBe(true);
    expect(message).not.toContain('undefined');
  });

  it('names no flag and no control, so the same sentence is true in a terminal and on a page', () => {
    const message = connectionRefusalMessage({ reason: 'scoped-managed' });
    expect(message).not.toMatch(/--|button|click|select/i);
  });
});

describe('AttachInput.mode', () => {
  const BASE = { endpoint: 'https://plane.example.test', accessKey: 'placeholder' };

  it('is optional, and an input without it parses with no mode key', () => {
    // A page built before the choice existed must still post a valid input.
    expect(AttachInput.parse(BASE)).toStrictEqual(BASE);
  });

  it.each(['machine', 'scoped'] as const)('accepts %s', (mode) => {
    expect(AttachInput.parse({ ...BASE, mode })).toStrictEqual({ ...BASE, mode });
  });

  it.each([['everything'], ['Scoped'], [''], [1], [null], [true]])(
    'refuses %j rather than stripping it',
    (mode) => {
      // Refused, not stripped: a mode this build does not know must not arrive
      // at the action as "no mode", which the action reads as its own default.
      expect(AttachInput.safeParse({ ...BASE, mode }).success).toBe(false);
    },
  );
});
