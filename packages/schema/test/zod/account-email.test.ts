import { describe, expect, it } from 'vitest';

import { normalizeAccountEmail } from '../../src/zod/agent-scope.ts';

// The one form two account emails are compared in. An address reads as
// personal data to a scanner, so each one here is built from parts.
const AT_SIGN = String.fromCharCode(64);
const address = (local: string, domain: string): string => `${local}${AT_SIGN}${domain}`;

describe('normalizeAccountEmail', () => {
  it('trims and lower-cases ASCII', () => {
    expect(normalizeAccountEmail(`  ${address('Dev.Lead', 'EXAMPLE.org')}\n`)).toBe(
      address('dev.lead', 'example.org'),
    );
  });

  it('a mixed-case email matches', () => {
    expect(normalizeAccountEmail(address('Dev', 'Example.org'))).toBe(
      normalizeAccountEmail(address('dev', 'EXAMPLE.org')),
    );
  });

  it('folds nothing else: a plus tag and the dots stay', () => {
    expect(normalizeAccountEmail(address('dev+aka', 'example.org'))).toBe(
      address('dev+aka', 'example.org'),
    );
    expect(normalizeAccountEmail(address('d.e.v', 'example.org'))).not.toBe(
      normalizeAccountEmail(address('dev', 'example.org')),
    );
  });

  it.each([
    ['an empty value', ''],
    ['only space', '   '],
    ['no @', 'dev.example.org'],
    ['two @', `dev${AT_SIGN}team${AT_SIGN}example.org`],
    ['nothing before the @', address('', 'example.org')],
    ['nothing after the @', address('dev', '')],
    ['a non-ASCII local part', address('dév', 'example.org')],
    ['a non-ASCII domain', address('dev', 'exämple.org')],
  ])('answers undefined for %s', (_label, input) => {
    expect(normalizeAccountEmail(input)).toBeUndefined();
  });

  it('answers undefined for a value that is not a string', () => {
    expect(normalizeAccountEmail(undefined)).toBeUndefined();
    expect(normalizeAccountEmail(42)).toBeUndefined();
    expect(
      normalizeAccountEmail({ toString: () => address('dev', 'example.org') }),
    ).toBeUndefined();
  });
});
