import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { ConnectionRefusal } from '@akasecurity/schema';
import { connectionRefusalMessage } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { refusalLine } from '../../src/lib/refusal-line.ts';

// A refusal's organization and pinned endpoint come from an administrator's
// file, and nothing in the schema keeps control characters out of either. Every
// command that prints a refusal goes through this function.

const ESC = String.fromCharCode(0x1b);
const ZERO_WIDTH_SPACE = String.fromCharCode(0x200b);
const ENDPOINT = 'https://aka.example.com/gateway';

describe('refusalLine', () => {
  it.each<ConnectionRefusal>([
    { reason: 'held-standalone', organization: 'Example IT' },
    { reason: 'pinned-endpoint', organization: 'Example IT', endpoint: ENDPOINT },
    { reason: 'pinned-label', organization: 'Example IT' },
    { reason: 'label-required', organization: 'Example IT' },
    { reason: 'held-attached', organization: 'Example IT', endpoint: ENDPOINT },
    { reason: 'scoped-managed', organization: 'Example IT' },
    { reason: 'scoped-managed' },
  ])('says what the schema says when there is nothing to strip (%j)', (refusal) => {
    expect(refusalLine(refusal)).toBe(connectionRefusalMessage(refusal));
  });

  it('strips control and format characters from the organization', () => {
    const line = refusalLine({
      reason: 'scoped-managed',
      organization: `Example${ESC}[2J${ZERO_WIDTH_SPACE} IT`,
    });
    expect(line).toBe(
      connectionRefusalMessage({ reason: 'scoped-managed', organization: 'Example[2J IT' }),
    );
    expect(line).not.toContain(ESC);
    expect(line).not.toContain(ZERO_WIDTH_SPACE);
  });

  it.each(['pinned-endpoint', 'held-attached'] as const)(
    'strips control characters from the endpoint a %s refusal names',
    (reason) => {
      const line = refusalLine({
        reason,
        organization: 'Example IT',
        endpoint: `${ENDPOINT}${ESC}[2J`,
      });
      expect(line).toBe(
        connectionRefusalMessage({
          reason,
          organization: 'Example IT',
          endpoint: `${ENDPOINT}[2J`,
        }),
      );
      expect(line).not.toContain(ESC);
    },
  );

  it('shows an organization or an endpoint of two hundred characters whole, and cuts a longer one', () => {
    const whole = 'o'.repeat(200);
    expect(refusalLine({ reason: 'scoped-managed', organization: whole })).toContain(
      `${whole} manages`,
    );
    const line = refusalLine({
      reason: 'pinned-endpoint',
      organization: 'o'.repeat(201),
      endpoint: `https://${'h'.repeat(300)}`,
    });
    expect(line).toContain(`${'o'.repeat(200)}…`);
    expect(line).not.toContain('o'.repeat(201));
    expect(line).not.toContain('h'.repeat(300));
  });

  it('does not change the refusal it is given', () => {
    const refusal: ConnectionRefusal = {
      reason: 'pinned-endpoint',
      organization: `Example${ESC}`,
      endpoint: `${ENDPOINT}${ESC}`,
    };
    refusalLine(refusal);
    expect(refusal).toEqual({
      reason: 'pinned-endpoint',
      organization: `Example${ESC}`,
      endpoint: `${ENDPOINT}${ESC}`,
    });
  });
});

// The strip only helps if nothing prints a refusal without it. The schema's own
// sentence stays exported, so what keeps a command from calling it directly is
// this test: only the module that strips may name it.
describe('who may name connectionRefusalMessage', () => {
  const SRC = fileURLToPath(new URL('../../src/', import.meta.url));
  const sources = readdirSync(SRC, { recursive: true, encoding: 'utf8' })
    .map((file) => file.replaceAll('\\', '/'))
    .filter((file) => file.endsWith('.ts'));

  it('finds the commands that print a refusal, so the search is not empty', () => {
    expect(sources).toEqual(
      expect.arrayContaining(['commands/attach.ts', 'commands/enroll.ts', 'lib/refusal-line.ts']),
    );
  });

  it('is named by the strip module alone', () => {
    const naming = sources.filter((file) =>
      /\bconnectionRefusalMessage\b/.test(readFileSync(join(SRC, file), 'utf8')),
    );
    expect(naming).toEqual(['lib/refusal-line.ts']);
  });

  it.each(['commands/attach.ts', 'commands/enroll.ts'])(
    'has %s print through refusalLine',
    (file) => {
      expect(readFileSync(join(SRC, file), 'utf8')).toMatch(/\brefusalLine\(/);
    },
  );
});
