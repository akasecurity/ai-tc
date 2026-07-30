// Tests the pure pointer-substitution decision module directly — NEVER via a
// hook entry file (src/hooks/*.ts entry modules run main() on import and hang
// vitest collection). The substitute function is stubbed: its contract is the
// SubstitutePointersResult shape, and grants/auditing are its business.
import { describe, expect, it, vi } from 'vitest';

import type { PointerField, PointerFieldOutcome } from '../../src/hooks/pointer-substitution.ts';
import { decideInputPointers, denyPointerMessage } from '../../src/hooks/pointer-substitution.ts';

// A well-formed wire pointer: [[aka:<category>:<b32 key_version>.<b32 id ×26>.<b32 tag ×16>]].
// `seed` must be a base32 character (A-Z, 2-7); distinct seeds give distinct pointers.
function pointer(seed: string): string {
  return `[[aka:secret:AA.${seed.repeat(26)}.${'B'.repeat(16)}]]`;
}

const P1 = pointer('C');
const P2 = pointer('D');
const RAW = 'sk-live-raw-value';

type Substitute = Parameters<typeof decideInputPointers>[1];

function field(
  text: string,
  executable: boolean,
  path: (string | number)[] = ['command'],
): PointerField {
  return { path, text, executable };
}

function only(outcomes: PointerFieldOutcome[]): PointerFieldOutcome {
  const first = outcomes[0];
  if (outcomes.length !== 1 || first === undefined) {
    throw new Error(`expected exactly one outcome, got ${String(outcomes.length)}`);
  }
  return first;
}

describe('decideInputPointers — data fields', () => {
  it('keeps the literal pointer when nothing was revealed, with no text property', async () => {
    const text = `token: ${P1}`;
    const substitute: Substitute = (t) =>
      Promise.resolve({ text: t, revealed: [], unresolved: [P1] });

    const outcome = only(await decideInputPointers([field(text, false, ['content'])], substitute));
    expect(outcome.disposition).toBe('keep');
    expect(outcome.path).toEqual(['content']);
    expect('text' in outcome).toBe(false);
  });

  it('derefs with the substituted text when a grant revealed the pointer', async () => {
    const rewritten = `token: ${RAW}`;
    const substitute: Substitute = () =>
      Promise.resolve({ text: rewritten, revealed: [P1], unresolved: [] });

    const outcome = only(
      await decideInputPointers([field(`token: ${P1}`, false, ['content'])], substitute),
    );
    expect(outcome.disposition).toBe('deref');
    expect(outcome.text).toBe(rewritten);
  });

  it('derefs with the partial text when some pointers revealed and some stayed literal', async () => {
    const partial = `a=${RAW} b=${P2}`;
    const substitute: Substitute = () =>
      Promise.resolve({ text: partial, revealed: [P1], unresolved: [P2] });

    const outcome = only(
      await decideInputPointers([field(`a=${P1} b=${P2}`, false, ['content'])], substitute),
    );
    expect(outcome.disposition).toBe('deref');
    expect(outcome.text).toBe(partial);
  });

  it('keeps the field when substitute throws', async () => {
    const substitute: Substitute = () => Promise.reject(new Error('vault unavailable'));

    const outcome = only(
      await decideInputPointers([field(`token: ${P1}`, false, ['content'])], substitute),
    );
    expect(outcome.disposition).toBe('keep');
    expect('text' in outcome).toBe(false);
  });
});

describe('decideInputPointers — executable fields', () => {
  it('denies an ungranted pointer with NO text property', async () => {
    const substitute: Substitute = (t) =>
      Promise.resolve({ text: t, revealed: [], unresolved: [P1] });

    const outcome = only(await decideInputPointers([field(`echo ${P1}`, true)], substitute));
    expect(outcome.disposition).toBe('deny');
    expect('text' in outcome).toBe(false);
  });

  it('derefs when every pointer resolved under a grant', async () => {
    const rewritten = `echo ${RAW}`;
    const substitute: Substitute = () =>
      Promise.resolve({ text: rewritten, revealed: [P1], unresolved: [] });

    const outcome = only(await decideInputPointers([field(`echo ${P1}`, true)], substitute));
    expect(outcome.disposition).toBe('deref');
    expect(outcome.text).toBe(rewritten);
  });

  it('denies a mixed revealed+unresolved field and never leaks the partial rewrite', async () => {
    // substitute's rewrite already contains the granted RAW value; the deny
    // must not carry it anywhere.
    const partial = `curl -H "x: ${RAW}" ${P2}`;
    const substitute: Substitute = () =>
      Promise.resolve({ text: partial, revealed: [P1], unresolved: [P2] });

    const outcomes = await decideInputPointers(
      [field(`curl -H "x: ${P1}" ${P2}`, true)],
      substitute,
    );
    const outcome = only(outcomes);
    expect(outcome.disposition).toBe('deny');
    expect('text' in outcome).toBe(false);
    expect(JSON.stringify(outcomes)).not.toContain(RAW);
  });

  it('denies when substitute throws', async () => {
    const substitute: Substitute = () => Promise.reject(new Error('vault unavailable'));

    const outcome = only(await decideInputPointers([field(`echo ${P1}`, true)], substitute));
    expect(outcome.disposition).toBe('deny');
    expect('text' in outcome).toBe(false);
  });
});

describe('decideInputPointers — field selection and independence', () => {
  it('yields no outcome for pointer-free fields and never calls substitute for them', async () => {
    const substitute = vi.fn<Substitute>((t) =>
      Promise.resolve({ text: t, revealed: [], unresolved: [] }),
    );

    const outcomes = await decideInputPointers(
      [
        field('echo plain', true),
        field('no pointers here either', false, ['content']),
        // A lookalike with an invented category must not parse as a pointer.
        field(`[[aka:notacategory:AA.${'C'.repeat(26)}.${'B'.repeat(16)}]]`, true),
      ],
      substitute,
    );

    expect(outcomes).toEqual([]);
    expect(substitute).not.toHaveBeenCalled();
  });

  it('processes multiple fields independently in one call', async () => {
    const substitute = vi.fn<Substitute>((t) =>
      t.includes(P1)
        ? Promise.resolve({ text: t.replace(P1, RAW), revealed: [P1], unresolved: [] })
        : Promise.resolve({ text: t, revealed: [], unresolved: [P2] }),
    );

    const outcomes = await decideInputPointers(
      [
        field(`echo ${P1}`, true, ['command']),
        field(`body ${P2}`, false, ['content']),
        field('plain text', false, ['prompt']),
        field(`run ${P2}`, true, ['url']),
      ],
      substitute,
    );

    expect(substitute).toHaveBeenCalledTimes(3);
    expect(outcomes).toEqual([
      { path: ['command'], disposition: 'deref', text: `echo ${RAW}` },
      { path: ['content'], disposition: 'keep' },
      { path: ['url'], disposition: 'deny' },
    ]);
  });
});

describe('denyPointerMessage', () => {
  it('names the tool, the reason, and the escape hatch', () => {
    const message = denyPointerMessage('Bash');
    expect(message).toContain('A vault pointer in a Bash command cannot execute as text');
    expect(message).toContain('aka exception approve');
    expect(message).toContain('remove the pointer');
  });
});
