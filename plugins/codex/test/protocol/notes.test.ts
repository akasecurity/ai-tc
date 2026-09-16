// The model-protocol note builders: realized-only truthfulness (a note never
// names a pointer that was not minted, and a degraded field never reads as
// recoverable), the enumeration cap, the standing brief's hard token budget,
// and the user disclosure's recoverable-vs-degraded copy.
import {
  VAULT_BRIEF_TOKEN_BUDGET,
  VAULT_EVENT_NOTE_MAX_POINTERS,
  VaultInlineReveal,
} from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import type { RealizedPointer, RealizedRewrite } from '../../src/protocol/notes.ts';
import {
  estimatedTokens,
  eventNote,
  standingBrief,
  userDisclosure,
} from '../../src/protocol/notes.ts';

const MARKER = 'deadbeef01234567';

// Plausible wire tokens (shape only — the builders treat them as opaque).
function fakeToken(n: number): string {
  const id = n.toString(36).toUpperCase().padStart(2, 'A');
  return `[[aka:secret:AA.${id.repeat(13)}.${'B'.repeat(16)}]]`;
}

function pointer(n: number, overrides: Partial<RealizedPointer> = {}): RealizedPointer {
  return { token: fakeToken(n), category: 'secret', ...overrides };
}

function occurrences(haystack: string, needle: string): number {
  return haystack.split(needle).length - 1;
}

describe('eventNote', () => {
  it('returns null when nothing was rewritten', () => {
    expect(
      eventNote({ marker: MARKER, surface: 'Bash', realized: { pointers: [], degraded: [] } }),
    ).toBeNull();
  });

  it('lists each minted pointer verbatim with its category and provider', () => {
    const realized: RealizedRewrite = {
      pointers: [
        pointer(1, { provider: 'aws' }),
        {
          token: '[[aka:config:AA.CCCCCCCCCCCCCCCCCCCCCCCCCC.DDDDDDDDDDDDDDDD]]',
          category: 'config',
        },
      ],
      degraded: [],
    };
    const note = eventNote({ marker: MARKER, surface: 'Bash', realized });
    expect(note).not.toBeNull();
    expect(note).toContain(fakeToken(1));
    expect(note).toContain('(secret/aws)');
    expect(note).toContain('(config)');
    expect(note).toContain('replaced 2 values');
    expect(note).toContain('verbatim');
    expect(note).toContain('Never fabricate');
    // No degraded copy on a pointer-only event.
    expect(note).not.toContain('irreversibly');
  });

  it('degraded-only: contains no pointer literal and claims no recoverability', () => {
    const note = eventNote({
      marker: MARKER,
      surface: 'Bash',
      realized: { pointers: [], degraded: [{ category: 'secret' }] },
    });
    expect(note).not.toBeNull();
    const text = note ?? '';
    expect(text).not.toContain('[[aka:');
    expect(text).toContain('removed 1 value');
    expect(text).toContain('(secret)');
    expect(text).toContain('redacted irreversibly');
    expect(text).toContain('no pointer exists');
    expect(text).toContain('Do not invent one');
    // Never any recovery hint: the value is gone.
    expect(text).not.toMatch(/recover|vault show|dashboard/i);
  });

  it('mixed events state both outcomes truthfully', () => {
    const note = eventNote({
      marker: MARKER,
      surface: 'Read',
      realized: { pointers: [pointer(1)], degraded: [{ category: 'pii' }] },
    });
    const text = note ?? '';
    expect(text).toContain(fakeToken(1));
    expect(text).toContain('replaced 1 value');
    expect(text).toContain('removed 1 value');
    expect(text).toContain('redacted irreversibly');
  });

  it(`enumerates at most ${String(VAULT_EVENT_NOTE_MAX_POINTERS)} pointers, then "and N more"`, () => {
    const many = Array.from({ length: VAULT_EVENT_NOTE_MAX_POINTERS + 3 }, (_, i) => pointer(i));
    const note = eventNote({
      marker: MARKER,
      surface: 'Bash',
      realized: { pointers: many, degraded: [] },
    });
    const text = note ?? '';
    expect(occurrences(text, '[[aka:')).toBe(VAULT_EVENT_NOTE_MAX_POINTERS);
    expect(text).toContain('and 3 more');
    // The total count stays truthful even when the list is capped.
    expect(text).toContain(`replaced ${String(VAULT_EVENT_NOTE_MAX_POINTERS + 3)} values`);
  });

  it('carries the marker exactly once, at the head', () => {
    const note = eventNote({
      marker: MARKER,
      surface: 'Bash',
      realized: { pointers: [pointer(1)], degraded: [{ category: 'secret' }] },
    });
    const text = note ?? '';
    expect(text.startsWith(`[AKA ${MARKER}] Bash:`)).toBe(true);
    expect(occurrences(text, MARKER)).toBe(1);
  });
});

describe('standingBrief', () => {
  const variants = VaultInlineReveal.options;

  it.each(variants)('fits the token budget under inlineReveal=%s', (inlineReveal) => {
    const brief = standingBrief({ marker: MARKER, inlineReveal });
    expect(estimatedTokens(brief)).toBeLessThanOrEqual(VAULT_BRIEF_TOKEN_BUDGET);
    expect(estimatedTokens(brief)).toBe(Math.ceil(brief.length / 4));
  });

  it.each(variants)(
    'carries the protocol rules and the marker under inlineReveal=%s',
    (inlineReveal) => {
      const brief = standingBrief({ marker: MARKER, inlineReveal });
      expect(brief).toContain(MARKER);
      expect(occurrences(brief, MARKER)).toBe(1);
      expect(brief).toContain('[[aka:<category>:...]]');
      expect(brief).toContain('verbatim');
      expect(brief).toContain('fabricate');
      expect(brief).toContain('never ask the user to re-send');
      expect(brief).toContain('untrusted data');
      expect(brief).toContain('never repeat it in your own output');
    },
  );

  it("'full' mentions inline visibility AND the CLI/dashboard path, hedged with 'may'", () => {
    const brief = standingBrief({ marker: MARKER, inlineReveal: 'full' });
    expect(brief).toContain('may appear inline');
    expect(brief).toContain('aka vault show');
    expect(brief).toContain('AKA dashboard');
  });

  it.each(['masked', 'off'] as const)(
    "'%s' names only the CLI/dashboard path, no inline claim",
    (inlineReveal) => {
      const brief = standingBrief({ marker: MARKER, inlineReveal });
      expect(brief).not.toContain('inline');
      expect(brief).not.toContain('terminal');
      expect(brief).toContain('aka vault show');
      expect(brief).toContain('AKA dashboard');
    },
  );
});

describe('userDisclosure', () => {
  it('returns null when nothing was rewritten', () => {
    expect(
      userDisclosure({ surface: 'Bash output', realized: { pointers: [], degraded: [] } }),
    ).toBeNull();
  });

  it('replaced values read as recoverable via the vault', () => {
    const line = userDisclosure({
      surface: 'Bash output',
      realized: { pointers: [pointer(1), pointer(2, { category: 'config' })], degraded: [] },
    });
    const text = line ?? '';
    expect(text).toContain('replaced 2 values');
    expect(text).toContain('secret, config');
    expect(text).toContain('kept recoverable in your local vault');
    expect(text).toContain('aka vault show');
    expect(text).toContain('AKA dashboard');
    expect(text).not.toContain('irreversibly');
    // The user line never carries wire tokens.
    expect(text).not.toContain('[[aka:');
  });

  it('degraded values read as irreversible, with no recovery pointer', () => {
    const line = userDisclosure({
      surface: 'prompt',
      realized: { pointers: [], degraded: [{ category: 'secret' }] },
    });
    const text = line ?? '';
    expect(text).toContain('removed 1 value');
    expect(text).toContain('redacted irreversibly');
    expect(text).toContain('the vault was unavailable');
    expect(text).not.toMatch(/recoverable|vault show/);
  });

  it('mixed outcomes state both, each with its own recoverability', () => {
    const line = userDisclosure({
      surface: 'Bash output',
      realized: { pointers: [pointer(1)], degraded: [{ category: 'pii' }] },
    });
    const text = line ?? '';
    expect(text).toContain('kept recoverable');
    expect(text).toContain('redacted irreversibly');
  });
});
