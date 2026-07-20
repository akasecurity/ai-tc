import { Rule } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { redact, scan } from '../../src/index.ts';

// Parsed through the real schema — these assert the shipped path end to end
// (scan -> span -> rawMatch -> redact), not just a matcher in isolation.
function keywordRule(keywords: string[], id = 'test-pack/kw'): Rule {
  return Rule.parse({
    specVersion: 1,
    id,
    name: 'test',
    category: 'secret',
    severity: 'high',
    matcher: { type: 'keyword', keywords },
  });
}

function regexRule(pattern: string, id = 'test-pack/re'): Rule {
  return Rule.parse({
    specVersion: 1,
    id,
    name: 'test',
    category: 'secret',
    severity: 'high',
    matcher: { type: 'regex', pattern, flags: 'gi' },
  });
}

function slices(text: string, rules: Rule[]): string[] {
  return scan(text, rules).map((f) => text.slice(f.span.start, f.span.end));
}

// Characters whose case-folded form differs in length from the source, plus
// astral and bidi text. Any of these ahead of a match used to shift its span.
const SHIFTING_CHARS: readonly (readonly [string, string])[] = [
  ['U+0130 dotted capital I', 'İ'],
  ['U+FB01 fi ligature', 'ﬁ'],
  ['U+1E9E capital sharp s', 'ẞ'],
  ['U+0587 armenian ech-yiwn', 'և'],
  ['astral emoji', '🔑'],
  ['combining acute', 'é'],
  ['RTL override', '‮'],
];

describe('unicode span integrity', () => {
  it('does not shift a keyword span after a length-changing lowercase char', () => {
    // Regression: the matcher searched text.toLowerCase() but sized the span
    // with the original keyword's length. "İ".toLowerCase() is two code units,
    // so every span after it was off by one — redact() then masked from one
    // char late, leaving the match's first character in the output.
    const text = 'İ my password is hunter2';
    const findings = scan(text, [keywordRule(['password'])]);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.span).toEqual({ start: 5, end: 13 });
    expect(findings[0]?.rawMatch).toBe('password');
    expect(redact(text, findings)).toBe('İ my [REDACTED:SECRET] is hunter2');
  });

  it.each(SHIFTING_CHARS)('keeps the span aligned with %s before the match', (_label, char) => {
    const text = `${char} my password is hunter2`;
    expect(slices(text, [keywordRule(['password'])])).toEqual(['password']);
    expect(scan(text, [keywordRule(['password'])])[0]?.rawMatch).toBe('password');
  });

  it.each(SHIFTING_CHARS)('keeps the span aligned with %s inside the text', (_label, char) => {
    const text = `a ${char} b password c`;
    expect(slices(text, [keywordRule(['password'])])).toEqual(['password']);
  });

  it('keeps regex spans aligned after a length-changing char', () => {
    const text = 'İ token=abc123def';
    expect(slices(text, [regexRule('token=[a-z0-9]+')])).toEqual(['token=abc123def']);
  });
});

describe('redaction containment', () => {
  // Asserted against the keyword we planted, never against finding.rawMatch:
  // engine.ts derives rawMatch by slicing the span it is given, so a finding is
  // self-consistent even when its span is wrong. Comparing the two only proves
  // slice() works. Ground truth is the only thing that catches a shifted span.
  it('never leaves a planted secret in the redacted output', () => {
    const secrets = ['password', 'secret'];
    const rules = [keywordRule(['password']), keywordRule(['secret'], 'test-pack/kw2')];
    let checked = 0;

    for (const [, char] of SHIFTING_CHARS) {
      for (const template of [
        `${char} my password is x`,
        `my password ${char} is secret`,
        `${char}${char} password secret ${char}`,
        `password ${char} secret`,
        `${char} secret`,
      ]) {
        const findings = scan(template, rules);
        const output = redact(template, findings);

        for (const secret of secrets) {
          if (!template.includes(secret)) continue;
          // Every planted secret is present, so every one must be found...
          expect(findings.some((f) => f.rawMatch === secret)).toBe(true);
          // ...and none may survive redaction, whole or in part.
          expect(output).not.toContain(secret);
          expect(output).not.toContain(secret.slice(1));
          checked++;
        }
      }
    }

    expect(checked).toBeGreaterThan(30);
  });

  it('does not leak the first character when a match follows a shifting char', () => {
    // The exact failure shape of the original bug: a one-char shift left the
    // match's leading character outside the redacted region.
    for (const [, char] of SHIFTING_CHARS) {
      const text = `${char} my password is hunter2`;
      const output = redact(text, scan(text, [keywordRule(['password'])]));
      expect(output).not.toContain('assword');
      expect(output).not.toContain('p[REDACTED');
    }
  });
});

describe('non-ascii inputs do not corrupt spans', () => {
  it('matches a keyword surrounded by astral characters', () => {
    expect(slices('🔑🔑 password 🔑🔑', [keywordRule(['password'])])).toEqual(['password']);
  });

  it('tolerates a lone surrogate without throwing or mislocating', () => {
    expect(slices('\ud800 password', [keywordRule(['password'])])).toEqual(['password']);
  });

  it('scans an empty string without matches', () => {
    expect(scan('', [keywordRule(['password'])])).toEqual([]);
  });
});
