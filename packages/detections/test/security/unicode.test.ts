import { resolve } from 'node:path';

import { Rule } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { redact, scan } from '../../src/index.ts';
import { loadRule, RULES_DIR } from '../helpers/rules.ts';

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

// A representative sample of \p{Cf} — see src/format-chars.ts for the full
// 170-member category. One invisible character from any of these families,
// inserted mid-secret, used to defeat every regex/keyword rule while leaving
// the secret usable after trivial cleanup.
const INVISIBLE_FORMAT_CHARS: readonly (readonly [string, string])[] = [
  ['U+200B zero width space', '​'],
  ['U+200C zero width non-joiner', '‌'],
  ['U+200D zero width joiner', '‍'],
  ['U+2060 word joiner', '⁠'],
  ['U+FEFF byte order mark', '﻿'],
  ['U+00AD soft hyphen', '­'],
  ['U+202E right-to-left override', '‮'],
  ['U+2066 left-to-right isolate', '⁦'],
  ['U+E0020 tag space', '\u{E0020}'],
];

describe('invisible format characters inside a match', () => {
  const githubPat = loadRule(resolve(RULES_DIR, 'secrets'), 'github-pat');
  const awsAccessKey = loadRule(resolve(RULES_DIR, 'secrets'), 'aws-access-key');
  const devPlaceholderSecret = loadRule(resolve(RULES_DIR, 'code-flaws'), 'dev-placeholder-secret');
  // Kept as its own plain-quoted constant, referenced with `${ZWSP}` below,
  // rather than written directly inside a template literal — ESLint's
  // `no-irregular-whitespace` (correctly) flags a raw zero-width space
  // sitting literally inside a template, and this is precisely the character
  // family this whole fix is about.
  const ZWSP = '​';

  it('still detects a known secret rule (GitHub PAT) with a ZWSP inserted mid-secret', () => {
    // Fixture secret from rules/secrets/fixtures/github-pat.json, split with a
    // zero-width space planted in the middle of the 36-char body.
    const body = 'aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890';
    const withZwsp = `ghp_${body.slice(0, 18)}${ZWSP}${body.slice(18)}`;
    const text = `token: ${withZwsp}`;

    const findings = scan(text, [githubPat]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('secrets/github-pat');
  });

  it('maps the finding span onto the original text, covering the inserted character', () => {
    const body = 'aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890';
    const withZwsp = `ghp_${body.slice(0, 18)}${ZWSP}${body.slice(18)}`;
    const text = `token: ${withZwsp}`;

    const [finding] = scan(text, [githubPat]);
    expect(finding).toBeDefined();
    if (!finding) return;

    // The span, sliced out of the ORIGINAL text, must reproduce the whole
    // matched secret including the zero-width space sitting inside it.
    const sliced = text.slice(finding.span.start, finding.span.end);
    expect(sliced).toBe(withZwsp);
    expect(sliced).toContain(ZWSP);
    // And the span is where the secret actually sits in the original string,
    // not shifted by the character stripped ahead of it.
    expect(finding.span).toEqual({ start: 7, end: 7 + withZwsp.length });
  });

  it('redacts the whole secret with no remnant, including the split halves', () => {
    const body = 'aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890';
    const withZwsp = `ghp_${body.slice(0, 18)}${ZWSP}${body.slice(18)}`;
    const text = `token: ${withZwsp} end`;

    const findings = scan(text, [githubPat]);
    const output = redact(text, findings);

    expect(output).not.toContain(ZWSP);
    expect(output).not.toContain(body.slice(0, 18));
    expect(output).not.toContain(body.slice(18));
    expect(output).toBe('token: [REDACTED:SECRET] end');
  });

  it('leaves a text with no format characters completely unaffected', () => {
    const text = 'token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890 end';
    const findings = scan(text, [githubPat]);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.span).toEqual({ start: 7, end: 7 + 40 });
    expect(findings[0]?.rawMatch).toBe('ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890');
    expect(redact(text, findings)).toBe('token: [REDACTED:SECRET] end');
  });

  it('still corroborates a keyword rule via requiresNearby when the KEYWORD itself carries a format char', () => {
    // rules/code-flaws/dev-placeholder-secret.json: keyword "changeme", gated on
    // a "key"/"secret"/"password"/"token" label within 80 chars. The zero-width
    // space sits inside the keyword match itself.
    const text = `SECRET_KEY = 'change${ZWSP}me'`;
    const findings = scan(text, [devPlaceholderSecret]);
    const finding = findings[0];

    expect(findings).toHaveLength(1);
    expect(finding?.ruleId).toBe('code-flaws/dev-placeholder-secret');
    expect(finding && text.slice(finding.span.start, finding.span.end)).toBe(`change${ZWSP}me`);
  });

  it('still corroborates via requiresNearby when the LABEL carries a format char', () => {
    const text = `api_se${ZWSP}cret = 'changeme'`;
    const findings = scan(text, [devPlaceholderSecret]);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('code-flaws/dev-placeholder-secret');
  });

  it('runs entropy post-validation against the clean value, not the one with a format char mixed in', () => {
    // rules/secrets/aws-access-key.json requires the "entropy" post-validator.
    // If the invisible character were left in the value handed to the
    // validator it would be scored as part of the secret's character content.
    const secret = 'AKIAIOSFODNN7EXAMPLE';
    const withZwsp = `${secret.slice(0, 10)}${ZWSP}${secret.slice(10)}`;
    const text = `const key = "${withZwsp}";`;

    const findings = scan(text, [awsAccessKey]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('secrets/aws-access-key');
  });

  it.each(INVISIBLE_FORMAT_CHARS)(
    'detects the secret with %s inserted mid-value',
    (_label, char) => {
      const secret = 'AKIAIOSFODNN7EXAMPLE';
      const withChar = `${secret.slice(0, 10)}${char}${secret.slice(10)}`;
      const text = `const key = "${withChar}";`;

      const findings = scan(text, [awsAccessKey]);
      expect(findings).toHaveLength(1);
      const finding = findings[0];
      const sliced = finding && text.slice(finding.span.start, finding.span.end);
      expect(sliced).toBe(withChar);

      const output = redact(text, findings);
      expect(output).not.toContain(secret.slice(0, 10));
      expect(output).not.toContain(secret.slice(10));
    },
  );
});

// Regression guard: normalizing text before matching must never make a
// bundled \b-anchored rule miss a secret main (with no normalization at all)
// already detects. JS's `\b` treats a \p{Cf} character as non-word — the SAME
// property that lets it split a secret in two also lets it SATISFY a `\b`
// between a word character and the secret when nothing else would. Stripping
// it can silently remove that boundary: a word char, a ZWSP, then "AKIA..."
// matches `\b(AKIA|...)…` on the ORIGINAL text (ZWSP is non-word, so there is
// a word/non-word transition right before "AKIA"), but on the stripped
// "xAKIA..." there is no such transition at all — a rule that matched before
// this package normalized ANYTHING must still match after.
describe('a format character must not remove a boundary main relies on', () => {
  const githubPat = loadRule(resolve(RULES_DIR, 'secrets'), 'github-pat');
  const awsAccessKey = loadRule(resolve(RULES_DIR, 'secrets'), 'aws-access-key');
  const devPlaceholderSecret = loadRule(resolve(RULES_DIR, 'code-flaws'), 'dev-placeholder-secret');
  const ZWSP = '​';

  it('still detects an AWS key preceded by <word char><format char>', () => {
    const secret = 'AKIAIOSFODNN7EXAMPLE';
    const text = `const key = "x${ZWSP}${secret}";`;

    const findings = scan(text, [awsAccessKey]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.rawMatch).toBe(secret);
  });

  it('still detects an AWS key followed by <format char><word char>', () => {
    const secret = 'AKIAIOSFODNN7EXAMPLE';
    const text = `const key = "${secret}${ZWSP}x";`;

    const findings = scan(text, [awsAccessKey]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.rawMatch).toBe(secret);
  });

  it('still detects a GitHub PAT preceded by <word char><format char>', () => {
    const secret = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890';
    const text = `token: x${ZWSP}${secret}`;

    const findings = scan(text, [githubPat]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.rawMatch).toBe(secret);
  });

  it('still detects a GitHub PAT followed by <format char><word char>', () => {
    const secret = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890';
    const text = `token: ${secret}${ZWSP}x`;

    const findings = scan(text, [githubPat]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.rawMatch).toBe(secret);
  });

  it('still corroborates via requiresNearby when a word char + format char sits right before the label', () => {
    // rules/code-flaws/dev-placeholder-secret.json's label boundary is
    // `(?<![A-Za-z0-9])label(?![A-Za-z0-9])` — the exact same non-word-neighbor
    // test as `\b`, so it is subject to the identical regression: on the
    // original text the ZWSP satisfies the lookbehind (not preceded by an
    // alnum); stripped, the word char right before "key" does not.
    const text = `abc${ZWSP}key = 'changeme'`;
    const findings = scan(text, [devPlaceholderSecret]);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('code-flaws/dev-placeholder-secret');
  });

  it('still detects a secret with a format character at the very start of the text', () => {
    const secret = 'AKIAIOSFODNN7EXAMPLE';
    const text = `${ZWSP}${secret}`;

    const findings = scan(text, [awsAccessKey]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.rawMatch).toBe(secret);
  });

  it('still detects a secret with a format character at the very end of the text', () => {
    const secret = 'AKIAIOSFODNN7EXAMPLE';
    const text = `${secret}${ZWSP}`;

    const findings = scan(text, [awsAccessKey]);
    expect(findings).toHaveLength(1);
    // Not a strict equality: the original-text pass matches exactly `secret`
    // (the trailing ZWSP sits outside `\b`), while the normalized-text pass
    // maps to a span reaching the text's own end (see format-chars.test.ts),
    // which is WIDER and so wins the same-rule dedup. Either way the secret
    // itself must be present and covered.
    expect(findings[0]?.rawMatch).toContain(secret);
  });

  it('reports exactly one finding, not two, when both passes detect the same occurrence', () => {
    // The dual-pass fix must not double-report: an original-text match and a
    // normalized-text match of the same rule over the same (mapped) span are
    // the SAME secret occurrence, not two findings.
    const secret = 'AKIAIOSFODNN7EXAMPLE';
    const text = `const key = "${secret.slice(0, 10)}${ZWSP}${secret.slice(10)}";`;

    const findings = scan(text, [awsAccessKey]);
    expect(findings).toHaveLength(1);
  });
});
