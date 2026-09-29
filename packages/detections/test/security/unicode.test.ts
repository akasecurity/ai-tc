import { resolve } from 'node:path';

import { Rule } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { redact, scan } from '../../src/index.ts';
import { BOM, FORMAT_CHARS, ZWSP } from '../helpers/format-chars.ts';
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

// Bundled rules reused across the describe blocks below, loaded once.
const githubPat = loadRule(resolve(RULES_DIR, 'secrets'), 'github-pat');
const awsAccessKey = loadRule(resolve(RULES_DIR, 'secrets'), 'aws-access-key');
const devPlaceholderSecret = loadRule(resolve(RULES_DIR, 'code-flaws'), 'dev-placeholder-secret');

describe('invisible format characters inside a match', () => {
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

  it.each(FORMAT_CHARS)('detects the secret with %s inserted mid-value', (_label, char) => {
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
  });
});

// Regression guard: normalizing text before matching must never make a
// \b-anchored rule miss a secret the unmodified (no format-character
// handling at all) engine already detects. JS's `\b` treats a \p{Cf}
// character as non-word — the SAME property that lets it split a secret in
// two also lets it SATISFY a `\b` between a word character and the secret
// when nothing else would. Stripping it can silently remove that boundary: a
// word char, a ZWSP, then "AKIA..." matches `\b(AKIA|...)…` on the ORIGINAL
// text (ZWSP is non-word, so there is a word/non-word transition right
// before "AKIA"), but on the stripped "xAKIA..." there is no such transition
// at all — a rule that matched with no normalization at all must still match
// with it.
describe('the original-text pass still finds a match whose boundary is a format character', () => {
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

  it('still detects a secret with a format character at the very end of the text, tightly', () => {
    const secret = 'AKIAIOSFODNN7EXAMPLE';
    const text = `${secret}${ZWSP}`;

    const findings = scan(text, [awsAccessKey]);
    expect(findings).toHaveLength(1);
    // Strict equality: with mapSpanToOriginal's end-of-text special case
    // removed, both the original-text pass (which finds `\bAKIA...{16}\b`
    // exactly, the ZWSP sitting outside the match) and the normalized-text
    // pass (now mapped back TIGHTLY, see format-chars.test.ts) agree on the
    // same clean span — matching what the unmodified engine finds.
    expect(findings[0]?.rawMatch).toBe(secret);
    expect(findings[0]?.span).toEqual({ start: 0, end: secret.length });
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

describe('requiresNearby corroboration can cross between the two passes', () => {
  // rules/code-flaws/dev-placeholder-secret.json: keyword "changeme", gated
  // on a "key"/"secret"/"password"/"token" label within 80 chars (schema
  // default 160, this rule sets 80). Neither pass alone can corroborate
  // these: the keyword only reads as one word in the normalized text (a
  // format character sits inside it), while the label's own boundary is
  // satisfied only by a format character present in the ORIGINAL text (the
  // same shape the previous describe block covers for a primitive match,
  // here for the requiresNearby label specifically). Pooling candidates from
  // both passes before gating — rather than gating each pass on its own — is
  // what lets the normalized-text keyword candidate see the original-text
  // label satisfy its corroboration.
  it('corroborates when the label needs the original text and the keyword needs the normalized text', () => {
    const text = `abc${ZWSP}key = 'change${ZWSP}me'`;
    const findings = scan(text, [devPlaceholderSecret]);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('code-flaws/dev-placeholder-secret');
  });

  it('corroborates the same shape with a different label ("my_api<fmt>key")', () => {
    const text = `my_api${ZWSP}key = 'change${ZWSP}me'`;
    const findings = scan(text, [devPlaceholderSecret]);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('code-flaws/dev-placeholder-secret');
  });
});

describe('a same-rule overlap that only appears once matching runs against both texts', () => {
  // A pattern with no upper bound (`{16,}`) can match FURTHER in the
  // normalized text than either half can in the original text (where the
  // format character splits the run into two shorter matches). Pooling both
  // passes' candidates, then folding same-rule overlaps into their union,
  // must produce ONE clean finding covering the whole thing — not two
  // overlapping findings, which downstream span-grouping (e.g. a
  // redact-and-vault policy) cannot treat as a single value.
  it('folds two original-text halves and one wider normalized-text match into one finding', () => {
    const generic = Rule.parse({
      specVersion: 1,
      id: 'test-pack/generic',
      name: 'generic',
      category: 'secret',
      severity: 'high',
      matcher: { type: 'regex', pattern: '[A-Za-z0-9]{16,}', flags: 'g' },
    });
    const tok = `Q7xK2mP9vL4nR8sT1wY5${ZWSP}zA3cE6gI0jM2oU4qS7uW`;
    const text = `key=${tok};`;

    const findings = scan(text, [generic]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.span).toEqual({ start: 4, end: 4 + tok.length });

    const output = redact(text, findings);
    expect(output).toBe('key=[REDACTED:SECRET];');
  });
});

describe('the slow path does not blow up on a large text with one format character', () => {
  // The regression this test is pinned against: a scan that used to take
  // single-digit milliseconds took multiple SECONDS with one leading BOM,
  // because the (now fixed) merge step was quadratic in the number of
  // findings. A fixed wall-clock ceiling is the wrong instrument for that —
  // CLAUDE.md/CONTRIBUTING.md's own reasoning against fixed millisecond
  // limits applies here: a shared or Windows CI runner can run this same
  // 60,000-finding scan tens of times slower than a dev machine, which would
  // cross any fixed ceiling generous enough to hold locally. A RATIO does
  // not have that problem — a slower runner slows both sides together — so
  // this times the identical text with and without the BOM, interleaved and
  // taking the fastest of several runs each (the standard way to cut noise
  // from a wall-clock measurement without needing a controlled benchmark
  // harness), and bounds the QUOTIENT. The bug this guards measured a ~330x
  // ratio (5972ms vs 18ms); 10x leaves that a wide margin on one side while
  // still comfortably above the ~2x this file's own dual-pass matching
  // costs on the other (see bench/benign-format-chars.bench.ts for the
  // measured, non-pathological cost of the slow path).
  it('scans a large multi-rule text with one leading BOM in roughly the same time as without one', () => {
    const mk = (id: string, pattern: string) =>
      Rule.parse({
        specVersion: 1,
        id,
        name: id,
        category: 'pii',
        severity: 'medium',
        matcher: { type: 'regex', pattern, flags: 'g' },
      });
    const rules = [0, 1, 2, 3, 4, 5].map((k) =>
      mk(`test-pack/w${String(k)}`, `\\bw${String(k)}\\b`),
    );
    let body = '';
    for (let i = 0; i < 10000; i++) body += 'w0 w1 w2 w3 w4 w5\n';
    const withoutBom = body;
    const withBom = BOM + body;

    function timeOnce(text: string): number {
      const start = performance.now();
      const findings = scan(text, rules);
      const ms = performance.now() - start;
      expect(findings).toHaveLength(60000);
      return ms;
    }

    const REPEATS = 5;
    let withoutBomBest = Infinity;
    let withBomBest = Infinity;
    for (let i = 0; i < REPEATS; i++) {
      withoutBomBest = Math.min(withoutBomBest, timeOnce(withoutBom));
      withBomBest = Math.min(withBomBest, timeOnce(withBom));
    }

    const ratio = withBomBest / Math.max(withoutBomBest, 0.001);
    expect(
      ratio,
      `with-BOM best of ${String(REPEATS)}: ${withBomBest.toFixed(1)}ms, without: ${withoutBomBest.toFixed(1)}ms`,
    ).toBeLessThan(10);
  });
});

describe('invisible padding cannot push a label outside the requiresNearby window', () => {
  // rules/code-flaws/dev-placeholder-secret.json's window is measured in
  // NORMALIZED characters for a normalized-pass candidate (see
  // `Candidate.labelWindow` in engine.ts), not always in original ones —
  // otherwise a run of invisible characters between a label and its value
  // counts against the window budget even though it disappears entirely
  // once normalized, letting an attacker push a genuinely nearby label
  // arbitrarily far outside the window just by padding with something no
  // one can see.
  it('still corroborates through 100 invisible characters of padding between the label and the value', () => {
    const text = `key = ${ZWSP.repeat(100)}'changeme'`;
    const findings = scan(text, [devPlaceholderSecret]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('code-flaws/dev-placeholder-secret');
  });

  it('still corroborates through 1000 invisible characters of padding', () => {
    const text = `key = ${ZWSP.repeat(1000)}'changeme'`;
    const findings = scan(text, [devPlaceholderSecret]);
    expect(findings).toHaveLength(1);
  });

  it('leaves VISIBLE padding subject to the window as before (not a regression to relax)', () => {
    // Padding an attacker cannot hide is not the threat this fix closes —
    // a real reader (and a real reviewer of the flagged content) sees a
    // label 100 characters away and can judge it a stretch; a real 100-char
    // window budget still applies to visible content.
    const text = `key = ${'x'.repeat(100)} 'changeme'`;
    const findings = scan(text, [devPlaceholderSecret]);
    expect(findings).toHaveLength(0);
  });
});

describe('a rule cannot corroborate itself through its own pooled cross-pass duplicate', () => {
  // A rule whose `requiresNearby.ruleIds` names its OWN id means "two
  // nearby occurrences of this rule corroborate each other" — a legitimate
  // config. On the slow path, the original-text and normalized-text passes
  // can each independently produce a candidate for the SAME occurrence, with
  // an identical or overlapping span once pooled in original coordinates.
  // Without excluding that pooled duplicate, a single, lone occurrence gets
  // corroborated by its own cross-pass copy the moment the text contains
  // ANY format character anywhere — not because a second occurrence exists,
  // but purely because normalizing happened to run at all.
  const selfCorroboratingRule = Rule.parse({
    specVersion: 1,
    id: 'test-pack/self-corroborating',
    name: 'self-corroborating',
    category: 'secret',
    severity: 'high',
    matcher: { type: 'regex', pattern: '[A-Z]{5}', flags: 'g' },
    requiresNearby: { ruleIds: ['test-pack/self-corroborating'], windowChars: 50 },
  });

  it('does not corroborate a lone occurrence via its own cross-pass duplicate', () => {
    const lone = 'one lone match HELLO here, nothing else nearby';
    // A stray format character elsewhere in the text (nowhere near the
    // match) is enough to put scan() on the slow path and so pool a
    // cross-pass duplicate of HELLO, without adding any second, real
    // occurrence of the rule.
    const withStrayFormatChar = `${lone}${ZWSP}`;

    expect(scan(lone, [selfCorroboratingRule])).toHaveLength(0);
    expect(scan(withStrayFormatChar, [selfCorroboratingRule])).toHaveLength(0);
  });

  it('still corroborates two GENUINELY separate nearby occurrences of the same rule', () => {
    // The self-reference config must keep working for what it is for: two
    // real, non-overlapping occurrences close enough to corroborate.
    const text = 'HELLO near WORLD';
    const findings = scan(text, [selfCorroboratingRule]);
    expect(findings).toHaveLength(2);
  });
});
