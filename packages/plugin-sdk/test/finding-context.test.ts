import type { MatchResult } from '@akasecurity/detections';
import { scan } from '@akasecurity/detections';
import type { FindingContext, Rule } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  CONTEXT_LINE_MAX,
  CONTEXT_MAX_PER_TEXT,
  createFindingLocator,
  evidenceLookup,
} from '../src/finding-context.ts';
import { bundledMaskingRules } from '../src/mask.ts';
import { assertRawFree } from '../src/raw-egress.ts';

// Secrets are ASSEMBLED at runtime from fragments so this source file contains
// no literal secret. This one is the AWS documentation example key, which is
// also `secrets/aws-access-key`'s own rule example.
const AWS_KEY = ['AKIA', 'IOSFODNN7', 'EXAMPLE'].join('');
const PGP_HEADER = ['-----BEGIN PGP', 'PRIVATE KEY BLOCK-----'].join(' ');
// Stands in for a key body: text no rule recognises, which is exactly why a
// neighbouring line can carry a secret nothing marks.
const KEY_BODY = 'qq-plain-body-line-no-rule-matches-this-qq';

function rules(): Rule[] {
  const loaded = bundledMaskingRules();
  if (loaded === null) throw new Error('bundled packs failed to load');
  return loaded;
}

function locateAll(text: string, basis: 'file' | 'excerpt' = 'file') {
  const ruleset = rules();
  const hits = scan(text, ruleset);
  const locate = createFindingLocator({
    text,
    basis,
    hits,
    evidenceOf: evidenceLookup(ruleset),
    backstopRules: ruleset,
  });
  return { hits, locate };
}

function hitOf(hits: readonly MatchResult[], ruleId: string): MatchResult {
  const hit = hits.find((h) => h.ruleId === ruleId);
  if (hit === undefined) throw new Error(`expected a ${ruleId} hit`);
  return hit;
}

function contextOf(location: { context: FindingContext | null }): FindingContext {
  if (location.context === null) throw new Error('expected an excerpt');
  return location.context;
}

// The highlighted text, read back out of the excerpt.
function highlighted(context: FindingContext): string {
  const match = context.match;
  if (match === null) return '';
  const line = context.lines[match.line - context.firstLine] ?? '';
  return line.slice(match.start, match.end);
}

const CODE_FILE = [
  'import { render } from "./view";',
  '',
  'export function show(userInput: string) {',
  '  const element = document.getElementById("out");',
  '  element.innerHTML = userInput;',
  '  return element;',
  '}',
  '',
].join('\n');

describe('createFindingLocator — position', () => {
  it('reports the 1-based line and column of the match start', () => {
    const { hits, locate } = locateAll(CODE_FILE);
    const location = locate(hitOf(hits, 'code-flaws/xss-inner-html'));
    expect(location.line).toBe(5);
    // `  element.innerHTML = …`: the keyword starts after "  element.".
    expect(location.col).toBe('  element.'.length + 1);
  });

  it('counts a match on the first line as line 1, column 1', () => {
    const { hits, locate } = locateAll('innerHTML = userInput');
    const location = locate(hitOf(hits, 'code-flaws/xss-inner-html'));
    expect(location.line).toBe(1);
    expect(location.col).toBe(1);
  });

  it('records the basis it was given', () => {
    const { hits, locate } = locateAll(CODE_FILE, 'excerpt');
    expect(contextOf(locate(hitOf(hits, 'code-flaws/xss-inner-html'))).basis).toBe('excerpt');
  });
});

describe('createFindingLocator — a code finding', () => {
  it('shows the matched line plus two lines either side, with the match highlighted', () => {
    const { hits, locate } = locateAll(CODE_FILE);
    const context = contextOf(locate(hitOf(hits, 'code-flaws/xss-inner-html')));
    expect(context.firstLine).toBe(3);
    expect(context.lines).toEqual([
      'export function show(userInput: string) {',
      '  const element = document.getElementById("out");',
      '  element.innerHTML = userInput;',
      '  return element;',
      '}',
    ]);
    expect(context.match?.line).toBe(5);
    expect(highlighted(context)).toBe('innerHTML =');
  });

  it('stops at the start and end of the text', () => {
    const text = 'element.innerHTML = userInput;\nnext();';
    const { hits, locate } = locateAll(text);
    const context = contextOf(locate(hitOf(hits, 'code-flaws/xss-inner-html')));
    expect(context.firstLine).toBe(1);
    expect(context.lines).toEqual(['element.innerHTML = userInput;', 'next();']);
  });

  it('never shows the empty line after a trailing newline', () => {
    const text = 'a();\nelement.innerHTML = userInput;\n';
    const { hits, locate } = locateAll(text);
    const context = contextOf(locate(hitOf(hits, 'code-flaws/xss-inner-html')));
    expect(context.lines).toEqual(['a();', 'element.innerHTML = userInput;']);
  });

  it('keeps a long line to its cap, centred on the match, and marks the cut', () => {
    const pad = 'x'.repeat(1000);
    const text = `${pad}element.innerHTML = userInput;${pad}`;
    const { hits, locate } = locateAll(text);
    const context = contextOf(locate(hitOf(hits, 'code-flaws/xss-inner-html')));
    const [line] = context.lines;
    // The cap plus an ellipsis at each cut end.
    expect(line?.length).toBe(CONTEXT_LINE_MAX + 2);
    expect(line?.startsWith('…')).toBe(true);
    expect(line?.endsWith('…')).toBe(true);
    expect(highlighted(context)).toBe('innerHTML =');
    // Centred: the match sits near the middle, not at an edge.
    expect(context.match?.start).toBeGreaterThan(CONTEXT_LINE_MAX / 4);
  });

  it('redacts a secret on a neighbouring line', () => {
    const text = [
      `const key = "${AWS_KEY}";`,
      'const element = document.getElementById("out");',
      'element.innerHTML = userInput;',
    ].join('\n');
    const { hits, locate } = locateAll(text);
    const context = contextOf(locate(hitOf(hits, 'code-flaws/xss-inner-html')));
    const shown = context.lines.join('\n');
    // Positive control: the line holding the secret is in the excerpt.
    expect(context.lines[0]).toContain('const key = "');
    expect(shown).toContain('[REDACTED:SECRET]');
    expect(() => assertRawFree(shown, [AWS_KEY])).not.toThrow();
  });

  it('redacts a value only the original scan reported, which the backstop cannot see', () => {
    // A custom rule's hit: no bundled rule recognises this value, so the
    // backstop re-scan cannot be what removes it.
    const value = 'zz-custom-token-value-zz';
    const text = [`const banner = "${value}";`, 'element.innerHTML = userInput;'].join('\n');
    const ruleset = rules();
    // Control: across the whole text the bundled rules see only the code hit.
    expect(scan(text, ruleset).map((h) => h.ruleId)).toEqual(['code-flaws/xss-inner-html']);
    const start = text.indexOf(value);
    const custom: MatchResult = {
      ruleId: 'custom/token',
      category: 'secret',
      severity: 'high',
      span: { start, end: start + value.length },
      rawMatch: value,
      confidence: 0.9,
    };
    const hits = [...scan(text, ruleset), custom];
    const locate = createFindingLocator({
      text,
      basis: 'file',
      hits,
      evidenceOf: evidenceLookup(ruleset),
      backstopRules: ruleset,
    });
    const shown = contextOf(locate(hitOf(hits, 'code-flaws/xss-inner-html'))).lines.join('\n');
    expect(shown).toContain('const banner = "[REDACTED:SECRET]";');
    expect(() => assertRawFree(shown, [value])).not.toThrow();
  });

  it('redacts a secret the original scan did not report, through the backstop', () => {
    const text = [`const key = "${AWS_KEY}";`, 'element.innerHTML = userInput;'].join('\n');
    const ruleset = rules();
    // Only the code hit is handed over, as when the pack that would have caught
    // the key was disabled for the capture.
    const codeHits = scan(text, ruleset).filter((h) => h.ruleId === 'code-flaws/xss-inner-html');
    expect(codeHits).toHaveLength(1);
    const locate = createFindingLocator({
      text,
      basis: 'file',
      hits: codeHits,
      evidenceOf: evidenceLookup(ruleset),
      backstopRules: ruleset,
    });
    const shown = contextOf(locate(hitOf(codeHits, 'code-flaws/xss-inner-html'))).lines.join('\n');
    expect(shown).toContain('const key = "');
    expect(() => assertRawFree(shown, [AWS_KEY])).not.toThrow();
  });

  it('redacts a secret inside the matched code itself', () => {
    const text = `element.innerHTML = "${AWS_KEY}";`;
    const { hits, locate } = locateAll(text);
    const context = contextOf(locate(hitOf(hits, 'code-flaws/xss-inner-html')));
    const shown = context.lines.join('\n');
    expect(shown).toContain('innerHTML =');
    expect(() => assertRawFree(shown, [AWS_KEY])).not.toThrow();
  });
});

describe('createFindingLocator — a match its own action redacted at rest', () => {
  it('redacts the matched code, so the excerpt never shows what the stored copy strips', () => {
    const ruleset = rules();
    const hits = scan(CODE_FILE, ruleset);
    const hit = hitOf(hits, 'code-flaws/xss-inner-html');
    const locate = createFindingLocator({
      text: CODE_FILE,
      basis: 'file',
      hits,
      evidenceOf: evidenceLookup(ruleset),
      backstopRules: ruleset,
      enforcedHits: new Set([hit]),
    });
    const context = contextOf(locate(hit));
    expect(context.lines).toEqual(['  element.[REDACTED:CODE_FLAW] userInput;']);
    expect(context.match).toBeNull();
  });
});

describe('createFindingLocator — a value finding', () => {
  it('shows the matched line alone, with the value redacted and nothing highlighted', () => {
    const text = ['const a = 1;', `const key = "${AWS_KEY}";`, 'const b = 2;'].join('\n');
    const { hits, locate } = locateAll(text);
    const context = contextOf(locate(hitOf(hits, 'secrets/aws-access-key')));
    expect(context.firstLine).toBe(2);
    expect(context.lines).toEqual(['const key = "[REDACTED:SECRET]";']);
    expect(context.match).toBeNull();
  });

  it('never shows the line after a PGP key header, which no rule marks', () => {
    const text = ['config:', PGP_HEADER, KEY_BODY, KEY_BODY, 'done'].join('\n');
    const ruleset = rules();
    // Control: the body line is invisible to every bundled rule, so nothing but
    // the one-line excerpt keeps it out.
    expect(scan(KEY_BODY, ruleset)).toEqual([]);
    const { hits, locate } = locateAll(text);
    const context = contextOf(locate(hitOf(hits, 'secrets-infra/pgp-private-key')));
    expect(context.lines).toHaveLength(1);
    expect(context.lines.join('\n')).not.toContain(KEY_BODY);
  });

  it('treats the code-flaw rules that match a real value as values', () => {
    const text = ['a();', 'password = "Tr0ub4dor&3"', 'b();'].join('\n');
    const { hits, locate } = locateAll(text);
    const context = contextOf(locate(hitOf(hits, 'code-flaws/hardcoded-password')));
    expect(context.lines).toHaveLength(1);
    expect(context.match).toBeNull();
    expect(context.lines[0]).not.toContain('Tr0ub4dor');
  });
});

describe('createFindingLocator — failing closed', () => {
  it('stores no excerpt when the masking rules could not be loaded', () => {
    const ruleset = rules();
    const hits = scan(CODE_FILE, ruleset);
    const locate = createFindingLocator({
      text: CODE_FILE,
      basis: 'file',
      hits,
      evidenceOf: evidenceLookup(ruleset),
      backstopRules: null,
    });
    const location = locate(hitOf(hits, 'code-flaws/xss-inner-html'));
    expect(location.context).toBeNull();
    // The position does not depend on masking and is kept.
    expect(location.line).toBe(5);
  });

  it('stores no excerpt when building it throws', () => {
    const ruleset = rules();
    const text = `const key = "${AWS_KEY}";\nelement.innerHTML = userInput;`;
    const hits = scan(text, ruleset);
    const locate = createFindingLocator({
      text,
      basis: 'file',
      hits,
      evidenceOf: () => {
        throw new Error('evidence lookup failed');
      },
      backstopRules: ruleset,
    });
    expect(locate(hitOf(hits, 'code-flaws/xss-inner-html')).context).toBeNull();
  });

  it('builds at most CONTEXT_MAX_PER_TEXT excerpts per text, and keeps every position', () => {
    const text = Array.from(
      { length: CONTEXT_MAX_PER_TEXT + 5 },
      () => 'element.innerHTML = userInput;',
    ).join('\n');
    const { hits, locate } = locateAll(text);
    const located = hits
      .filter((h) => h.ruleId === 'code-flaws/xss-inner-html')
      .map((h) => locate(h));
    expect(located).toHaveLength(CONTEXT_MAX_PER_TEXT + 5);
    expect(located.filter((l) => l.context !== null)).toHaveLength(CONTEXT_MAX_PER_TEXT);
    expect(located.at(-1)?.line).toBe(CONTEXT_MAX_PER_TEXT + 5);
  });
});

describe('evidenceLookup', () => {
  it("prefers a rule's own field to the bundled classification", () => {
    const ruleset = rules().map((rule) =>
      rule.id === 'code-flaws/xss-inner-html' ? { ...rule, evidence: 'value' as const } : rule,
    );
    expect(evidenceLookup(ruleset)('code-flaws/xss-inner-html')).toBe('value');
  });

  it('treats a rule it has never seen as a value', () => {
    expect(evidenceLookup([])('custom/unknown')).toBe('value');
  });
});
