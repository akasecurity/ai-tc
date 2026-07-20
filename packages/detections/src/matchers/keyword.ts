import type { Rule, Span } from '@akasecurity/schema';

import { escapeRegExp } from '../escape-regexp.ts';
import type { Matcher } from '../types.ts';
import { MAX_MATCHES_PER_RULE } from './limits.ts';

export class KeywordMatcher implements Matcher {
  match(text: string, rule: Rule): Span[] {
    if (rule.matcher.type !== 'keyword') return [];
    const { keywords, caseSensitive } = rule.matcher;
    const spans: Span[] = [];

    for (const kw of keywords) {
      // An empty keyword matches at every position without ever advancing
      // `lastIndex`, so the walk below would not terminate. The schema rejects
      // it; skipping keeps the matcher safe on its own if a rule bypasses that.
      if (kw.length === 0) continue;

      // The per-rule ceiling is shared across all of a rule's keywords: a
      // 1-character keyword over a very large input would otherwise emit one
      // span per occurrence. Stop before scanning any further keyword.
      if (spans.length >= MAX_MATCHES_PER_RULE) break;

      // Match against the original `text` directly — a case-folded copy can
      // differ in length from `text` (e.g. "İ".toLowerCase() is two code
      // units), which would misalign every offset found in it.
      //
      // `u` is safe and preferred here for two reasons: `escapeRegExp` only ever
      // escapes SyntaxCharacters, so the pattern is always valid under `u`
      // (which rejects stray identity escapes a lenient regex would accept); and
      // `u` keeps case-folding parity with the old case-folded-copy matcher for
      // characters like "ß"/"ẞ" (which a plain `i` regex stops folding). No
      // bundled keyword is non-ASCII, so the folding only matters for custom
      // rules — but the parity is free.
      const re = new RegExp(escapeRegExp(kw), caseSensitive ? 'gu' : 'giu');
      let m: RegExpExecArray | null;
      // An escaped non-empty keyword only ever matches a non-empty run, so the
      // `g` flag always advances past it and the walk terminates.
      while ((m = re.exec(text)) !== null) {
        spans.push({ start: m.index, end: m.index + m[0].length });
        if (spans.length >= MAX_MATCHES_PER_RULE) break;
      }
    }
    return spans;
  }
}
