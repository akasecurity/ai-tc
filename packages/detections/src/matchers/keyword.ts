import type { Rule, Span } from '@aka/schema';

import type { Matcher } from '../types.ts';

export class KeywordMatcher implements Matcher {
  match(text: string, rule: Rule): Span[] {
    if (rule.matcher.type !== 'keyword') return [];
    const { keywords, caseSensitive } = rule.matcher;
    const haystack = caseSensitive ? text : text.toLowerCase();
    const spans: Span[] = [];

    for (const kw of keywords) {
      const needle = caseSensitive ? kw : kw.toLowerCase();
      let idx = 0;
      while (idx < haystack.length) {
        const pos = haystack.indexOf(needle, idx);
        if (pos === -1) break;
        spans.push({ start: pos, end: pos + kw.length });
        idx = pos + 1;
      }
    }
    return spans;
  }
}
