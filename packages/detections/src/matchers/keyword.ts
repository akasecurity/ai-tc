import type { Rule, Span } from '@akasecurity/schema';

import type { Matcher } from '../types.ts';

function escapeForRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

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

      // Match against the original `text` directly — a case-folded copy can
      // differ in length from `text` (e.g. "İ".toLowerCase() is two code
      // units), which would misalign every offset found in it.
      //
      // `u` makes case-insensitive matching fold by code point ("ß" matches
      // "ẞ"), which a code-unit comparison misses. It also makes an escaped
      // keyword a well-formed pattern rather than a lenient one.
      const re = new RegExp(escapeForRegExp(kw), caseSensitive ? 'gu' : 'giu');
      let m: RegExpExecArray | null;
      // An escaped non-empty keyword only ever matches a non-empty run, so the
      // `g` flag always advances past it and the walk terminates.
      while ((m = re.exec(text)) !== null) {
        spans.push({ start: m.index, end: m.index + m[0].length });
      }
    }
    return spans;
  }
}
