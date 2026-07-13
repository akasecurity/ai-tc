import type { Rule, Span } from '@akasecurity/schema';

import type { Matcher } from '../types.ts';

// An absolute per-scan match ceiling. A whole-match pattern that can match the
// empty string (e.g. "\d*") re-matches at the same index forever unless
// `lastIndex` is advanced — the `g`-flag loop below now does that — but this
// ceiling stays as a second backstop against any other way a rule ends up
// looping (a huge text, an unexpected zero-width edge case in a future engine).
const MAX_MATCHES_PER_RULE = 10_000;

export class RegexMatcher implements Matcher {
  match(text: string, rule: Rule): Span[] {
    if (rule.matcher.type !== 'regex') return [];
    const { pattern, flags, captureGroup } = rule.matcher;
    // The 'd' (hasIndices) flag provides exact per-group offsets. Searching for
    // the captured text inside the overall match (indexOf) would mislocate the
    // span whenever the captured value also occurs earlier in the match, and a
    // mislocated span makes redact() mask the wrong characters.
    const re = new RegExp(pattern, flags.includes('d') ? flags : `${flags}d`);
    const spans: Span[] = [];
    let m: RegExpExecArray | null;

    while ((m = re.exec(text)) !== null) {
      const group = captureGroup != null ? m[captureGroup] : m[0];
      // A zero-length match (e.g. "\d*" matching "") never advances `lastIndex`
      // on its own, so a `g`-flag loop that just re-runs `exec` at the same
      // index hangs forever. Bump it past the empty match before continuing.
      if (m[0].length === 0) re.lastIndex++;
      if (group && spans.length < MAX_MATCHES_PER_RULE) {
        const groupIndices = captureGroup != null ? m.indices?.[captureGroup] : undefined;
        const start = groupIndices ? groupIndices[0] : m.index;
        spans.push({ start, end: start + group.length });
      }
      if (!flags.includes('g') || spans.length >= MAX_MATCHES_PER_RULE) break;
    }
    return spans;
  }
}
