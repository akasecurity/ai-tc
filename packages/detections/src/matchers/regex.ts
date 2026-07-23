import type { Rule, Span } from '@akasecurity/schema';

import type { Matcher } from '../types.ts';
import { MAX_MATCHES_PER_RULE, MAX_REGEX_INPUT_LENGTH } from './limits.ts';

export class RegexMatcher implements Matcher {
  match(text: string, rule: Rule): Span[] {
    if (rule.matcher.type !== 'regex') return [];
    const { pattern, flags, captureGroup } = rule.matcher;
    // The 'd' (hasIndices) flag provides exact per-group offsets. Searching for
    // the captured text inside the overall match (indexOf) would mislocate the
    // span whenever the captured value also occurs earlier in the match, and a
    // mislocated span makes redact() mask the wrong characters.
    const re = new RegExp(pattern, flags.includes('d') ? flags : `${flags}d`);
    // Bound how much of `text` a single caller-supplied pattern is ever run
    // against — see MAX_REGEX_INPUT_LENGTH for why this matters for a
    // catastrophically-backtracking pattern. `scanText` is always a prefix of
    // `text`, so spans found within it are valid offsets into the original.
    const scanText =
      text.length > MAX_REGEX_INPUT_LENGTH ? text.slice(0, MAX_REGEX_INPUT_LENGTH) : text;
    const spans: Span[] = [];
    let m: RegExpExecArray | null;
    // Defense-in-depth iteration budget: a well-formed loop only ever advances
    // `lastIndex`, so it cannot run more than one iteration per character of
    // `scanText`. This should never trip — it exists purely as a backstop
    // against an unforeseen zero-advance edge case, independent of the
    // MAX_MATCHES_PER_RULE cap below (which stops recording spans, not
    // iterating).
    const maxIterations = scanText.length + 1;
    let iterations = 0;

    while ((m = re.exec(scanText)) !== null) {
      if (++iterations > maxIterations) break;
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
