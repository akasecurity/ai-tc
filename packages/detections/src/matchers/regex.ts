import type { Rule, Span } from '@akasecurity/schema';

import type { Matcher } from '../types.ts';

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
      if (!group) continue;
      const groupIndices = captureGroup != null ? m.indices?.[captureGroup] : undefined;
      const start = groupIndices ? groupIndices[0] : m.index;
      spans.push({ start, end: start + group.length });
      if (!flags.includes('g')) break;
    }
    return spans;
  }
}
