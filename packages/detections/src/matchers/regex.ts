import type { Rule, Span } from '@akasecurity/schema';

import { memoizedRegExp } from '../regex-cache.ts';
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
    //
    // Compiled once per matcher rather than once per call, and shared across
    // calls, so it arrives with `lastIndex` at 0. That reset is load-bearing
    // rather than tidy: every `break` below leaves a global pattern's
    // `lastIndex` mid-input, so without it the next call would resume from the
    // previous call's offset and miss every match before it.
    const re = memoizedRegExp(
      rule.matcher,
      () => new RegExp(pattern, flags.includes('d') ? flags : `${flags}d`),
    );
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

    // The extent of the match last taken, so a sub-match of it can be told from
    // a new occurrence that merely overlaps it.
    let takenStart = -1;
    let takenEnd = -1;

    while ((m = re.exec(scanText)) !== null) {
      if (++iterations > maxIterations) break;
      const end = m.index + m[0].length;
      // A match wholly inside the one just taken is a shorter reading of it (a
      // suffix of a quantified run, or the empty string), never a separate
      // occurrence, so skip it and resume after the outer match. Without this
      // the loop reports every suffix of every match, and re-scans each run
      // once per position in it, which costs time quadratic in the run's
      // length. `takenEnd` can equal `m.index` for a zero-length match, so
      // resume at least one character on to keep `lastIndex` advancing.
      if (takenStart >= 0 && m.index >= takenStart && end <= takenEnd) {
        re.lastIndex = Math.max(takenEnd, m.index + 1);
        continue;
      }
      const group = captureGroup != null ? m[captureGroup] : m[0];
      if (group && spans.length < MAX_MATCHES_PER_RULE) {
        const groupIndices = captureGroup != null ? m.indices?.[captureGroup] : undefined;
        const start = groupIndices ? groupIndices[0] : m.index;
        spans.push({ start, end: start + group.length });
      }
      takenStart = m.index;
      takenEnd = end;
      // Resume one character past where this match STARTED, not past where it
      // ended. Letting `g` skip the whole match drops every occurrence that
      // overlaps one already taken, which makes the reported set depend on the
      // offset the scan began at: a scan of part of a text then tiles it
      // differently from a scan of all of it, and an occurrence that a later
      // match needed in order to anchor can be consumed by an earlier one.
      re.lastIndex = m.index + 1;
      if (!flags.includes('g') || spans.length >= MAX_MATCHES_PER_RULE) break;
    }
    return spans;
  }
}
