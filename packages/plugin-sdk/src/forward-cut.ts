import type { ReviewValue } from '@akasecurity/schema';
import { REVIEW_VALUE_MAX_CHARS, REVIEW_VALUES_MAX } from '@akasecurity/schema';

/** What a capture marked for forwarding stores: its text, cut to the cap. */
export interface ForwardCut {
  content: string;
  /** The text's full length, present only when the content was cut. */
  truncatedFrom?: number;
}

/**
 * The first `maxChars` UTF-16 code units of `text`, one fewer when the cut
 * would leave the first half of a surrogate pair at the end.
 */
export function cutForForward(text: string, maxChars: number): ForwardCut {
  if (text.length <= maxChars) return { content: text };
  let end = Math.max(0, maxChars);
  const last = text.charCodeAt(end - 1);
  if (end > 0 && last >= 0xd800 && last <= 0xdbff) end -= 1;
  return { content: text.slice(0, end), truncatedFrom: text.length };
}

/**
 * Each finding's raw value, once per rule and value, in finding order, up to
 * the wire's bounds. A value longer than a review value may be is left out.
 */
export function reviewCandidatesOf(
  findings: readonly { ruleId: string; rawMatch: string }[],
): ReviewValue[] {
  const out: ReviewValue[] = [];
  const seen = new Set<string>();
  for (const { ruleId, rawMatch } of findings) {
    if (out.length >= REVIEW_VALUES_MAX) break;
    if (rawMatch === '' || rawMatch.length > REVIEW_VALUE_MAX_CHARS || ruleId === '') continue;
    const key = `${ruleId}\u0000${rawMatch}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ ruleId, value: rawMatch });
  }
  return out;
}
