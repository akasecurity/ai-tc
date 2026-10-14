import { TriageRecommendation } from '@akasecurity/schema';

const FENCE_OPEN = '```json';
const FENCE_CLOSE = '```';

// eval/prompt.md instructs the model that its TriageRecommendation fence
// "must be the last thing in your reply" — but a model can still emit an
// earlier illustrative ```json``` block (e.g. "here's the shape I'll use").
// Taking the FIRST fence would silently parse that wrong block instead of
// the real verdict, so take the LAST fence instead. Falls back to bare-JSON
// parsing when the reply has no fence at all.
//
// Shared by the eval harness (eval/run.ts) and the wizard's judge runner
// (triage/judge.ts) so both parse a model verdict identically — the harness
// only validates what the wizard will actually accept.
export function parseRecommendation(text: string): TriageRecommendation {
  const raw = lastFenceBody(text) ?? text;
  return TriageRecommendation.parse(JSON.parse(raw.trim()));
}

// The body of the last ```json fence, found with indexOf rather than
// /```json\s*([\s\S]*?)```/g. That pattern's whitespace run and its lazy body
// can both match whitespace, so on a fence that never closes the engine tries
// every split of the run between the two — quadratic in the run's length.
//
// It finds the same fences. Each closes at the first ``` after its opener, even
// one that opens another fence, and the search resumes after that closer. An
// opener with no ``` after it ends the search, since a later opener would
// itself hold one. The body keeps the leading whitespace the pattern's \s*
// skipped, and the caller's trim drops it.
function lastFenceBody(text: string): string | undefined {
  let body: string | undefined;
  let open = text.indexOf(FENCE_OPEN);
  while (open !== -1) {
    const start = open + FENCE_OPEN.length;
    const close = text.indexOf(FENCE_CLOSE, start);
    if (close === -1) break;
    body = text.slice(start, close);
    open = text.indexOf(FENCE_OPEN, close + FENCE_CLOSE.length);
  }
  return body;
}
