import { TriageRecommendation } from '@akasecurity/schema';

const FENCE_RE = /```json\s*([\s\S]*?)```/g;

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
  const fences = [...text.matchAll(FENCE_RE)];
  const lastFence = fences.at(-1);
  const raw = lastFence?.[1] ?? text;
  return TriageRecommendation.parse(JSON.parse(raw.trim()));
}
