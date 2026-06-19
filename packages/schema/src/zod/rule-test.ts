// Control-plane contract for the rule authoring/test endpoint (POST /v1/rules/test).
// Lets an author run DRAFT rules through the detection engine (scan()) against
// ad-hoc text and/or fixtures — without publishing or installing anything — so the
// dashboard rule editor can preview a matcher before it ever ships. Stateless: no
// stored data is read or written. The keystone of the rule-authoring flow.
import { z } from 'zod';

import { DetectionCategory, Severity, Span } from './finding.ts';
import { Rule, RuleFixture } from './rule.ts';

// POST /v1/rules/test — draft rules plus something to test them against. At least
// one of `text` (ad-hoc scan) or a non-empty `fixtures` (expectation checks) must
// be present, otherwise there is nothing to evaluate.
export const TestRulesRequest = z
  .object({
    rules: z.array(Rule).min(1).max(100),
    text: z.string().max(50_000).optional(),
    fixtures: z.array(RuleFixture).max(200).optional(),
  })
  .refine((v) => v.text !== undefined || (v.fixtures?.length ?? 0) > 0, {
    message: 'Provide `text`, `fixtures`, or both — there must be something to test',
  })
  .meta({ id: 'TestRulesRequest' });
export type TestRulesRequest = z.infer<typeof TestRulesRequest>;

// A single match the engine produced, shaped for an authoring UI. `match` is the
// RAW substring the rule caught: the input here is the author's own test text, so
// echoing it back is intended — it is what makes the tester useful for tuning a
// matcher. (This deliberately differs from Finding, which masks, because findings
// carry real user content off the enforcement path.)
export const RuleTestMatch = z
  .object({
    ruleId: z.string(),
    category: DetectionCategory,
    severity: Severity,
    span: Span,
    confidence: z.number().min(0).max(1),
    match: z.string(),
  })
  .meta({ id: 'RuleTestMatch' });
export type RuleTestMatch = z.infer<typeof RuleTestMatch>;

// Outcome of running the draft rules against one fixture. `passed` compares the
// fixture's expectation (`shouldMatch`) against what the engine actually did
// (`didMatch`).
export const FixtureResult = z
  .object({
    label: z.string(),
    shouldMatch: z.boolean(),
    didMatch: z.boolean(),
    passed: z.boolean(),
    matches: z.array(RuleTestMatch),
  })
  .meta({ id: 'FixtureResult' });
export type FixtureResult = z.infer<typeof FixtureResult>;

export const TestRulesResponse = z
  .object({
    // Present only when the request supplied `text`.
    adhoc: z.object({ matches: z.array(RuleTestMatch) }).optional(),
    fixtures: z.array(FixtureResult),
    summary: z.object({
      total: z.number().int().nonnegative(),
      passed: z.number().int().nonnegative(),
      failed: z.number().int().nonnegative(),
    }),
    // Ids of rules whose matcher type the engine cannot evaluate today (e.g.
    // `validator`), so they silently never match. Surfaced so an author is not
    // misled by a green run that actually skipped a rule.
    unsupportedRuleIds: z.array(z.string()),
  })
  .meta({ id: 'TestRulesResponse' });
export type TestRulesResponse = z.infer<typeof TestRulesResponse>;
