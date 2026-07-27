// The harness-agnostic core of the /aka:setup calibration → triage →
// remediation wizard. Everything here is pure logic or dependency-injected:
// no host command names, no transcript locations, no judge subprocess. Each
// plugin (Claude Code, Codex CLI) supplies those at its own I/O boundary and
// renders the host-specific surfaces itself.
export * from './onboard-posture.ts';
export * from './posture-reasoning.ts';
export * from './remediation/chain.ts';
export * from './remediation/deliverable.ts';
export * from './remediation/posture.ts';
export * from './remediation/redaction-summary.ts';
export * from './remediation/rotation-checklist.ts';
export { dedupeForJudge } from './triage/dedupe.ts';
export { deriveFalsePositivePatterns } from './triage/false-positive-patterns.ts';
export * from './triage/fixture-exception.ts';
export * from './triage/gate-display.ts';
export * from './triage/join-file.ts';
export { chunkForJudge, chunkIds, groundVerdict, mergeRecommendations } from './triage/merge.ts';
export * from './triage/parse-verdict.ts';
export { deletePlanFile, readPlanFile, writePlanFile } from './triage/plan-file.ts';
export * from './triage/resolve.ts';
export { deriveProvider, deriveSurfacedSecretFindings } from './triage/surfaced-secrets.ts';
export * from './triage/writeback.ts';
