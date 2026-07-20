/**
 * The Claude-layer evaluation seam: a scripted, deterministic checker over the
 * frame JSON the setup-wizard scripts already emit (`readFrameJsonBlock` /
 * `CalibrationFrame` from `src/setup-frame-json.ts` and `@akasecurity/schema`)
 * — no second production data channel. It asserts that a candidate set of
 * narrated/reasoned claims is GROUNDED in the script-emitted facts, so a
 * Claude-authored narration, posture rationale, or fixture-offer pattern can be
 * checked for invention without invoking Claude: this module is pure and
 * Claude-free, over its inputs only (no store, no network, no
 * `process.env`).
 *
 * It covers the three grounding contracts the evaluation seam is the
 * automation owner (executor, not behavioral owner) for:
 *   - checkNarrationContract — narrated counts and finding facts (labeled
 *     per-field counts; cited finding facts grounded on content —
 *     provider/location/validity — not just a matching masked token)
 *   - checkPostureContract   — repo-aware posture reasoning (fixture-grounded
 *     evidence, mandatory per-deviation and category-matched — an empty or
 *     mismatched evidence list on a tightened category fails)
 *   - checkFpSignalContract  — the false-positive-signal grounding leg
 *
 * deriveRepoFactFixture is the real, test-only producer for checkPostureContract's
 * RepoFactFixture/ReadBoundaryTrace inputs: it derives both by actually reading
 * a working tree rather than a hand-typed fixture literal, while remaining
 * test-only — see its own doc comment.
 *
 * Every check returns a structured ContractCheckResult (never a bare boolean)
 * so a caller can assert exactly why a check failed, not just that it did.
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

import type {
  BuiltinPolicyId,
  CalibrationFrame,
  DetectionCategory,
  SecretFindingState,
} from '@akasecurity/schema';
import {
  CalibrationFrame as CalibrationFrameSchema,
  severityFloorPosture,
} from '@akasecurity/schema';

import { PostureLooseningError, validateTightenOnly } from '../src/posture-reasoning.ts';
import { readFrameJsonBlock } from '../src/setup-frame-json.ts';

export type ContractCheckResult =
  { readonly ok: true } | { readonly ok: false; readonly reason: string };

// Parses a captured frame block (the same `<<<AKA_FRAME_JSON …` block the
// scripts emit at stdout) into a validated CalibrationFrame. Returns undefined
// when there is no readable block — absent, or present but not valid JSON
// (readFrameJsonBlock collapses both to undefined). This is the JSON-absent leg
// every check's caller degrades to the static frame over, never invents a
// narration for. A block that IS present and valid JSON but fails
// CalibrationFrame validation throws a ZodError rather than degrading: a
// malformed frame emission is a bug in the emitter, surfaced loudly, not a
// missing frame.
export function parseCalibrationFrame(stdout: string): CalibrationFrame | undefined {
  const raw = readFrameJsonBlock(stdout);
  if (raw === undefined) return undefined;
  return CalibrationFrameSchema.parse(raw);
}

// Returns true when the frame carries the run's `maskedFindings` — the field
// frameCalibration() populates only when a secret finding actually surfaced
// (src/calibration.ts). This is a presence check, not a provenance proof: a
// pure function over a CalibrationFrame cannot tell a genuine composition
// output from a hand-built object that sets the same field. What it does
// distinguish is a finding-bearing frame from the static, empty frame the
// JSON-absent leg degrades to — so a finding-fact claim is only grounded
// against a frame that actually carries findings, never against the static
// frame.
export function carriesRunFindings(frame: CalibrationFrame): boolean {
  return frame.maskedFindings !== undefined;
}

// ─── Narration contract ─────────────────────────────────────────────────────

// Which frame field a spoken count claims to represent: one of the frame's
// aggregate counts, or a specific finding kind's count (keyed by its
// DetectionCategory). Naming the field — not just the number — is what lets
// the contract catch a MISLABELED count: a narration that speaks a real frame
// number but attaches it to the wrong claim (e.g. calling the important count
// "routine") passes a bare membership check but fails a labeled one.
export type CountField =
  'total' | 'important' | 'routine' | { readonly category: DetectionCategory };

// A single spoken count, naming which frame field it claims to be.
export interface LabeledCountClaim {
  readonly field: CountField;
  readonly count: number;
}

export interface NarrationFindingClaim {
  readonly maskedToken: string;
  readonly explanation: string;
  // Asserted attributes of the finding `maskedToken` names. Each present
  // attribute is cross-checked against the actual MaskedSecretFinding fields —
  // not just the token — so a claim that reuses a real masked token but
  // invents what it is (wrong provider, wrong location, wrong validity/state)
  // still fails as an invented finding attribute, even though the token itself
  // is real. `assertedState` covers both "what state is this in" and validity
  // ('still-valid' | 'unknown' | 'invalid').
  readonly assertedProvider?: string;
  readonly assertedLocation?: string;
  readonly assertedState?: SecretFindingState;
}

// A candidate set of claims a finding narration makes: the labeled counts it
// speaks, the value tokens it references, and the per-finding facts it
// explains.
export interface NarrationClaimSet {
  readonly spokenCounts: readonly LabeledCountClaim[];
  readonly referencedValues: readonly string[];
  readonly citedFindingFacts: readonly NarrationFindingClaim[];
}

// Resolves a CountField to the value the frame actually carries for it, or
// undefined when the frame carries no such field (e.g. a finding-kind category
// that never surfaced).
function resolveCountField(frame: CalibrationFrame, field: CountField): number | undefined {
  if (field === 'total') return frame.counts.total;
  if (field === 'important') return frame.counts.important;
  if (field === 'routine') return frame.counts.routine;
  return frame.findingKinds.find((k) => k.category === field.category)?.count;
}

function describeCountField(field: CountField): string {
  return typeof field === 'string' ? field : `findingKinds["${field.category}"]`;
}

// Asserts every claim in `claims` is grounded in `frame`:
//   - every spoken count names a frame field (counts.total/important/routine
//     or a findingKinds category) the frame actually carries, and its number
//     equals that NAMED field's value — a count that matches some other frame
//     field is a mislabeled claim, not a grounded one;
//   - every referenced value appears masked — it must match a
//     maskedFindings[].maskedToken, never a raw value;
//   - every cited finding fact's masked token has a corresponding
//     maskedFindings entry (an invented claim fails), and every asserted
//     attribute on that fact (provider/location/validity-state) matches the
//     actual finding's fields — an invented attribute on a real token fails;
//   - the claim set is not a bare count-recital — it must explain at least one
//     known finding, not just restate counts.
export function checkNarrationContract(
  frame: CalibrationFrame,
  claims: NarrationClaimSet,
): ContractCheckResult {
  for (const claim of claims.spokenCounts) {
    const actual = resolveCountField(frame, claim.field);
    if (actual === undefined) {
      return {
        ok: false,
        reason: `spoken count names frame field ${describeCountField(claim.field)}, which the frame does not carry`,
      };
    }
    if (actual !== claim.count) {
      return {
        ok: false,
        reason: `spoken count ${String(claim.count)} labeled ${describeCountField(claim.field)} does not match the frame's actual ${describeCountField(claim.field)} count (${String(actual)}) — mislabeled count`,
      };
    }
  }

  const maskedTokens = (frame.maskedFindings ?? []).map((f) => f.maskedToken);
  for (const value of claims.referencedValues) {
    if (!maskedTokens.includes(value)) {
      return {
        ok: false,
        reason: `referenced value "${value}" does not match a masked finding token — values must appear masked, never raw`,
      };
    }
  }

  for (const fact of claims.citedFindingFacts) {
    const finding = (frame.maskedFindings ?? []).find((f) => f.maskedToken === fact.maskedToken);
    if (!finding) {
      return {
        ok: false,
        reason: `cited finding "${fact.maskedToken}" has no corresponding frame fact — invented claim`,
      };
    }
    if (fact.assertedProvider !== undefined && fact.assertedProvider !== finding.provider) {
      return {
        ok: false,
        reason: `cited finding "${fact.maskedToken}" asserts provider "${fact.assertedProvider}", but the frame records provider "${finding.provider}" — invented finding attribute`,
      };
    }
    if (fact.assertedLocation !== undefined && fact.assertedLocation !== finding.where.filePath) {
      return {
        ok: false,
        reason: `cited finding "${fact.maskedToken}" asserts location "${fact.assertedLocation}", but the frame records location "${finding.where.filePath}" — invented finding attribute`,
      };
    }
    if (fact.assertedState !== undefined && fact.assertedState !== finding.state) {
      return {
        ok: false,
        reason: `cited finding "${fact.maskedToken}" asserts state "${fact.assertedState}", but the frame records state "${finding.state}" — invented finding attribute`,
      };
    }
  }

  const explainsAKnownFinding = claims.citedFindingFacts.some(
    (fact) => fact.explanation.trim() !== '',
  );
  if (!explainsAKnownFinding) {
    return {
      ok: false,
      reason:
        'claim set only restates counts without explaining a known finding — bare count recital',
    };
  }

  return { ok: true };
}

// ─── Posture contract ───────────────────────────────────────────────────────

export interface PostureEvidenceClaim {
  readonly category: DetectionCategory;
  readonly fact: string;
  readonly rationale: string;
}

// Test-only shape: a controlled working-tree fixture's known, enumerated repo
// facts a posture rationale's cited evidence must resolve against. Not a
// production schema shape — it attaches at the same frame-JSON seam as a test
// input alongside the captured frame, not a second production data channel. A
// caller can fill it by hand (a small controlled fixture) or, via
// deriveRepoFactFixture below, from an actual temporary working tree's real
// facts.
export interface RepoFactFixture {
  readonly facts: readonly string[];
}

export type ReadBoundarySource = 'working-tree' | 'historical-store';

export interface ReadBoundaryTraceEntry {
  readonly source: ReadBoundarySource;
  readonly path: string;
}

// Test-only shape: an observable trace of what a posture run read and whether
// it solicited consent, recorded by the harness driving the run. Not a
// production schema shape — see RepoFactFixture doc above.
export interface ReadBoundaryTrace {
  readonly reads: readonly ReadBoundaryTraceEntry[];
  readonly consentRequested: boolean;
  readonly consentGatedPathInvoked: boolean;
}

// The real, test-only producer for RepoFactFixture/ReadBoundaryTrace: derives
// both by actually reading a working tree rooted at `rootDir`, rather than a
// hand-typed fixture literal. It reads the same narrow surface a repo-aware
// posture pass inspects — package.json's declared dependencies and any model
// source files under src/models — and records every path it reads as the
// trace, so a checkPostureContract run fed this pair is checked against facts
// genuinely present on disk, not an assertion typed by hand. Still test-only
// (lives in eval/, never bundled into the shipped plugin, per this module's
// header) — reading a real directory is not a second production data channel.
export function deriveRepoFactFixture(rootDir: string): {
  readonly fixture: RepoFactFixture;
  readonly trace: ReadBoundaryTrace;
} {
  const reads: ReadBoundaryTraceEntry[] = [];
  const facts: string[] = [];

  const pkgPath = join(rootDir, 'package.json');
  if (existsSync(pkgPath)) {
    reads.push({ source: 'working-tree', path: 'package.json' });
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    for (const name of Object.keys(deps)) {
      facts.push(`package.json declares a "${name}" dependency`);
    }
  }

  const modelsDir = join(rootDir, 'src', 'models');
  if (existsSync(modelsDir)) {
    for (const entry of readdirSync(modelsDir)) {
      const filePath = join(modelsDir, entry);
      if (!entry.endsWith('.ts') || !statSync(filePath).isFile()) continue;
      const relPath = relative(rootDir, filePath);
      reads.push({ source: 'working-tree', path: relPath });
      const content = readFileSync(filePath, 'utf8');
      const match = /\b(?:class|interface)\s+(\w+)\b/.exec(content);
      const modelName = match?.[1];
      if (modelName) {
        facts.push(`${relPath} defines a ${modelName} model`);
      }
    }
  }

  return {
    fixture: { facts },
    trace: { reads, consentRequested: false, consentGatedPathInvoked: false },
  };
}

export interface PostureContractInput {
  readonly proposed: Partial<Record<DetectionCategory, BuiltinPolicyId>>;
  readonly floor?: Record<DetectionCategory, BuiltinPolicyId>;
  readonly evidence: readonly PostureEvidenceClaim[];
  readonly fixture: RepoFactFixture;
  readonly trace: ReadBoundaryTrace;
}

// Asserts a repo-aware posture proposal is tighten-only, evidence-grounded,
// and working-tree-only:
//   (a) the proposal passes the tighten-only guard (validateTightenOnly) —
//       a loosening suggestion is rejected;
//   (b) every cited evidence fact resolves to a known fact in the fixture — a
//       rationale citing a fact absent from the fixture (an invented repo
//       fact) fails;
//   (c) every category the proposal actually tightens above the floor carries
//       at least one evidence claim category-matched to it — a tightened
//       category with no evidence at all, or whose only evidence names a
//       DIFFERENT category, is an undocumented deviation and fails, even
//       though its evidence (if any) individually passes (b);
//   (d) the read-boundary trace shows only working-tree reads and no
//       historical-store read, and requests neither scan nor history consent
//       nor invokes any consent-gated path.
export function checkPostureContract(input: PostureContractInput): ContractCheckResult {
  const floor = input.floor ?? severityFloorPosture();
  let accepted: Record<DetectionCategory, BuiltinPolicyId>;
  try {
    accepted = validateTightenOnly(input.proposed, floor);
  } catch (err) {
    if (err instanceof PostureLooseningError) {
      return { ok: false, reason: err.message };
    }
    throw err;
  }

  for (const claim of input.evidence) {
    if (!input.fixture.facts.includes(claim.fact)) {
      return {
        ok: false,
        reason: `cited evidence fact "${claim.fact}" is absent from the fixture's known repo facts — invented repo fact`,
      };
    }
  }

  for (const category of Object.keys(input.proposed) as DetectionCategory[]) {
    if (accepted[category] === floor[category]) continue; // not an actual deviation
    const hasMatchingEvidence = input.evidence.some((e) => e.category === category);
    if (!hasMatchingEvidence) {
      return {
        ok: false,
        reason: `category "${category}" tightens the floor to "${accepted[category]}" but carries no matching-category evidence — undocumented deviation`,
      };
    }
  }

  const historicalRead = input.trace.reads.find((r) => r.source === 'historical-store');
  if (historicalRead) {
    return {
      ok: false,
      reason: `read-boundary trace recorded a historical-store read (${historicalRead.path}) — posture reasoning must be working-tree-only`,
    };
  }

  if (input.trace.consentRequested || input.trace.consentGatedPathInvoked) {
    return {
      ok: false,
      reason:
        'read-boundary trace shows a scan/history consent request or a consent-gated path invocation — working-tree inspection must be consent-free',
    };
  }

  return { ok: true };
}

// ─── FP-signal grounding ────────────────────────────────────────────────────

export interface NamedFpClaim {
  readonly pattern: string;
  readonly count: number;
}

// Asserts a candidate named false-positive pattern/count resolves to the
// frame's falsePositivePatterns signal — an invented pattern name or a
// fabricated count fails.
export function checkFpSignalContract(
  frame: CalibrationFrame,
  claim: NamedFpClaim,
): ContractCheckResult {
  const signal = frame.falsePositivePatterns ?? [];
  const group = signal.find((g) => g.pattern === claim.pattern);
  if (!group) {
    return {
      ok: false,
      reason: `named pattern "${claim.pattern}" does not resolve to the frame's falsePositivePatterns signal — invented pattern`,
    };
  }
  if (group.count !== claim.count) {
    return {
      ok: false,
      reason: `named count ${String(claim.count)} for pattern "${claim.pattern}" does not match the emitted signal's count ${String(group.count)} — fabricated count`,
    };
  }

  return { ok: true };
}
