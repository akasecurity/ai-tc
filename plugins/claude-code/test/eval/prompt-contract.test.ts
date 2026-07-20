import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  type CalibrationPreview,
  type FalsePositivePatternGroup,
  type MaskedSecretFinding,
  severityFloorPosture,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  carriesRunFindings,
  checkFpSignalContract,
  checkNarrationContract,
  checkPostureContract,
  deriveRepoFactFixture,
  type LabeledCountClaim,
  type NarrationClaimSet,
  parseCalibrationFrame,
  type PostureEvidenceClaim,
  type ReadBoundaryTrace,
  type RepoFactFixture,
} from '../../eval/prompt-contract.ts';
import { frameCalibration } from '../../src/calibration.ts';
import { validateTightenOnly } from '../../src/posture-reasoning.ts';
import { frameJsonBlock } from '../../src/setup-frame-json.ts';

// A calibration frame built through the real composition seam (frameCalibration),
// not hand-rolled — the same function apply-suppressions uses to emit the frame
// JSON. 1 genuine secret finding, 12 suppressed as a false-positive pattern.
const preview: CalibrationPreview = {
  categories: [{ category: 'secret', genuineCount: 1, fpCount: 12, egress: false }],
  posture: severityFloorPosture(),
};

const masked: MaskedSecretFinding[] = [
  {
    provider: 'stripe',
    maskedToken: 'sk_live_****',
    where: { filePath: '~/.claude/transcripts/2026-07-01.jsonl' },
    state: 'still-valid',
  },
];

const patterns: FalsePositivePatternGroup[] = [
  {
    pattern: 'test_sk_live_placeholder',
    count: 12,
    values: [
      {
        ruleId: 'secrets/stripe-live-key',
        category: 'secret',
        valueFingerprint: 'ab'.repeat(32),
        keyVersion: 1,
      },
    ],
  },
];

const { frame } = frameCalibration(preview, masked, patterns);

describe('parseCalibrationFrame', () => {
  it('parses the frame back out of the real emission seam (frameJsonBlock)', () => {
    const stdout = `some rendered card\n${frameJsonBlock(frame)}trailing note\n`;
    expect(parseCalibrationFrame(stdout)).toEqual(frame);
  });

  it('returns undefined when no frame JSON block is present — the JSON-absent leg', () => {
    expect(parseCalibrationFrame('just a plain card, no frame here')).toBeUndefined();
  });
});

describe('carriesRunFindings', () => {
  it('is true for a frame composed with the run’s maskedFindings', () => {
    expect(carriesRunFindings(frame)).toBe(true);
  });

  it('is false for the static, findings-free frame the JSON-absent leg degrades to', () => {
    const { frame: noFindings } = frameCalibration(preview);
    expect(carriesRunFindings(noFindings)).toBe(false);
  });
});

describe('checkNarrationContract', () => {
  const groundedCounts: readonly LabeledCountClaim[] = [
    { field: 'total', count: 13 },
    { field: 'important', count: 1 },
    { field: 'routine', count: 12 },
  ];

  const groundedClaims: NarrationClaimSet = {
    spokenCounts: groundedCounts,
    referencedValues: ['sk_live_****'],
    citedFindingFacts: [
      {
        maskedToken: 'sk_live_****',
        explanation:
          'A Stripe live secret key (sk_live_****) turned up in a transcript — if it leaked it grants live payment API access, so it should be rotated.',
        assertedProvider: 'stripe',
        assertedLocation: '~/.claude/transcripts/2026-07-01.jsonl',
        assertedState: 'still-valid',
      },
    ],
  };

  it('passes a grounded claim set — labeled counts, masked values, and cited facts all match the frame', () => {
    expect(checkNarrationContract(frame, groundedClaims)).toEqual({ ok: true });
  });

  it('fails an invented spoken count naming a real field with a fabricated number', () => {
    const invented: NarrationClaimSet = {
      ...groundedClaims,
      spokenCounts: [{ field: 'total', count: 99 }],
    };
    const result = checkNarrationContract(frame, invented);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/spoken count/);
  });

  it('fails a MISLABELED count — a real frame number attached to the wrong named field', () => {
    // 1 is the frame's real `important` count, not its `total` — a
    // membership-only check would pass this (1 is A frame count); the labeled
    // check must catch the mislabeling.
    const mislabeled: NarrationClaimSet = {
      ...groundedClaims,
      spokenCounts: [{ field: 'total', count: 1 }],
    };
    const result = checkNarrationContract(frame, mislabeled);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/mislabeled|does not match/);
  });

  it('fails a spoken count naming a finding-kind field the frame never surfaced', () => {
    const unknownField: NarrationClaimSet = {
      ...groundedClaims,
      spokenCounts: [{ field: { category: 'financial' }, count: 1 }],
    };
    const result = checkNarrationContract(frame, unknownField);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/does not carry/);
  });

  it('fails a referenced value that is not a masked token (raw/unmasked value)', () => {
    const raw: NarrationClaimSet = {
      ...groundedClaims,
      referencedValues: ['sk_live_51Hraw0000000000000000'],
    };
    const result = checkNarrationContract(frame, raw);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/masked/);
  });

  it('fails a cited finding fact whose masked token has no corresponding frame fact (invented claim)', () => {
    const invented: NarrationClaimSet = {
      ...groundedClaims,
      citedFindingFacts: [{ maskedToken: 'AKIA****************', explanation: 'an AWS key' }],
    };
    const result = checkNarrationContract(frame, invented);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/no corresponding frame fact/);
  });

  it('fails an invented provider on an otherwise real finding — the token is real, the attribute is not', () => {
    const invented: NarrationClaimSet = {
      ...groundedClaims,
      citedFindingFacts: [
        {
          maskedToken: 'sk_live_****',
          explanation: 'A stray AWS key, unrelated to Stripe.',
          assertedProvider: 'aws',
        },
      ],
    };
    const result = checkNarrationContract(frame, invented);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/invented finding attribute/);
  });

  it('fails an invented location on an otherwise real finding', () => {
    const invented: NarrationClaimSet = {
      ...groundedClaims,
      citedFindingFacts: [
        {
          maskedToken: 'sk_live_****',
          explanation: 'Found in the project source tree.',
          assertedLocation: 'src/config/payments.ts',
        },
      ],
    };
    const result = checkNarrationContract(frame, invented);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/invented finding attribute/);
  });

  it('fails an invented validity/state on an otherwise real finding', () => {
    const invented: NarrationClaimSet = {
      ...groundedClaims,
      citedFindingFacts: [
        {
          maskedToken: 'sk_live_****',
          explanation: 'This key no longer works, so no need to rotate it.',
          assertedState: 'invalid',
        },
      ],
    };
    const result = checkNarrationContract(frame, invented);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/invented finding attribute/);
  });

  it('fails a bare count-recital that cites no explained finding', () => {
    const bare: NarrationClaimSet = {
      spokenCounts: groundedCounts,
      referencedValues: [],
      citedFindingFacts: [],
    };
    const result = checkNarrationContract(frame, bare);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/bare count recital/);
  });
});

describe('checkPostureContract', () => {
  const fixture: RepoFactFixture = {
    facts: [
      'package.json declares a "stripe" dependency',
      'src/models/customer.ts defines a Customer model',
    ],
  };

  const workingTreeOnlyTrace: ReadBoundaryTrace = {
    reads: [
      { source: 'working-tree', path: 'package.json' },
      { source: 'working-tree', path: 'src/models/customer.ts' },
    ],
    consentRequested: false,
    consentGatedPathInvoked: false,
  };

  const groundedEvidence: readonly PostureEvidenceClaim[] = [
    {
      category: 'financial',
      fact: 'package.json declares a "stripe" dependency',
      rationale: 'Stripe + customer models here — financial → warn',
    },
  ];

  it('passes a tighten-only proposal with fixture-grounded, matching-category evidence and a working-tree-only trace', () => {
    const result = checkPostureContract({
      proposed: { financial: 'redact' },
      evidence: groundedEvidence,
      fixture,
      trace: workingTreeOnlyTrace,
    });
    expect(result).toEqual({ ok: true });
  });

  it('rejects a loosening proposal via the tighten-only guard', () => {
    const result = checkPostureContract({
      proposed: { secret: 'monitor' }, // secret floors at 'warn'
      evidence: [],
      fixture,
      trace: workingTreeOnlyTrace,
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/may only tighten/);
  });

  it('fails a rationale citing a fact absent from the fixture (invented repo fact)', () => {
    const result = checkPostureContract({
      proposed: { financial: 'redact' },
      evidence: [
        {
          category: 'financial',
          fact: 'src/models/payroll.ts defines a Payroll model',
          rationale: 'Payroll data here → financial warn',
        },
      ],
      fixture,
      trace: workingTreeOnlyTrace,
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/invented repo fact/);
  });

  it('fails a tightening deviation with NO evidence at all (evidence: [])', () => {
    const result = checkPostureContract({
      proposed: { financial: 'redact' },
      evidence: [],
      fixture,
      trace: workingTreeOnlyTrace,
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/no matching-category evidence/);
  });

  it('fails a tightening deviation whose only evidence is CATEGORY-MISMATCHED (fixture-grounded, but for the wrong category)', () => {
    const result = checkPostureContract({
      proposed: { financial: 'redact' },
      evidence: [
        {
          category: 'secret',
          fact: 'package.json declares a "stripe" dependency',
          rationale: 'Stripe here → secret redact',
        },
      ],
      fixture,
      trace: workingTreeOnlyTrace,
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/no matching-category evidence/);
  });

  it('fails a read-boundary trace carrying a historical-store read', () => {
    const result = checkPostureContract({
      proposed: { financial: 'redact' },
      evidence: groundedEvidence,
      fixture,
      trace: {
        reads: [
          { source: 'working-tree', path: 'package.json' },
          { source: 'historical-store', path: '~/.aka/data/aka.db' },
        ],
        consentRequested: false,
        consentGatedPathInvoked: false,
      },
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/historical-store read/);
  });

  it('fails a read-boundary trace that requests scan/history consent', () => {
    const result = checkPostureContract({
      proposed: { financial: 'redact' },
      evidence: groundedEvidence,
      fixture,
      trace: {
        reads: [{ source: 'working-tree', path: 'package.json' }],
        consentRequested: true,
        consentGatedPathInvoked: false,
      },
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/consent/);
  });

  it('fails a read-boundary trace that invoked a consent-gated path, even with no explicit consent request', () => {
    const result = checkPostureContract({
      proposed: { financial: 'redact' },
      evidence: groundedEvidence,
      fixture,
      trace: {
        reads: [{ source: 'working-tree', path: 'package.json' }],
        consentRequested: false,
        consentGatedPathInvoked: true,
      },
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/consent/);
  });

  it('the posture fail-open leg: over a bare fixture with no inferable signals, the contract holds with no proposed deviation and no rationale, and the accepted posture is byte-for-byte the severity floor', () => {
    const bareFixture: RepoFactFixture = { facts: [] };
    const bareTrace: ReadBoundaryTrace = {
      reads: [],
      consentRequested: false,
      consentGatedPathInvoked: false,
    };
    const noDeviationProposal = {};
    const noRationale: readonly PostureEvidenceClaim[] = [];

    const result = checkPostureContract({
      proposed: noDeviationProposal,
      evidence: noRationale,
      fixture: bareFixture,
      trace: bareTrace,
    });
    expect(result).toEqual({ ok: true });

    // The same computation checkPostureContract runs internally for this
    // input — proves the recommendation is the floor defaults exactly, not just
    // that the contract happened to pass.
    const floor = severityFloorPosture();
    expect(validateTightenOnly(noDeviationProposal, floor)).toEqual(floor);
  });
});

describe('deriveRepoFactFixture — real working-tree fact/read-boundary producer', () => {
  let rootDir: string;

  beforeEach(() => {
    rootDir = mkdtempSync(join(tmpdir(), 'aka-repofact-'));
  });

  afterEach(() => {
    rmSync(rootDir, { recursive: true, force: true });
  });

  it('derives real facts by actually reading a working tree — not a hand-typed literal', () => {
    writeFileSync(
      join(rootDir, 'package.json'),
      JSON.stringify({ name: 'fixture-repo', dependencies: { stripe: '^1.0.0' } }),
    );
    mkdirSync(join(rootDir, 'src', 'models'), { recursive: true });
    writeFileSync(
      join(rootDir, 'src', 'models', 'customer.ts'),
      'export class Customer {\n  id: string;\n}\n',
    );

    const { fixture } = deriveRepoFactFixture(rootDir);

    expect(fixture.facts).toContain('package.json declares a "stripe" dependency');
    expect(fixture.facts).toContain('src/models/customer.ts defines a Customer model');
  });

  it('records a read-boundary trace of only the working-tree paths it actually read, with no consent', () => {
    writeFileSync(join(rootDir, 'package.json'), JSON.stringify({ name: 'fixture-repo' }));

    const { trace } = deriveRepoFactFixture(rootDir);

    expect(trace.reads.length).toBeGreaterThan(0);
    for (const read of trace.reads) {
      expect(read.source).toBe('working-tree');
    }
    expect(trace.reads.some((r) => r.path === 'package.json')).toBe(true);
    expect(trace.consentRequested).toBe(false);
    expect(trace.consentGatedPathInvoked).toBe(false);
  });

  it('derives no facts from a bare working tree with no inferable signals', () => {
    const { fixture } = deriveRepoFactFixture(rootDir);
    expect(fixture.facts).toEqual([]);
  });

  it('feeds real, working-tree-derived facts and trace straight into checkPostureContract', () => {
    writeFileSync(
      join(rootDir, 'package.json'),
      JSON.stringify({ name: 'fixture-repo', dependencies: { stripe: '^1.0.0' } }),
    );
    mkdirSync(join(rootDir, 'src', 'models'), { recursive: true });
    writeFileSync(
      join(rootDir, 'src', 'models', 'customer.ts'),
      'export class Customer {\n  id: string;\n}\n',
    );

    const { fixture, trace } = deriveRepoFactFixture(rootDir);

    const result = checkPostureContract({
      proposed: { financial: 'redact' },
      evidence: [
        {
          category: 'financial',
          fact: 'package.json declares a "stripe" dependency',
          rationale: 'Stripe + customer models here — financial → warn',
        },
      ],
      fixture,
      trace,
    });
    expect(result).toEqual({ ok: true });
  });
});

describe('checkFpSignalContract — FP-signal grounding', () => {
  it('passes a named pattern and count that resolve to the emitted signal', () => {
    const result = checkFpSignalContract(frame, {
      pattern: 'test_sk_live_placeholder',
      count: 12,
    });
    expect(result).toEqual({ ok: true });
  });

  it('fails an invented pattern name absent from the signal', () => {
    const result = checkFpSignalContract(frame, { pattern: 'not_a_real_pattern', count: 12 });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/invented pattern/);
  });

  it('fails a fabricated count for an otherwise real pattern', () => {
    const result = checkFpSignalContract(frame, {
      pattern: 'test_sk_live_placeholder',
      count: 999,
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/fabricated count/);
  });

  it('fails when the frame carries no false-positive pattern signal at all', () => {
    const { frame: noSignal } = frameCalibration(preview, masked);
    const result = checkFpSignalContract(noSignal, {
      pattern: 'test_sk_live_placeholder',
      count: 12,
    });
    expect(result.ok).toBe(false);
  });
});
