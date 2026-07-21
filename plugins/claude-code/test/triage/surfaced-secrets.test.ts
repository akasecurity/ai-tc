import { safeMaskedMatch } from '@akasecurity/plugin-sdk';
import {
  MaskedSecretFinding,
  type TriageHit,
  type TriageRecommendation,
} from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { deriveProvider, deriveSurfacedSecretFindings } from '../../src/triage/surfaced-secrets.ts';
import { planTriageWriteback } from '../../src/triage/writeback.ts';

// Assembled at runtime so the source carries no contiguous key-shaped literal
// (mirrors the AKIA fixtures) — the value is an obviously-fake example, not a key.
const RAW_STRIPE = ['sk', 'live', '51H8xEXAMPLErawstripesecretVALUE0000'].join('_');
const RAW_AWS = 'AKIAIOSFODNN7EXAMPLE';

const hit = (over: Partial<TriageHit>): TriageHit => ({
  ruleId: 'secrets/aws-access-key',
  category: 'secret',
  severity: 'critical',
  maskedMatch: 'A***E',
  rawMatch: RAW_AWS,
  context: `export KEY=${RAW_AWS} # prod`,
  confidence: 0.9,
  id: '0',
  valueFingerprint: 'ab'.repeat(32),
  keyVersion: 1,
  ...over,
});

describe('deriveProvider — a raw-free provider label from the rule that fired', () => {
  it('reads the provider from the ruleId slug across the id shapes in the tree', () => {
    expect(deriveProvider('secrets/stripe-live-key')).toBe('stripe');
    expect(deriveProvider('secrets/aws-access-key')).toBe('aws');
    expect(deriveProvider('core-secret/aws')).toBe('aws');
    expect(deriveProvider('secret.aws-access-key')).toBe('aws');
  });

  it('falls back to unknown rather than an empty label', () => {
    expect(deriveProvider('')).toBe('unknown');
  });
});

describe('deriveSurfacedSecretFindings — genuine, non-suppressed secret leaks', () => {
  it('surfaces a genuine secret hit as a raw-free MaskedSecretFinding, derived from the hit', () => {
    const surfaced = hit({
      id: '0',
      ruleId: 'secrets/stripe-live-key',
      rawMatch: RAW_STRIPE,
      context: `token=${RAW_STRIPE}`,
      valueFingerprint: 'ab'.repeat(32),
      filePath: '~/.claude/transcripts/2026-07-01.jsonl',
    });
    const rec: TriageRecommendation = {
      perCategory: [
        {
          category: 'secret',
          action: 'warn',
          reasoning: 'a genuine live key',
          genuineCount: 1,
          fpCount: 0,
          fpIds: [],
        },
      ],
      notes: 'looks routine',
    };
    const plan = planTriageWriteback([surfaced], rec);
    const findings = deriveSurfacedSecretFindings([surfaced], rec, plan);

    expect(findings).toHaveLength(1);
    const f = findings[0];
    if (f === undefined) throw new Error('expected one surfaced finding');
    // provider read from the ruleId (raw-free metadata), not the raw key
    expect(f.provider).toBe('stripe');
    // masked token re-derived from the raw value — never the raw key itself
    expect(f.maskedToken).toBe(safeMaskedMatch(RAW_STRIPE));
    expect(f.maskedToken).not.toBe(RAW_STRIPE);
    expect(f.maskedToken).not.toContain(RAW_STRIPE);
    // where-found threaded from the hit's filePath
    expect(f.where.filePath).toBe('~/.claude/transcripts/2026-07-01.jsonl');
    // validity cannot be checked with no network — the honest default is 'unknown'
    expect(f.state).toBe('unknown');
    // the derived shape passes the .strict() raw-free contract
    expect(MaskedSecretFinding.safeParse(f).success).toBe(true);
  });

  it('excludes a suppressed (false-positive) secret hit — only genuine leaks surface', () => {
    const surfaced = hit({
      id: '0',
      ruleId: 'secrets/stripe-live-key',
      rawMatch: RAW_STRIPE,
      context: `token=${RAW_STRIPE}`,
      valueFingerprint: 'ab'.repeat(32),
      filePath: '~/.claude/transcripts/a.jsonl',
    });
    const suppressed = hit({
      id: '1',
      ruleId: 'secrets/aws-access-key',
      rawMatch: RAW_AWS,
      context: `export KEY=${RAW_AWS}`,
      valueFingerprint: 'cd'.repeat(32),
      filePath: '/tmp/agent-dump.txt',
    });
    const rec: TriageRecommendation = {
      perCategory: [
        {
          category: 'secret',
          action: 'warn',
          reasoning: 'one genuine, one canonical example key',
          genuineCount: 1,
          fpCount: 1,
          fpIds: ['1'],
        },
      ],
      notes: 'looks routine',
    };
    const plan = planTriageWriteback([surfaced, suppressed], rec);
    // Guard against vacuity: the suppressed hit really did resolve to a suppression.
    expect(plan.entries).toHaveLength(1);

    const findings = deriveSurfacedSecretFindings([surfaced, suppressed], rec, plan);
    expect(findings.map((f) => f.provider)).toEqual(['stripe']);
  });

  it('surfacing follows the model fpIds verdict, not whether a suppression was written', () => {
    // Suppressions are keyed by (ruleId, fingerprint,
    // keyVersion), so an FP suppression for one rule must NOT hide a genuine
    // same-value hit under a DIFFERENT rule. The genuine hit shares the suppressed
    // hit's fingerprint but has its own id and is absent from fpIds — it surfaces.
    const genuine = hit({
      id: '0',
      ruleId: 'secrets/stripe-live-key',
      rawMatch: RAW_STRIPE,
      context: `token=${RAW_STRIPE}`,
      valueFingerprint: 'ab'.repeat(32),
      filePath: '~/.claude/transcripts/a.jsonl',
    });
    const fp = hit({
      id: '1',
      ruleId: 'secrets/generic-high-entropy-secret',
      rawMatch: RAW_STRIPE,
      context: `token=${RAW_STRIPE}`,
      // same fingerprint as the genuine hit, but dismissed under its own rule
      valueFingerprint: 'ab'.repeat(32),
      filePath: '/tmp/b.txt',
    });
    const rec: TriageRecommendation = {
      perCategory: [
        {
          category: 'secret',
          action: 'warn',
          reasoning: 'one genuine, one false positive under a broad entropy rule',
          genuineCount: 1,
          fpCount: 1,
          fpIds: ['1'],
        },
      ],
      notes: 'looks routine',
    };
    const plan = planTriageWriteback([genuine, fp], rec);
    const findings = deriveSurfacedSecretFindings([genuine, fp], rec, plan);
    // The genuine hit surfaces even though a same-fingerprint suppression exists.
    expect(findings).toHaveLength(1);
    expect(findings[0]?.where.filePath).toBe('~/.claude/transcripts/a.jsonl');
  });

  it('keeps a model-dismissed FP dismissed even when it could not be keyed to a suppression', () => {
    // On the fail-secure unfingerprinted path a
    // model-classified false positive produces NO suppression entry (resolve.ts
    // drops it — no fingerprint to key an exception). It must still stay dismissed,
    // never surface as a live leaked key, and the surfaced count must match the
    // model's genuine count.
    const genuine = hit({
      id: '0',
      ruleId: 'secrets/stripe-live-key',
      rawMatch: RAW_STRIPE,
      context: `token=${RAW_STRIPE}`,
      valueFingerprint: undefined,
      filePath: '~/.claude/transcripts/a.jsonl',
    });
    const fp = hit({
      id: '1',
      ruleId: 'secrets/aws-access-key',
      rawMatch: RAW_AWS,
      context: `export KEY=${RAW_AWS}`,
      valueFingerprint: undefined,
      filePath: '/tmp/agent-dump.txt',
    });
    const rec: TriageRecommendation = {
      perCategory: [
        {
          category: 'secret',
          action: 'warn',
          reasoning: 'one genuine, one canonical example key',
          genuineCount: 1,
          fpCount: 1,
          fpIds: ['1'],
        },
      ],
      notes: 'looks routine',
    };
    const plan = planTriageWriteback([genuine, fp], rec);
    // No fingerprint ⇒ the FP could NOT resolve to a suppression entry.
    expect(plan.entries).toHaveLength(0);

    const findings = deriveSurfacedSecretFindings([genuine, fp], rec, plan);
    // Only the genuine hit surfaces; the dismissed example key never does — and the
    // surfaced count matches the model's genuineCount (1), so the frame is coherent.
    expect(findings).toHaveLength(1);
    expect(findings.map((f) => f.provider)).toEqual(['stripe']);
  });

  it('excludes non-secret (customer-data / PII) hits', () => {
    const secret = hit({ id: '0', valueFingerprint: 'ab'.repeat(32) });
    const pii = hit({
      id: '1',
      category: 'pii',
      ruleId: 'pii/email',
      rawMatch: 'jane.doe@example.com',
      context: 'to: jane.doe@example.com',
      valueFingerprint: 'cd'.repeat(32),
    });
    const rec: TriageRecommendation = {
      perCategory: [
        {
          category: 'secret',
          action: 'warn',
          reasoning: 'a genuine live key',
          genuineCount: 1,
          fpCount: 0,
          fpIds: [],
        },
      ],
      notes: 'looks routine',
    };
    const plan = planTriageWriteback([secret, pii], rec);
    const findings = deriveSurfacedSecretFindings([secret, pii], rec, plan);
    expect(findings).toHaveLength(1);
    expect(findings.every((f) => f.provider === 'aws')).toBe(true);
  });

  it('falls back to an honest location when the hit carried no filePath', () => {
    const surfaced = hit({ id: '0', filePath: undefined });
    const rec: TriageRecommendation = {
      perCategory: [
        {
          category: 'secret',
          action: 'warn',
          reasoning: 'a genuine live key',
          genuineCount: 1,
          fpCount: 0,
          fpIds: [],
        },
      ],
      notes: 'looks routine',
    };
    const plan = planTriageWriteback([surfaced], rec);
    const findings = deriveSurfacedSecretFindings([surfaced], rec, plan);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.where.filePath).toBe('(location unavailable)');
  });

  it('surfaces nothing when the secret category was distrusted (reasoning echoed a raw value)', () => {
    const surfaced = hit({ id: '0', rawMatch: RAW_STRIPE, context: `token=${RAW_STRIPE}` });
    const rec: TriageRecommendation = {
      perCategory: [
        {
          category: 'secret',
          action: 'warn',
          // reasoning that leaks the raw value → the whole category is dropped
          reasoning: `the key ${RAW_STRIPE} is genuine`,
          genuineCount: 1,
          fpCount: 0,
          fpIds: [],
        },
      ],
      notes: 'looks routine',
    };
    const plan = planTriageWriteback([surfaced], rec);
    // The poisoned category left no posture, so no reviewed finding may surface.
    expect(plan.posture.secret).toBeUndefined();
    expect(deriveSurfacedSecretFindings([surfaced], rec, plan)).toEqual([]);
  });
});

// The derivation is LOCATION-scoped: each finding carries one filePath, and that
// path is the only thing that puts a file in the redaction pass's scope and the
// only unit the complete-vs-partial redaction gate counts. The judge, by
// contrast, is VALUE-scoped — it sees one representative per distinct value.
// These tests pin both halves of that split.
describe('deriveSurfacedSecretFindings — one value found in several artifacts', () => {
  // Same value, same rule, three different transcripts: one collapsed finding
  // would put ONE file in redaction scope, leave the key live in the other two,
  // and still satisfy the complete-redaction gate (`redactedKeys === findings.length`).
  const occurrences = ['s1', 's2', 's3'].map((tag, i) =>
    hit({ id: String(i), filePath: `/h/.claude/projects/p/${tag}.jsonl` }),
  );
  // The one the judge would have seen, standing in for the whole value class.
  const [representative] = occurrences;
  if (representative === undefined) throw new Error('unreachable: fixed-length array');

  const genuineRec: TriageRecommendation = {
    perCategory: [
      {
        category: 'secret',
        action: 'redact',
        reasoning: 'a live-looking provider key in old transcripts',
        genuineCount: 1,
        fpCount: 0,
        fpIds: [],
      },
    ],
    notes: '',
  };

  it('surfaces every occurrence so each artifact holding the key enters redaction scope', () => {
    const plan = planTriageWriteback(occurrences, genuineRec);
    const out = deriveSurfacedSecretFindings(occurrences, genuineRec, plan);

    expect(out).toHaveLength(3);
    expect(out.map((f) => f.where.filePath)).toEqual([
      '/h/.claude/projects/p/s1.jsonl',
      '/h/.claude/projects/p/s2.jsonl',
      '/h/.claude/projects/p/s3.jsonl',
    ]);
    // One value, so one masked token across all three — the rows differ only by
    // location, which is exactly what the remediation table's WHERE column shows.
    expect(new Set(out.map((f) => f.maskedToken)).size).toBe(1);
    for (const f of out) expect(MaskedSecretFinding.safeParse(f).success).toBe(true);
  });

  it('expands the judge’s per-representative dismissal over every occurrence of that value', () => {
    // The judge saw only the representative (id '0') and dismissed it. The other
    // two occurrences were never named in fpIds — but they are the same value, so
    // the verdict binds them too and none of the three may surface as a live leak.
    const dismissedRec: TriageRecommendation = {
      perCategory: [
        {
          category: 'secret',
          action: 'warn',
          reasoning: 'canonical documentation example value',
          genuineCount: 0,
          fpCount: 1,
          fpIds: ['0'],
        },
      ],
      notes: '',
    };
    const plan = planTriageWriteback([representative], dismissedRec);
    expect(deriveSurfacedSecretFindings(occurrences, dismissedRec, plan)).toEqual([]);
  });

  it('never lets a dismissal cross to a different rule sharing the fingerprint', () => {
    // Suppressions key on ruleId+fingerprint+keyVersion, so the value class does
    // too: a same-value hit under a DIFFERENT rule is a different class and must
    // still surface after the first rule's hit is dismissed.
    const otherRule = hit({
      id: '9',
      ruleId: 'secrets/generic-high-entropy',
      filePath: '/h/.claude/projects/p/s9.jsonl',
    });
    const dismissedRec: TriageRecommendation = {
      perCategory: [
        {
          category: 'secret',
          action: 'warn',
          reasoning: 'example value under the aws rule',
          genuineCount: 0,
          fpCount: 1,
          fpIds: ['0'],
        },
      ],
      notes: '',
    };
    const hits = [representative, otherRule];
    const plan = planTriageWriteback(hits, dismissedRec);
    const out = deriveSurfacedSecretFindings(hits, dismissedRec, plan);
    expect(out.map((f) => f.where.filePath)).toEqual(['/h/.claude/projects/p/s9.jsonl']);
  });
});
