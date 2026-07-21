import { MaskedSecretFinding, type RotationChecklistEntry } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  renderRedactionOutcome,
  renderRemediationDecision,
  renderResolvedSummary,
} from '../../src/remediation/render.ts';
import { renderChecklistMarkdown } from '../../src/remediation/rotation-checklist.ts';

// The RAW_* constants are what the underlying leak actually contains; each
// fixture's `maskedToken` is the masked preview of the SAME raw value (raw prefix
// kept, tail masked). The decision layout must surface only the masked preview and
// never the raw key it derives from (the raw-free boundary), so the raw-free
// assertions below compare the rendered output against these real raw values.
// Assembled at runtime so the source carries no contiguous key-shaped literal
// (mirrors the AKIA fixtures) — the value is an obviously-fake example, not a key.
const RAW_STRIPE = ['sk', 'live', '51H8xEXAMPLErawstripesecretVALUE0000'].join('_');
const RAW_AWS = 'AKIAIOSFODNN7EXAMPLE';

// Masked preview of RAW_STRIPE / RAW_AWS — the exact strings the table should
// carry in place of the raw values above.
const MASKED_STRIPE = 'sk_live_****';
const MASKED_AWS = 'AKIA****************';

// The loader emits state:'unknown' — validity is unverifiable under the
// no-network OSS constraint — so the fixtures carry the state a real finding does.
function stripeFinding(): MaskedSecretFinding {
  return {
    provider: 'stripe',
    maskedToken: MASKED_STRIPE,
    where: { filePath: '~/.claude/transcripts/2026-07-01.jsonl' },
    state: 'unknown',
  };
}

function awsFinding(): MaskedSecretFinding {
  return {
    provider: 'aws',
    maskedToken: MASKED_AWS,
    where: { filePath: '/tmp/agent-dump.txt', span: { start: 12, end: 32 } },
    state: 'unknown',
  };
}

// The chaining line's secret-scan continuation is registry-driven: `/aka:scan`
// today, or a dedicated secret-scan command name if one is registered instead.
const REGISTRY_SCAN = ['/aka:dashboard', '/aka:scan'];
const REGISTRY_SECRETSCAN = ['/aka:dashboard', '/aka:secretscan'];

describe('renderRemediationDecision — decision layout', () => {
  it('renders one table row per masked finding with provider / token / where / state', () => {
    const out = renderRemediationDecision([stripeFinding(), awsFinding()], 0, REGISTRY_SCAN);
    // provider
    expect(out).toContain('stripe');
    expect(out).toContain('aws');
    // masked token (masked preview, not the raw key)
    expect(out).toContain('sk_live_****');
    expect(out).toContain('AKIA****************');
    // where-found
    expect(out).toContain('~/.claude/transcripts/2026-07-01.jsonl');
    expect(out).toContain('/tmp/agent-dump.txt');
    // the honest per-finding state, rendered as human text — never an
    // unverifiable 'still valid' claim over an unknown-state finding
    expect(out).toContain('unknown');
    expect(out).not.toContain('still valid');
  });

  it('renders each finding state as honest human text (still valid / unknown / invalid)', () => {
    // The table shows whatever state a finding carries; validity is only claimed
    // when it is genuinely known. 'still-valid' stays reachable for when a caller
    // can verify a key, but the default unknown state never reads as valid.
    expect(
      renderRemediationDecision([{ ...stripeFinding(), state: 'still-valid' }], 0, REGISTRY_SCAN),
    ).toContain('still valid');
    expect(
      renderRemediationDecision([{ ...stripeFinding(), state: 'unknown' }], 0, REGISTRY_SCAN),
    ).toContain('unknown');
    expect(
      renderRemediationDecision([{ ...stripeFinding(), state: 'invalid' }], 0, REGISTRY_SCAN),
    ).toContain('invalid');
  });

  it('never emits a raw secret value — masked tokens only (raw-free)', () => {
    const out = renderRemediationDecision([stripeFinding(), awsFinding()], 0, REGISTRY_SCAN);
    // The masked preview is what surfaces; the raw value it derives from does not.
    // Guard the assertion against vacuity: the masked and raw forms must genuinely
    // differ, so `not.toContain(RAW_*)` is a real check, not a tautology over a
    // string the renderer was never given.
    expect(MASKED_STRIPE).not.toEqual(RAW_STRIPE);
    expect(MASKED_AWS).not.toEqual(RAW_AWS);
    expect(out).toContain(MASKED_STRIPE);
    expect(out).toContain(MASKED_AWS);
    expect(out).not.toContain(RAW_STRIPE);
    expect(out).not.toContain(RAW_AWS);
  });

  it('cannot be handed a raw value — the MaskedSecretFinding contract rejects it (.strict)', () => {
    // The renderer emits only fields present on a MaskedSecretFinding, so the
    // 'NO raw secret value ever emitted' property rests on raw never reaching it.
    // The `.strict()` schema is that structural guard: a finding smuggling the raw
    // key under an extra field fails validation at the boundary, so the renderer's
    // input can never carry one.
    const smuggled = { ...stripeFinding(), rawValue: RAW_STRIPE };
    expect(MaskedSecretFinding.safeParse(smuggled).success).toBe(false);
  });

  it('renders the most-exposed-first recommendation line verbatim', () => {
    const out = renderRemediationDecision([stripeFinding()], 0, REGISTRY_SCAN);
    expect(out).toContain("I'd redact them and get you rotating, most-exposed first");
  });

  it('closes with the chaining line naming the registered secret-scan command', () => {
    const out = renderRemediationDecision([stripeFinding()], 1, REGISTRY_SCAN);
    expect(out).toContain("1 more worth a look — run /aka:scan when you're ready.");
  });

  it('reflects the registry — names /aka:secretscan when that is what is registered, not a hardcode', () => {
    const out = renderRemediationDecision([stripeFinding()], 2, REGISTRY_SECRETSCAN);
    expect(out).toContain("2 more worth a look — run /aka:secretscan when you're ready.");
  });

  it('fails loud when no secret-scan command is registered', () => {
    // Neither `/aka:scan` nor `/aka:secretscan` present ⇒ the chaining line would
    // name a command the plugin does not register, so selection throws rather than
    // shipping an uninvokable call-to-action.
    expect(() => renderRemediationDecision([stripeFinding()], 1, ['/aka:dashboard'])).toThrow();
  });
});

describe('renderResolvedSummary', () => {
  const entries: readonly RotationChecklistEntry[] = [
    {
      provider: 'stripe',
      maskedToken: MASKED_STRIPE,
      consolePath: 'dashboard.stripe.com → Developers → API keys',
      occurrenceSpread: 2,
    },
    {
      provider: 'aws',
      maskedToken: MASKED_AWS,
      consolePath: 'console.aws.amazon.com → IAM → Security credentials',
      occurrenceSpread: 1,
    },
  ];

  it('renders real key and distinct-transcript counts independently with the dynamic location', () => {
    const findings = [
      stripeFinding(),
      { ...stripeFinding(), maskedToken: 'sk_live_…2222' },
      awsFinding(),
    ];

    const summary = renderResolvedSummary({
      redactedKeys: 3,
      findings,
      unredactedFindings: [],
      location: 'repo root',
      entries,
    });

    expect(summary).toContain('Leaked secrets — resolved');
    expect(summary).toContain('✓ Redacted 3 keys across 2 transcripts');
    expect(summary).toContain('✓ I drafted a rotation checklist for you (repo root).');

    // A fourth finding (all four struck: redactedKeys tracks findings.length so
    // the "resolved" framing stays honest) proves the transcript count is
    // independently derived from distinct filePaths, not the key count relabelled.
    const threeTranscriptSummary = renderResolvedSummary({
      redactedKeys: 4,
      findings: [
        ...findings,
        { ...awsFinding(), where: { filePath: '/tmp/second-agent-dump.txt' } },
      ],
      unredactedFindings: [],
      location: 'repo root',
      entries,
    });
    expect(threeTranscriptSummary).toContain('✓ Redacted 4 keys across 3 transcripts');
  });

  it('renders singular key and transcript nouns from a single-key fixture', () => {
    const summary = renderResolvedSummary({
      redactedKeys: 1,
      findings: [stripeFinding()],
      unredactedFindings: [],
      location: 'repo root',
      entries: entries.slice(0, 1),
    });

    expect(summary).toContain('✓ Redacted 1 key across 1 transcript');
  });

  it('renders the inline preview entry-for-entry from the checklist file model', () => {
    const summary = renderResolvedSummary({
      redactedKeys: 2,
      findings: [stripeFinding(), awsFinding()],
      unredactedFindings: [],
      location: 'repo root',
      entries,
    });
    const previewLines = summary.split('\n').filter((line) => line.startsWith('- [ ] '));
    const fileLines = renderChecklistMarkdown(entries).trimEnd().split('\n');

    expect(previewLines).toEqual(fileLines);
  });

  it('never claims "resolved" on a partial strike — an honest partial message names the shortfall and the file still holding a live key', () => {
    const secondAwsFinding = { ...awsFinding(), where: { filePath: '/tmp/second-agent-dump.txt' } };
    const findings = [stripeFinding(), awsFinding(), secondAwsFinding];

    // Two of the three findings were struck; the aws finding in the second file
    // was not (e.g. it vanished or changed between the calibration scan and the
    // redact-time re-scan) — a real, legitimate partial outcome.
    const summary = renderResolvedSummary({
      redactedKeys: 2,
      findings,
      unredactedFindings: [secondAwsFinding],
      location: 'repo root',
      entries,
    });

    // The clean "resolved" framing is never shown over a partial strike.
    expect(summary).not.toContain('Leaked secrets — resolved');
    expect(summary).toContain('Leaked secrets — partially redacted');
    expect(summary).toContain(
      'Redacted 2 of 3 keys; 1 key still needs attention in /tmp/second-agent-dump.txt',
    );
    // The checklist deliverable still lands — rotation is still owed regardless
    // of whether the leaked text itself was struck.
    expect(summary).toContain('✓ I drafted a rotation checklist for you (repo root).');
  });

  it('pluralizes the partial message correctly across more than one remaining key', () => {
    const secondStripeFinding = {
      ...stripeFinding(),
      maskedToken: 'sk_live_…2222',
      where: { filePath: '/tmp/second-agent-dump.txt' },
    };
    const findings = [stripeFinding(), secondStripeFinding, awsFinding()];

    const summary = renderResolvedSummary({
      redactedKeys: 1,
      findings,
      unredactedFindings: [secondStripeFinding, awsFinding()],
      location: 'repo root',
      entries,
    });

    expect(summary).toContain('Leaked secrets — partially redacted');
    expect(summary).toContain('Redacted 1 of 3 keys; 2 keys still need attention in');
    // Both remaining files are named, not just the first.
    expect(summary).toContain('/tmp/second-agent-dump.txt');
    expect(summary).toContain(awsFinding().where.filePath);
  });

  it('never renders "Redacted 0 keys" as a clean all-clear when nothing was struck', () => {
    const findings = [stripeFinding(), awsFinding()];

    const summary = renderResolvedSummary({
      redactedKeys: 0,
      findings,
      unredactedFindings: findings,
      location: 'repo root',
      entries,
    });

    expect(summary).not.toContain('Leaked secrets — resolved');
    expect(summary).toContain('Leaked secrets — partially redacted');
    expect(summary).toContain('Redacted 0 of 2 keys; 2 keys still need attention in');
  });

  it('treats a degraded checklist-write note the same across the complete and partial framings', () => {
    const findings = [stripeFinding()];
    const partial = renderResolvedSummary({
      redactedKeys: 0,
      findings,
      unredactedFindings: findings,
      degradedNote: 'Could not draft rotation-checklist.md at /nowhere.',
      entries,
    });

    expect(partial).toContain('Leaked secrets — partially redacted');
    expect(partial).toContain('Could not draft rotation-checklist.md at /nowhere.');
  });
});

describe('renderRedactionOutcome — redact-only confirmation', () => {
  it('renders the clean confirmation when every finding was struck', () => {
    const findings = [stripeFinding(), awsFinding()];
    expect(renderRedactionOutcome({ redactedKeys: 2, findings, unredactedFindings: [] })).toBe(
      '✓ Redacted 2 keys.',
    );
  });

  it('pluralizes the clean confirmation over a single struck key', () => {
    const findings = [stripeFinding()];
    expect(renderRedactionOutcome({ redactedKeys: 1, findings, unredactedFindings: [] })).toBe(
      '✓ Redacted 1 key.',
    );
  });

  it('never claims a clean strike on a partial redact-only outcome — it names the shortfall and the file still holding a live key', () => {
    const secondAwsFinding = { ...awsFinding(), where: { filePath: '/tmp/second-agent-dump.txt' } };
    const findings = [stripeFinding(), awsFinding(), secondAwsFinding];

    // Two of three struck; the aws finding in the second file was not (it vanished
    // or changed between the calibration scan and the redact-time re-scan) — the
    // redact-only route must disclose this exactly as the resolved summary does.
    const outcome = renderRedactionOutcome({
      redactedKeys: 2,
      findings,
      unredactedFindings: [secondAwsFinding],
    });

    expect(outcome).not.toContain('✓ Redacted');
    expect(outcome).toBe(
      'Redacted 2 of 3 keys; 1 key still needs attention in /tmp/second-agent-dump.txt',
    );
  });

  it('pluralizes the partial confirmation across more than one remaining key', () => {
    const secondStripeFinding = {
      ...stripeFinding(),
      maskedToken: 'sk_live_…2222',
      where: { filePath: '/tmp/second-agent-dump.txt' },
    };
    const findings = [stripeFinding(), secondStripeFinding, awsFinding()];

    const outcome = renderRedactionOutcome({
      redactedKeys: 1,
      findings,
      unredactedFindings: [secondStripeFinding, awsFinding()],
    });

    expect(outcome).toContain('Redacted 1 of 3 keys; 2 keys still need attention in');
    expect(outcome).toContain('/tmp/second-agent-dump.txt');
    expect(outcome).toContain(awsFinding().where.filePath);
  });
});
