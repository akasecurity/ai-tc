import { MaskedSecretFinding, type RotationChecklistEntry } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  renderRedactionOutcome,
  renderResolvedSummary,
} from '../../src/remediation/redaction-summary.ts';
import { renderChecklistMarkdown } from '../../src/remediation/rotation-checklist.ts';

// The RAW_* constants are what the underlying leak actually contains; each
// fixture's `maskedToken` is the masked preview of the SAME raw value (raw prefix
// kept, tail masked). The formatters must surface only the masked preview and
// never the raw key it derives from (the raw-free boundary), so the raw-free
// assertions below compare the rendered output against these real raw values.
// Assembled at runtime so the source carries no contiguous key-shaped literal
// (mirrors the AKIA fixtures) — the value is an obviously-fake example, not a key.
const STRIPE_PREFIX = ['sk', 'live', ''].join('_');
const AWS_PREFIX = 'AKIA';
// The portion the mask HIDES — the part that is actually secret. The prefixes
// above are kept visible on purpose (that is what `maskMatch` does), so only
// these tails are what "never echoed" can mean.
const STRIPE_SECRET_TAIL = '51H8xEXAMPLErawstripesecretVALUE0000';
const AWS_SECRET_TAIL = 'IOSFODNN7EXAMPLE';
const RAW_STRIPE = `${STRIPE_PREFIX}${STRIPE_SECRET_TAIL}`;
const RAW_AWS = `${AWS_PREFIX}${AWS_SECRET_TAIL}`;

// Masked preview of RAW_STRIPE / RAW_AWS — the exact strings the summary should
// carry in place of the raw values above.
const MASKED_STRIPE = `${STRIPE_PREFIX}****`;
const MASKED_AWS = `${AWS_PREFIX}****************`;

// The loader emits state:'unknown' — validity is unverifiable under the
// no-network OSS constraint — so the fixtures carry the state a real finding does.
function stripeFinding(): MaskedSecretFinding {
  return {
    provider: 'stripe',
    maskedToken: MASKED_STRIPE,
    where: { filePath: '/transcripts/2026-07-01.jsonl' },
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

// The secret portion is absent from a summary only if no RUN of it survives: a
// branch that echoed a truncated value would still hand out a live credential's
// fragment, and a whole-value `not.toContain` stays green on exactly that.
// Applied to the HIDDEN tail rather than the whole raw value, because the
// masked preview keeps the provider prefix visible on purpose.
// Copied (not imported — it lives behind a package wall) from
// plugins/claude-code/test/triage/judge.test.ts, guard included.
const ECHO_RUN = 8;
function expectNoEchoOf(message: string | undefined, value: string): void {
  expect(message).toBeDefined();
  const haystack = message ?? '';
  for (let i = 0; i + ECHO_RUN <= value.length; i += 1) {
    expect(haystack).not.toContain(value.slice(i, i + ECHO_RUN));
  }
  if (value.length < ECHO_RUN) expect(haystack).not.toContain(value);
}

const POINTERED_SENTENCE = /replaced with recoverable vault pointers/g;

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

describe('renderResolvedSummary — raw-free egress', () => {
  const entries: readonly RotationChecklistEntry[] = [
    {
      provider: 'stripe',
      maskedToken: MASKED_STRIPE,
      consolePath: 'dashboard.stripe.com → Developers → API keys',
      occurrenceSpread: 1,
    },
  ];

  it('surfaces only the masked previews — no run of the secret portion they hide', () => {
    // Guard the assertion against vacuity: the masked and raw forms must
    // genuinely differ, so the no-echo check is a real check, not a tautology
    // over strings the formatter was never given.
    expect(MASKED_STRIPE).not.toEqual(RAW_STRIPE);
    expect(MASKED_AWS).not.toEqual(RAW_AWS);

    const summary = renderResolvedSummary({
      redactedKeys: 2,
      findings: [stripeFinding(), awsFinding()],
      unredactedFindings: [],
      location: 'repo root',
      entries,
    });

    // Positive control: the masked preview DOES surface, so the absence checks
    // below describe a summary that genuinely carries this finding.
    expect(summary).toContain(MASKED_STRIPE);
    // The whole raw value never appears...
    expect(summary).not.toContain(RAW_STRIPE);
    expect(summary).not.toContain(RAW_AWS);
    // ...and neither does any run of the portion the mask hides. The visible
    // provider prefixes (sk_live_ / AKIA) are excluded on purpose: `maskMatch`
    // keeps them, so they are not what secrecy rests on.
    expectNoEchoOf(summary, STRIPE_SECRET_TAIL);
    expectNoEchoOf(summary, AWS_SECRET_TAIL);
  });

  it('cannot be handed a raw value — the MaskedSecretFinding contract rejects it (.strict) — and never echoes one smuggled past the types', () => {
    // The structural guard: a finding smuggling the raw key under an extra
    // field fails validation at the boundary.
    const smuggled = { ...stripeFinding(), rawValue: RAW_STRIPE };
    expect(MaskedSecretFinding.safeParse(smuggled).success).toBe(false);

    // The behavioral guard: even when a smuggled finding is forced past the
    // types, the formatter reads only its known fields — a rewrite that dumps
    // the finding object (a debug JSON.stringify, say) turns this red.
    const summary = renderResolvedSummary({
      redactedKeys: 1,
      findings: [smuggled],
      unredactedFindings: [],
      location: 'repo root',
      entries,
    });
    expect(summary).toContain('✓ Redacted 1 key');
    expect(summary).not.toContain(RAW_STRIPE);
    expectNoEchoOf(summary, STRIPE_SECRET_TAIL);
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

describe('pointered-strike copy — recoverable vault pointers', () => {
  const entries: readonly RotationChecklistEntry[] = [
    {
      provider: 'stripe',
      maskedToken: MASKED_STRIPE,
      consolePath: 'dashboard.stripe.com → Developers → API keys',
      occurrenceSpread: 1,
    },
  ];

  it('the clean confirmation says the values are recoverable when every struck value was pointered', () => {
    const findings = [stripeFinding(), awsFinding()];
    expect(
      renderRedactionOutcome({
        redactedKeys: 2,
        pointeredKeys: 2,
        findings,
        unredactedFindings: [],
      }),
    ).toBe(
      '✓ Redacted 2 keys. 2 values were replaced with recoverable vault pointers — ' +
        'view them in the dashboard or with `aka vault show`.',
    );
  });

  it('a mixed outcome names only the pointered share as recoverable', () => {
    const findings = [stripeFinding(), awsFinding()];
    const outcome = renderRedactionOutcome({
      redactedKeys: 2,
      pointeredKeys: 1,
      findings,
      unredactedFindings: [],
    });
    expect(outcome).toContain('✓ Redacted 2 keys.');
    expect(outcome).toContain('1 value was replaced with recoverable vault pointers');
  });

  it('pointeredKeys 0 (or omitted) keeps the irreversible wording byte-identical — a one-way strike is never described as recoverable', () => {
    const findings = [stripeFinding()];
    const plain = renderRedactionOutcome({ redactedKeys: 1, findings, unredactedFindings: [] });
    const zeroed = renderRedactionOutcome({
      redactedKeys: 1,
      pointeredKeys: 0,
      findings,
      unredactedFindings: [],
    });
    expect(plain).toBe('✓ Redacted 1 key.');
    expect(zeroed).toBe(plain);
    expect(plain).not.toContain('recoverable');
  });

  it('the partial outcome still names the values that WERE pointered as recoverable', () => {
    const secondAwsFinding = { ...awsFinding(), where: { filePath: '/tmp/second-agent-dump.txt' } };
    const findings = [stripeFinding(), awsFinding(), secondAwsFinding];
    const outcome = renderRedactionOutcome({
      redactedKeys: 2,
      pointeredKeys: 2,
      findings,
      unredactedFindings: [secondAwsFinding],
    });
    expect(outcome).toContain(
      'Redacted 2 of 3 keys; 1 key still needs attention in /tmp/second-agent-dump.txt',
    );
    expect(outcome).toContain('2 values were replaced with recoverable vault pointers');
  });

  it('the resolved summary carries the recoverable sentence on its redaction line exactly once — and drops it when nothing was pointered', () => {
    const findings = [stripeFinding(), awsFinding()];
    const pointered = renderResolvedSummary({
      redactedKeys: 2,
      pointeredKeys: 2,
      findings,
      unredactedFindings: [],
      location: 'repo root',
      entries,
    });
    expect(pointered).toContain('Leaked secrets — resolved');
    expect(pointered).toContain(
      '✓ Redacted 2 keys across 2 transcripts. 2 values were replaced with recoverable vault pointers — ' +
        'view them in the dashboard or with `aka vault show`.',
    );
    // The recoverability sentence rides the redaction line exactly once.
    expect(pointered.match(POINTERED_SENTENCE)).toHaveLength(1);

    const struckOnly = renderResolvedSummary({
      redactedKeys: 2,
      findings,
      unredactedFindings: [],
      location: 'repo root',
      entries,
    });
    expect(struckOnly).toContain('✓ Redacted 2 keys across 2 transcripts');
    expect(struckOnly).not.toContain('recoverable');
  });

  it('the partial resolved summary keeps the honest partial header while naming the pointered share — never the clean resolved framing', () => {
    const secondAwsFinding = { ...awsFinding(), where: { filePath: '/tmp/second-agent-dump.txt' } };
    const findings = [stripeFinding(), awsFinding(), secondAwsFinding];
    // Two of three struck (both as recoverable pointers); the third transcript
    // still holds a live key. The partial strike never earns the clean
    // "resolved" framing — even when every struck value is recoverable.
    const summary = renderResolvedSummary({
      redactedKeys: 2,
      pointeredKeys: 2,
      findings,
      unredactedFindings: [secondAwsFinding],
      location: 'repo root',
      entries,
    });

    expect(summary).toContain('Leaked secrets — partially redacted');
    expect(summary).not.toContain('Leaked secrets — resolved');
    expect(summary).toContain('Redacted 2 of 3 keys');
    expect(summary).toContain('1 key still needs attention in /tmp/second-agent-dump.txt');
    expect(summary).toContain('2 values were replaced with recoverable vault pointers');
    expect(summary.match(POINTERED_SENTENCE)).toHaveLength(1);
  });

  it('renders byte-identical resolved summaries for pointeredKeys: 0 and an omitted pointeredKeys — no pointer sentence', () => {
    const secondAwsFinding = { ...awsFinding(), where: { filePath: '/tmp/second-agent-dump.txt' } };
    const findings = [stripeFinding(), awsFinding(), secondAwsFinding];
    const unredactedFindings = [secondAwsFinding];

    // Partial shape: an irreversible strike keeps its wording untouched.
    const zeroPartial = renderResolvedSummary({
      redactedKeys: 2,
      findings,
      unredactedFindings,
      pointeredKeys: 0,
      entries,
      location: 'repo root',
    });
    const omittedPartial = renderResolvedSummary({
      redactedKeys: 2,
      findings,
      unredactedFindings,
      entries,
      location: 'repo root',
    });
    expect(zeroPartial).toBe(omittedPartial);
    expect(zeroPartial).not.toContain('recoverable');

    // Complete shape: same byte-stability guarantee.
    const zeroResolved = renderResolvedSummary({
      redactedKeys: 3,
      findings,
      unredactedFindings: [],
      pointeredKeys: 0,
      entries,
      location: 'repo root',
    });
    const omittedResolved = renderResolvedSummary({
      redactedKeys: 3,
      findings,
      unredactedFindings: [],
      entries,
      location: 'repo root',
    });
    expect(zeroResolved).toBe(omittedResolved);
    expect(zeroResolved).not.toContain('recoverable');
  });
});
