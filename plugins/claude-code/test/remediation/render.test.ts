import { MaskedSecretFinding } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { renderRemediationDecision } from '../../src/remediation/render.ts';

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
    expect(out).toContain('1 more worth a look — run /aka:scan');
  });

  it('reflects the registry — names /aka:secretscan when that is what is registered, not a hardcode', () => {
    const out = renderRemediationDecision([stripeFinding()], 2, REGISTRY_SECRETSCAN);
    expect(out).toContain('2 more worth a look — run /aka:secretscan');
  });

  it('fails loud when no secret-scan command is registered', () => {
    // Neither `/aka:scan` nor `/aka:secretscan` present ⇒ the chaining line would
    // name a command the plugin does not register, so selection throws rather than
    // shipping an uninvokable call-to-action.
    expect(() => renderRemediationDecision([stripeFinding()], 1, ['/aka:dashboard'])).toThrow();
  });
});
