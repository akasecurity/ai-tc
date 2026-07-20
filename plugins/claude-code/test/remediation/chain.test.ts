import type {
  BatchedRemediation,
  BatchedRemediationDecision,
  MaskedSecretFinding,
  RemediationEntryContext,
} from '@akasecurity/schema';
import { describe, expect, it, vi } from 'vitest';

import type { RemediationHandlers } from '../../src/remediation/chain.ts';
import { presentBatchedRemediation, routeRemediationOption } from '../../src/remediation/chain.ts';

const FIRST_RUN: RemediationEntryContext = { entrySource: 'first-run' };

// A surfaced secret-leak finding — the raw-free MaskedSecretFinding[] the loader
// reads from the calibration frame. It is secret-only by construction (customer-
// data / PII never takes this shape), so the exclusion of customer-data / PII findings
// is a type-level guarantee and is proven at the derivation seam
// (test/triage/surfaced-secrets.test.ts), not by a runtime filter here.
function secretFinding(n: number): MaskedSecretFinding {
  return {
    provider: 'aws',
    maskedToken: `AKIA***************${n.toString()}`,
    where: { filePath: `~/.claude/transcripts/2026-07-0${n.toString()}.jsonl` },
    state: 'unknown',
  };
}

function asDecision(result: BatchedRemediation): BatchedRemediationDecision {
  if (result.kind !== 'decision') {
    throw new Error(`expected a decision, got '${result.kind}'`);
  }
  return result;
}

// Every user-facing string the core emits for a decision: the count prompt
// plus each option label.
function emittedStrings(decision: BatchedRemediationDecision): string[] {
  return [decision.prompt, ...decision.options.map((o) => o.label)];
}

describe('presentBatchedRemediation', () => {
  it('presents ALL same-type secret findings as ONE decision', () => {
    const decision = asDecision(
      presentBatchedRemediation([secretFinding(1), secretFinding(2), secretFinding(3)], FIRST_RUN),
    );
    // One decision moment for the whole set — not one per finding.
    expect(decision.kind).toBe('decision');
    expect(decision.secretCount).toBe(3);
  });

  it('templates the count over the real findings, never hardcoded', () => {
    const three = asDecision(
      presentBatchedRemediation([secretFinding(1), secretFinding(2), secretFinding(3)], FIRST_RUN),
    );
    expect(three.secretCount).toBe(3);
    expect(three.prompt).toContain('3');

    // Change the input to 2 findings ⇒ the count follows, proving no hardcode.
    const two = asDecision(
      presentBatchedRemediation([secretFinding(1), secretFinding(2)], FIRST_RUN),
    );
    expect(two.secretCount).toBe(2);
    expect(two.prompt).toContain('2');
    expect(two.prompt).not.toContain('3');
  });

  it('does not assert the unverifiable "still valid" claim in the count copy', () => {
    // The no-network OSS product cannot authenticate a leaked key, so the loader
    // emits findings with state:'unknown'. The count copy must not claim a
    // validity the product never verified — it states only the honest fact.
    const decision = asDecision(
      presentBatchedRemediation([secretFinding(1), secretFinding(2), secretFinding(3)], FIRST_RUN),
    );
    expect(decision.prompt.toLowerCase()).not.toContain('still valid');
    // No status word either: the finding's status is what the data holds (unknown),
    // rendered per-row — the count copy states only the count and where.
    expect(decision.prompt.toLowerCase()).not.toContain('live');
    expect(decision.prompt).toContain('3 exposed secret keys found in old transcripts');
  });

  it("never emits the word 'case' in user-facing copy", () => {
    const decision = asDecision(
      presentBatchedRemediation([secretFinding(1), secretFinding(2)], FIRST_RUN),
    );
    for (const s of emittedStrings(decision)) {
      expect(s.toLowerCase()).not.toContain('case');
    }
  });

  it('offers EXACTLY the four options in stable order', () => {
    const decision = asDecision(
      presentBatchedRemediation([secretFinding(1), secretFinding(2), secretFinding(3)], FIRST_RUN),
    );
    expect(decision.options.map((o) => o.id)).toEqual([
      'redact-rotation-checklist',
      'redact-only',
      'set-secret-redact',
      'leave',
    ]);
    expect(decision.options.map((o) => o.label)).toEqual([
      'Redact + rotation checklist',
      'Redact only',
      "Set 'secret' to redact",
      'Leave',
    ]);
  });

  it('echoes each entry source through the decision — entry-point-agnostic', () => {
    // A direct caller supplies the same findings shape a first-run entry does,
    // tagged with where it entered from. Every entry source round-trips onto the
    // decision unchanged, so a pre-push or secret-scan caller is a first-class
    // entry, not a special case of the first-run one.
    for (const entrySource of ['first-run', 'pre-push', 'secret-scan'] as const) {
      const decision = asDecision(
        presentBatchedRemediation([secretFinding(1), secretFinding(2)], { entrySource }),
      );
      expect(decision.entrySource).toBe(entrySource);
    }
  });

  it('degrades honestly on an empty (zero-result) secret set', () => {
    // A successful read that returned no findings — distinct from a read throw.
    const result = presentBatchedRemediation([], FIRST_RUN);
    expect(result.kind).toBe('no-decision');
    // No fabricated count and no decision presented as if findings had surfaced.
    expect(result).not.toHaveProperty('secretCount');
    expect(result).not.toHaveProperty('options');
    expect(result).not.toHaveProperty('prompt');
  });
});

// The injected side-effecting capabilities the router dispatches to, each a spy so
// a test asserts exactly which capability the router invoked for a chosen option —
// and, as important, which it left untouched. The real closures (redaction over the
// findings' recovered raw values within the transcript/temp scope; the standing
// 'secret'→Redact posture write) are bound at the IO boundary, proven in their own
// suites (redact.test.ts, posture.test.ts) — here they are stubbed.
function fakeHandlers(redactedKeys = 2): RemediationHandlers & {
  redact: ReturnType<typeof vi.fn>;
  setStandingRedactPosture: ReturnType<typeof vi.fn>;
} {
  return {
    redact: vi.fn(() => redactedKeys),
    setStandingRedactPosture: vi.fn(() => ({ persisted: true, level: 'redact' as const })),
  };
}

describe('routeRemediationOption — non-spine option routing', () => {
  it("'Redact only' routes through the redaction mechanism and generates NO deliverable", () => {
    const handlers = fakeHandlers(3);
    const outcome = routeRemediationOption('redact-only', handlers);

    // It redacts, via the injected redaction mechanism...
    expect(handlers.redact).toHaveBeenCalledTimes(1);
    expect(outcome).toEqual({ kind: 'redacted', withRotationChecklist: false, redactedKeys: 3 });
    // ...and does nothing more: no posture written.
    expect(handlers.setStandingRedactPosture).not.toHaveBeenCalled();
  });

  it("'Leave' exits cleanly with ZERO side effects", () => {
    const handlers = fakeHandlers();
    const outcome = routeRemediationOption('leave', handlers);

    // No redaction, no posture write, no deliverable — a clean exit that leaves the
    // store, settings, and working tree untouched.
    expect(handlers.redact).not.toHaveBeenCalled();
    expect(handlers.setStandingRedactPosture).not.toHaveBeenCalled();
    expect(outcome).toEqual({ kind: 'left' });
  });

  it("'Set secret to redact' dispatches to the standing-posture write, not redaction", () => {
    const handlers = fakeHandlers();
    const outcome = routeRemediationOption('set-secret-redact', handlers);

    expect(handlers.setStandingRedactPosture).toHaveBeenCalledTimes(1);
    expect(handlers.redact).not.toHaveBeenCalled();
    expect(outcome).toEqual({ kind: 'posture-set', posture: { persisted: true, level: 'redact' } });
  });

  it("'Redact + rotation checklist' routes through the SAME redaction mechanism, deliverable deferred", () => {
    const handlers = fakeHandlers(4);
    const outcome = routeRemediationOption('redact-rotation-checklist', handlers);

    // The same redaction path as 'Redact only'...
    expect(handlers.redact).toHaveBeenCalledTimes(1);
    expect(handlers.setStandingRedactPosture).not.toHaveBeenCalled();
    // ...recording that a rotation checklist was requested, while the deliverable
    // itself is not generated here.
    expect(outcome).toEqual({ kind: 'redacted', withRotationChecklist: true, redactedKeys: 4 });
  });

  it('dispatches each option id to its correct branch and only that branch', () => {
    const cases = [
      { id: 'redact-only', redact: 1, posture: 0 },
      { id: 'redact-rotation-checklist', redact: 1, posture: 0 },
      { id: 'set-secret-redact', redact: 0, posture: 1 },
      { id: 'leave', redact: 0, posture: 0 },
    ] as const;
    for (const c of cases) {
      const handlers = fakeHandlers();
      routeRemediationOption(c.id, handlers);
      expect(handlers.redact.mock.calls.length, `${c.id} redact calls`).toBe(c.redact);
      expect(handlers.setStandingRedactPosture.mock.calls.length, `${c.id} posture calls`).toBe(
        c.posture,
      );
    }
  });
});
