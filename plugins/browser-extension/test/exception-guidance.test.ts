// The pure exception-guidance builders. Sibling of plugins/{claude-code,codex,
// antigravity}/test/exception-guidance.test.ts, with one deliberate difference:
// those build TERMINAL text and join it, while this returns the parts
// separately so the banner can render the command as its own selectable
// element. A reference the user cannot select is a reference they cannot use.
import type { BlockedDetectionRef } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import { blockGuidance, exceptionPointer } from '../src/exception-guidance.ts';

function ref(reference: string, maskedValue = 'A******E'): BlockedDetectionRef {
  return { reference, ruleId: 'secrets/aws-access-key', maskedValue };
}

describe('blockGuidance', () => {
  it('names the rules, the masked preview, and the copy-paste-complete command', () => {
    const g = blockGuidance({ ruleIds: 'secrets/aws-access-key', blockedRef: ref('3f2a91') });

    expect(g.headline).toContain('secrets/aws-access-key');
    expect(g.headline).toContain('A******E');
    expect(g.command).toBe('aka exception approve 3f2a91');
    expect(g.help).toContain('aka exception --help');
  });

  it('puts removal before the exception — the escape hatch is offered, never promoted', () => {
    // The sibling modules state this as their governing rule. Asserted on
    // ORDER rather than presence: copy that leads with "grant an exception"
    // teaches the reader to reach for the bypass first.
    const g = blockGuidance({ ruleIds: 'secrets/aws-access-key', blockedRef: ref('3f2a91') });
    expect(g.advice.toLowerCase()).toContain('remove');
    const joined = [g.headline, g.advice, g.approveIntro, g.command].join(' | ');
    expect(joined.indexOf('emove')).toBeLessThan(joined.indexOf('exception'));
  });

  it('degrades to the bare command when no ledger row was recorded', () => {
    // Without a reference `approve <ref>` would resolve against nothing. The
    // bare form lists recent blocks to pick from instead, so the user is never
    // handed a command that cannot work.
    const g = blockGuidance({ ruleIds: 'secrets/aws-access-key', blockedRef: undefined });
    expect(g.command).toBe('aka exception approve');
    expect(g.headline).not.toContain('undefined');
  });

  it('shows no preview when there is no ledger row to take one from', () => {
    // Preview and reference come from the SAME row, so a preview without a
    // reference could describe a different value than the command resolves.
    const g = blockGuidance({ ruleIds: 'secrets/aws-access-key', blockedRef: undefined });
    expect(g.headline).not.toContain('(');
  });

  it('joins multiple rule ids as given', () => {
    const g = blockGuidance({
      ruleIds: 'secrets/aws-access-key, secrets-infra/jwt-token',
      blockedRef: ref('7c1d'),
    });
    expect(g.headline).toContain('secrets-infra/jwt-token');
  });
});

describe('exceptionPointer', () => {
  it('names the reference for a redact that was ledgered', () => {
    expect(exceptionPointer([ref('9b8a')])).toContain('aka exception approve 9b8a');
  });

  it('is empty when nothing was ledgered, so no unusable command is offered', () => {
    expect(exceptionPointer([])).toBe('');
    expect(exceptionPointer(undefined)).toBe('');
  });
});
