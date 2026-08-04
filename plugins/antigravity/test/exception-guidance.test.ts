// Tests the pure exception-guidance builders directly — NEVER via the hook
// entry files (src/hooks/*.ts run main() on import and hang vitest collection).
// Identical to plugins/claude-code/src/exception-guidance.test.ts — the
// messaging is host-agnostic.
import type { BlockedDetectionRef } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import {
  blockMessage,
  exceptionPointer,
  withheldBanner,
  withheldToolText,
} from '../src/exception-guidance.ts';

function ref(reference: string, maskedValue = 'F******E'): BlockedDetectionRef {
  return { reference, ruleId: 'secrets/aws-access-key', maskedValue };
}

describe('blockMessage', () => {
  it('block with a reference: copy-paste-complete approve command, masked preview, ≤ 5 lines', () => {
    const out = blockMessage({
      subject: 'prompt',
      ruleIds: 'secrets/aws-access-key',
      blockedRef: ref('3f2a91'),
    });
    const lines = out.split('\n');
    expect(lines.length).toBeLessThanOrEqual(5);
    expect(lines[0]).toContain('AKA blocked this prompt — flagged secrets/aws-access-key');
    expect(lines[0]).toContain('Remove the flagged content and resubmit.');
    expect(lines[0]).toContain('(F******E)');
    expect(out).toContain('If this is intentional and you accept the risk, grant an exception:');
    expect(out).toContain('aka exception approve 3f2a91');
    expect(out).toContain('(asks for scope + reason, then resubmit)');
    expect(out).toContain('aka exception approve <value>');
    expect(out).toContain('More: aka exception --help');
  });

  it('weaves an optional note between the flag preview and the removal advice', () => {
    const out = blockMessage({
      subject: 'Bash call',
      ruleIds: 'core-pii/ip-address',
      blockedRef: ref('3f2a91', '4******6'),
      note: 'Masking inside an executable command would silently change what runs, so a redact policy blocks it instead.',
    });
    const lines = out.split('\n');
    expect(lines.length).toBeLessThanOrEqual(5);
    expect(lines[0]).toBe(
      'AKA blocked this Bash call — flagged core-pii/ip-address (4******6). ' +
        'Masking inside an executable command would silently change what runs, so a redact policy blocks it instead. ' +
        'Remove the flagged content and resubmit.',
    );
  });

  it('block without a reference: the approve command degrades to its bare form', () => {
    const out = blockMessage({
      subject: 'Bash call',
      ruleIds: 'secrets/aws-access-key, core-pii/email',
    });
    expect(out).toContain(
      'AKA blocked this Bash call — flagged secrets/aws-access-key, core-pii/email.',
    );
    expect(out).toContain('  aka exception approve       ');
    expect(out).not.toMatch(/aka exception approve [0-9a-f]/);
    expect(out).not.toContain('<value>');
    expect(out.split('\n')[0]).not.toContain('(');
  });
});

describe('exceptionPointer', () => {
  it('points at the approve command when a reference exists', () => {
    const out = exceptionPointer([ref('9c04d7'), ref('3f2a91')]);
    expect(out).toBe(
      ' To allow this exact value intentionally, run: aka exception approve 9c04d7.',
    );
  });

  it('is empty when nothing was ledgered', () => {
    expect(exceptionPointer(undefined)).toBe('');
    expect(exceptionPointer([])).toBe('');
  });
});

describe('withheldBanner', () => {
  it('renders a shade-glyph banner with rule, masked preview, and approve command', () => {
    const out = withheldBanner({
      toolName: 'Bash',
      action: 'withheld',
      withheldRuleIds: 'secrets/aws-access-key',
      blockedRef: ref('3f2a91'),
    });
    const lines = out.split('\n');
    expect(lines.length).toBeLessThanOrEqual(5);
    expect(lines[0]).toContain('█▓▒░ AKA ░▒▓█');
    expect(lines[0]).toContain('Bash output withheld');
    for (const line of lines.slice(1)) expect(line.startsWith('█')).toBe(true);
    expect(out).toContain('Withheld: secrets/aws-access-key');
    expect(out).toContain('(F******E) intentionally: aka exception approve 3f2a91');
    expect(out).toContain('never reached the model');
  });

  it('redacted variant names the action and keeps the approve pointer', () => {
    const out = withheldBanner({
      toolName: 'Bash',
      action: 'redacted',
      redactedRuleIds: 'core-pii/email',
      blockedRef: ref('9c04d7', 'j***@e******.com'),
    });
    expect(out.split('\n')[0]).toContain('Bash output redacted');
    expect(out).toContain('Redacted: core-pii/email');
    expect(out).toContain('(j***@e******.com) intentionally: aka exception approve 9c04d7');
  });

  it('degrades to the bare approve command without a ledger reference', () => {
    const out = withheldBanner({
      toolName: 'Bash',
      action: 'withheld',
      withheldRuleIds: 'secrets/aws-access-key',
    });
    expect(out).toContain('aka exception approve\n');
    expect(out).not.toContain('(F');
  });

  it('splits mixed outcomes into separate Withheld/Redacted lines', () => {
    const out = withheldBanner({
      toolName: 'Bash',
      action: 'withheld',
      withheldRuleIds: 'secrets/aws-access-key',
      redactedRuleIds: 'core-pii/email',
      blockedRef: ref('3f2a91'),
    });
    const lines = out.split('\n');
    expect(lines.length).toBeLessThanOrEqual(6);
    expect(lines.some((line) => line.includes('Withheld: secrets/aws-access-key'))).toBe(true);
    expect(lines.some((line) => line.includes('Redacted: core-pii/email'))).toBe(true);
  });

  it('surfaces warn-action rules from other fields on their own line', () => {
    const out = withheldBanner({
      toolName: 'Bash',
      action: 'withheld',
      withheldRuleIds: 'secrets/aws-access-key',
      blockedRef: ref('3f2a91'),
      warnedRuleIds: 'core-pii/email',
    });
    const lines = out.split('\n');
    expect(lines.length).toBeLessThanOrEqual(6);
    expect(out).toContain('Also flagged (warn): core-pii/email');
    const warnIndex = lines.findIndex((line) => line.includes('Also flagged'));
    const claimIndex = lines.findIndex((line) => line.includes('never reached the model'));
    expect(warnIndex).toBeGreaterThan(-1);
    expect(claimIndex).toBeGreaterThan(warnIndex);
  });
});

describe('withheldToolText', () => {
  it('tells the model what happened and to inform the user, without the approve command', () => {
    const out = withheldToolText('Bash', 'secrets/aws-access-key');
    expect(out).toContain('[AKA SECURITY]');
    expect(out).toContain('Bash output withheld');
    expect(out).toContain('secrets/aws-access-key');
    expect(out).toContain('not added to your context');
    expect(out).toContain('Do not attempt to obtain the withheld content through other channels');
    expect(out).toContain('Tell the user');
    expect(out).toContain('re-run this same tool call');
    expect(out).toContain('re-evaluates every capture');
    expect(out).toContain('if it is safe to repeat');
    expect(out).not.toContain('aka exception approve');
  });

  it('marks itself as a placeholder that must never be written back', () => {
    const out = withheldToolText('Bash', 'secrets/aws-access-key', 'stdout');
    expect(out).toContain('placeholder');
    expect(out).toContain('never write this notice back');
    expect(out).toContain('unchanged');
  });

  it('names the replaced field so a partial withhold does not read as total', () => {
    const out = withheldToolText('Bash', 'secrets/aws-access-key', 'stderr');
    expect(out).toContain('Bash stderr withheld');
    expect(out).not.toContain('Bash output withheld');
  });
});
