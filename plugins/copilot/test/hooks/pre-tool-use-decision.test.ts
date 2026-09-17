// Tests the pure preToolUse decision module directly — NEVER via the hook
// entry file (src/hooks/*.ts run main() on import and hang vitest collection).
//
// Every enforcement case is driven TWICE, once per dialect, against the same
// runtime result. That pairing is the point of this suite rather than a
// doubling of it: the two hosts' output vocabularies are near-misses (both
// spell `permissionDecision`, one at the top level and one nested), so a
// builder that answered the wrong host would be syntactically plausible and
// silently ignored by whichever host received it. Only a case that pins the
// shape per dialect can see that.
import type { CaptureResult } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import type { Dialect } from '../../src/hooks/dialect.ts';
import type { ScannableField } from '../../src/hooks/pre-tool-use-decision.ts';
import {
  CLI_SCANNABLE_FIELDS,
  decideInputPointerDeny,
  decidePreToolUse,
  denyPointerMessage,
  EXECUTABLE_REDACT_NOTE,
  scannableFields,
  UNREDACTABLE_NOTE,
  VSCODE_SCANNABLE_FIELDS,
} from '../../src/hooks/pre-tool-use-decision.ts';
import type { HookOutput } from '../../src/hooks/shared.ts';

// Assembled rather than written out: this repository is public, and a literal
// that looks like a real credential does not belong in it.
const IP = ['45', '79', '142', '6'].join('.');
const EMAIL = ['user1', 'example.com'].join('@');

const DIALECTS: Dialect[] = ['cli', 'vscode'];

// The two hosts' executable field and stored field. Named per dialect so each
// case drives the tool the host it is testing actually sends.
const EXECUTABLE: Record<Dialect, { tool: string; spec: ScannableField }> = {
  cli: { tool: 'bash', spec: { field: 'command', executable: true } },
  vscode: { tool: 'run_in_terminal', spec: { field: 'command', executable: true } },
};
const STORED: Record<Dialect, { tool: string; spec: ScannableField }> = {
  cli: { tool: 'apply_patch', spec: { field: 'input', executable: false } },
  vscode: { tool: 'create_file', spec: { field: 'content', executable: false } },
};

type Finding = CaptureResult['findings'][number];

function finding(ruleId: string, rawMatch: string, text: string): Finding {
  const start = text.indexOf(rawMatch);
  return {
    ruleId,
    category: 'pii',
    severity: 'low',
    span: { start, end: start + rawMatch.length },
    rawMatch,
    confidence: 0.9,
  };
}

function blockResult(text: string, ruleId: string, rawMatch: string, reference?: string) {
  return {
    action: 'block' as const,
    text: null,
    findings: [finding(ruleId, rawMatch, text)],
    ...(reference ? { blockedReferences: [{ reference, ruleId, maskedValue: '4******6' }] } : {}),
  };
}

function redactResult(
  text: string,
  ruleId: string,
  rawMatch: string,
  reference?: string,
): CaptureResult {
  return {
    action: 'redact',
    text: text.replace(rawMatch, '[REDACTED:PII]'),
    findings: [finding(ruleId, rawMatch, text)],
    ...(reference ? { blockedReferences: [{ reference, ruleId, maskedValue: '4******6' }] } : {}),
  };
}

function warnResult(text: string, ruleId: string, rawMatch: string): CaptureResult {
  return { action: 'warn', text, findings: [finding(ruleId, rawMatch, text)] };
}

function monitorResult(text: string): CaptureResult {
  return { action: 'log', text, findings: [] };
}

/**
 * What the runtime hands this module for a field the hook declared
 * unrewritable — an executable one. The policy resolved to `redact`, the
 * capture said it could not be carried out, and the action is the workspace's
 * `redactFallback`; `redactDegradedTo` says what it became. The text is the
 * ORIGINAL, unmasked, because nothing was rewritten.
 */
function degradedRedact(
  action: 'log' | 'warn' | 'block',
  text: string,
  ruleId: string,
  rawMatch: string,
  reference?: string,
): CaptureResult {
  return {
    action,
    text: action === 'block' ? null : text,
    findings: [finding(ruleId, rawMatch, text)],
    redactDegradedTo: action,
    ...(reference ? { blockedReferences: [{ reference, ruleId, maskedValue: '4******6' }] } : {}),
  };
}

/** The deny reason, read out of whichever shape this dialect's host reads. */
function denyReason(output: HookOutput | null, dialect: Dialect): string {
  if (output === null) throw new Error('expected a decision, got null');
  if (dialect === 'vscode') {
    if (!('hookSpecificOutput' in output)) throw new Error('expected hookSpecificOutput');
    const decision = output.hookSpecificOutput;
    if (decision.permissionDecision !== 'deny') {
      throw new Error(`expected deny, got ${decision.permissionDecision}`);
    }
    return decision.permissionDecisionReason;
  }
  if (!('permissionDecision' in output)) throw new Error('expected a top-level permissionDecision');
  if (output.permissionDecision !== 'deny') {
    throw new Error(`expected deny, got ${output.permissionDecision}`);
  }
  return output.permissionDecisionReason ?? '';
}

/** The rewritten argument bag, read out of whichever shape this dialect uses. */
function rewritten(output: HookOutput | null, dialect: Dialect): Record<string, unknown> {
  if (output === null) throw new Error('expected a decision, got null');
  if (dialect === 'vscode') {
    if (!('hookSpecificOutput' in output)) throw new Error('expected hookSpecificOutput');
    const decision = output.hookSpecificOutput;
    if (decision.permissionDecision !== 'allow') throw new Error('expected an allow');
    return decision.updatedInput;
  }
  if (!('modifiedArgs' in output)) throw new Error('expected modifiedArgs');
  return output.modifiedArgs;
}

describe('the two field tables', () => {
  it('keep the executable flag on command text and off stored text', () => {
    // The executable flag is the whole of the redact split — flipping one
    // silently reopens in-place rewriting of command text (or breaks
    // stored-text redaction, which is the only place true masking happens).
    expect(CLI_SCANNABLE_FIELDS.bash).toContainEqual({ field: 'command', executable: true });
    expect(CLI_SCANNABLE_FIELDS.bash).toContainEqual({ field: 'description', executable: false });
    expect(VSCODE_SCANNABLE_FIELDS.run_in_terminal).toContainEqual({
      field: 'command',
      executable: true,
    });
  });

  it('never merges, because the two vocabularies do not overlap', () => {
    // The failure a merged table causes is silent: a CLI `bash` payload looked
    // up under VS Code's table finds nothing and is allowed unscanned, while a
    // merged table would find `run_in_terminal`'s fields and scan keys the
    // payload does not have — reporting success having read nothing.
    expect(CLI_SCANNABLE_FIELDS.run_in_terminal).toBeUndefined();
    expect(VSCODE_SCANNABLE_FIELDS.bash).toBeUndefined();
    expect(scannableFields('cli')).toBe(CLI_SCANNABLE_FIELDS);
    expect(scannableFields('vscode')).toBe(VSCODE_SCANNABLE_FIELDS);
  });

  it('shares only apply_patch, which both hosts really do expose', () => {
    expect(CLI_SCANNABLE_FIELDS.apply_patch).toBeDefined();
    expect(VSCODE_SCANNABLE_FIELDS.apply_patch).toBeDefined();
  });
});

describe.each(DIALECTS)('decidePreToolUse [%s]', (dialect) => {
  const exec = EXECUTABLE[dialect];
  const stored = STORED[dialect];
  const COMMAND = `psql -c "DELETE FROM share_destination WHERE host = '${IP}';"`;
  const CONTENT = `contact ${EMAIL}\n`;

  it('blocks, naming the rule and the exception command', () => {
    const output = decidePreToolUse(dialect, exec.tool, { command: COMMAND }, [
      { spec: exec.spec, result: blockResult(COMMAND, 'core-pii/ip-address', IP, '3f2a91') },
    ]);
    const reason = denyReason(output, dialect);
    expect(reason).toContain(`AKA blocked this ${exec.tool} call — flagged core-pii/ip-address`);
    expect(reason).toContain('aka exception approve 3f2a91');
    // A plain block carries neither escalation note.
    expect(reason).not.toContain(EXECUTABLE_REDACT_NOTE);
    expect(reason).not.toContain(UNREDACTABLE_NOTE);
  });

  it('redacts a STORED field in place, carrying the whole argument bag', () => {
    const args = { [stored.spec.field]: CONTENT, path: 'notes.md' };
    const output = decidePreToolUse(dialect, stored.tool, args, [
      { spec: stored.spec, result: redactResult(CONTENT, 'core-pii/email-address', EMAIL, 'a1') },
    ]);
    const updated = rewritten(output, dialect);
    expect(updated[stored.spec.field]).toContain('[REDACTED:PII]');
    expect(updated[stored.spec.field]).not.toContain(EMAIL);
    // The untouched sibling survives: both hosts REPLACE the argument bag, and
    // VS Code validates it against the tool's own schema, which a partial
    // object would fail.
    expect(updated.path).toBe('notes.md');
    expect(JSON.stringify(output)).not.toContain(EMAIL);
  });

  it('denies an EXECUTABLE redact under a block fallback, saying masking was impossible', () => {
    const output = decidePreToolUse(dialect, exec.tool, { command: COMMAND }, [
      {
        spec: exec.spec,
        result: degradedRedact('block', COMMAND, 'core-pii/ip-address', IP, '3f2a91'),
      },
    ]);
    const reason = denyReason(output, dialect);
    expect(reason).toContain(EXECUTABLE_REDACT_NOTE);
    const emitted = JSON.stringify(output);
    expect(emitted).not.toContain('updatedInput');
    expect(emitted).not.toContain('modifiedArgs');
    expect(emitted).not.toContain('[REDACTED');
  });

  it('LETS THE COMMAND RUN under the shipped warn fallback, saying so on screen', () => {
    // The consequence of the shipped default, pinned rather than left implicit:
    // this command would have been denied before the fallback existed. The
    // payload still carries no rewrite, because nothing was masked.
    const output = decidePreToolUse(dialect, exec.tool, { command: COMMAND }, [
      { spec: exec.spec, result: degradedRedact('warn', COMMAND, 'core-pii/ip-address', IP) },
    ]);
    const emitted = JSON.stringify(output);
    expect(emitted).toContain(`AKA flagged sensitive content in ${exec.tool} input`);
    expect(emitted).not.toContain('updatedInput');
    expect(emitted).not.toContain('modifiedArgs');
    expect(emitted).not.toContain('AKA redacted');
  });

  it('denies a redact carrying no text rather than passing the input through', () => {
    // CaptureResult.text is `string | null`, so { action: 'redact', text: null }
    // is protocol-legal. Allowing it would emit the ORIGINAL input back under
    // the "AKA redacted sensitive content" message — the raw value sent, and
    // the transcript claiming it was masked.
    const args = { [stored.spec.field]: CONTENT };
    const output = decidePreToolUse(dialect, stored.tool, args, [
      {
        spec: stored.spec,
        result: {
          action: 'redact',
          text: null,
          findings: [finding('core-pii/email-address', EMAIL, CONTENT)],
        },
      },
    ]);
    const reason = denyReason(output, dialect);
    expect(reason).toContain(UNREDACTABLE_NOTE);
    expect(reason).not.toContain(EXECUTABLE_REDACT_NOTE);
    expect(JSON.stringify(output)).not.toContain(EMAIL);
  });

  it('is not displaced by a field that merely WARNED under the fallback', () => {
    // `escalatedExecutable` wins the note precedence, so reading
    // `redactDegradedTo` by PRESENCE rather than by VALUE would let a command
    // field that only warned displace the unredactable note on a deny the
    // stored field alone caused — wrong on both halves of what it then says.
    const output = decidePreToolUse(
      dialect,
      exec.tool,
      { command: COMMAND, [stored.spec.field]: CONTENT },
      [
        { spec: exec.spec, result: degradedRedact('warn', COMMAND, 'core-pii/ip-address', IP) },
        {
          spec: stored.spec,
          result: {
            action: 'redact',
            text: null,
            findings: [finding('core-pii/email-address', EMAIL, CONTENT)],
          },
        },
      ],
    );
    const reason = denyReason(output, dialect);
    expect(reason).toContain(UNREDACTABLE_NOTE);
    expect(reason).not.toContain(EXECUTABLE_REDACT_NOTE);
  });

  it('warns without rewriting anything', () => {
    const output = decidePreToolUse(dialect, exec.tool, { command: COMMAND }, [
      { spec: exec.spec, result: warnResult(COMMAND, 'core-pii/ip-address', IP) },
    ]);
    expect(output).toEqual({
      systemMessage: `AKA flagged sensitive content in ${exec.tool} input (core-pii/ip-address).`,
    });
  });

  it('says nothing at all under monitor', () => {
    // `null` is the "no opinion" the caller turns into the explicit allow. A
    // monitor decision must not emit a systemMessage: there is nothing to tell
    // the user, and on the CLI every byte printed is a decision.
    const output = decidePreToolUse(dialect, exec.tool, { command: COMMAND }, [
      { spec: exec.spec, result: monitorResult(COMMAND) },
    ]);
    expect(output).toBeNull();
  });

  it('emits the deny in THIS host’s shape and not the other host’s', () => {
    const output = decidePreToolUse(dialect, exec.tool, { command: COMMAND }, [
      { spec: exec.spec, result: blockResult(COMMAND, 'core-pii/ip-address', IP) },
    ]);
    if (dialect === 'cli') {
      expect(output).toHaveProperty('permissionDecision', 'deny');
      expect(output).not.toHaveProperty('hookSpecificOutput');
    } else {
      expect(output).toHaveProperty('hookSpecificOutput');
      expect(output).not.toHaveProperty('permissionDecision');
    }
  });
});

describe.each(DIALECTS)('decideInputPointerDeny [%s]', (dialect) => {
  const exec = EXECUTABLE[dialect];
  const stored = STORED[dialect];
  // A real pointer's own token shape, assembled from its documented segment
  // widths rather than written out: `[[aka:<category>:<b32 key_version>.<b32
  // pointer_id>.<b32 tag>]]`. Nothing secret-shaped is in it.
  const POINTER = `[[aka:secret:AA.${'A'.repeat(26)}.${'A'.repeat(16)}]]`;

  it('denies a pointer in a field that EXECUTES, in this host’s shape', () => {
    const output = decideInputPointerDeny(dialect, exec.tool, { command: POINTER }, [exec.spec]);
    expect(output).not.toBeNull();
    expect(denyReason(output, dialect)).toBe(denyPointerMessage(exec.tool));
  });

  it('lets a pointer in a STORED field through to the scan', () => {
    // The pre-check is scoped to executable text on purpose: a pointer written
    // into a file is a string, not something that runs, and the ordinary scan
    // is what has an opinion about it.
    const output = decideInputPointerDeny(dialect, stored.tool, { [stored.spec.field]: POINTER }, [
      stored.spec,
    ]);
    expect(output).toBeNull();
  });

  it('returns null when no pointer is present', () => {
    expect(
      decideInputPointerDeny(dialect, exec.tool, { command: 'ls -la' }, [exec.spec]),
    ).toBeNull();
  });

  it('ignores a non-string field', () => {
    expect(decideInputPointerDeny(dialect, exec.tool, { command: 42 }, [exec.spec])).toBeNull();
  });

  it('does not deny on a lookalike carrying an invented category', () => {
    // The category alternation in the pointer pattern is pinned to the real
    // DetectionCategory members, so a token that merely LOOKS like a pointer
    // must not trip an executable-field deny — it is ordinary text, and the
    // ordinary scan is what has an opinion about it.
    const lookalike = `[[aka:bogus:AA.${'A'.repeat(26)}.${'A'.repeat(16)}]]`;
    expect(
      decideInputPointerDeny(dialect, exec.tool, { command: lookalike }, [exec.spec]),
    ).toBeNull();
  });
});
