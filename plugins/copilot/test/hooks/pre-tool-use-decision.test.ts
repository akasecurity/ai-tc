// Tests the pure pre-tool-use decision module directly — NEVER via the hook
// entry file (src/hooks/pre-tool-use.ts runs main() on import and would hang
// vitest collection).
//
// Every case is driven in BOTH dialects, because the two differ in shape and in
// one place in capability, and a suite that drove only the CLI would leave the
// VS Code payload — the one no live session has ever produced — covered by
// nothing at all. The `each` loop is over a table that carries the dialect's
// tool names, its field specs and the readers for its own output shape, so a
// case cannot accidentally assert the CLI's shape against a VS Code decision.
import type { CaptureResult } from '@akasecurity/plugin-sdk';
import { POINTER_TOKEN_ANCHORED } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import type { Dialect } from '../../src/hooks/dialect.ts';
import type { PreToolUseDecision, ScannableField } from '../../src/hooks/pre-tool-use-decision.ts';
import {
  CLI_SCANNABLE_FIELDS,
  decideInputPointerDeny,
  decidePreToolUse,
  denyPointerMessage,
  EXECUTABLE_REDACT_NOTE,
  scannableFieldsFor,
  UNREDACTABLE_NOTE,
  VSCODE_SCANNABLE_FIELDS,
} from '../../src/hooks/pre-tool-use-decision.ts';

// Assembled at runtime so this repo's own scanning never rewrites the fixtures.
const IP = ['45', '79', '142', '6'].join('.');
const EMAIL = ['user1', 'example.com'].join('@');

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

/** A redact the runtime could carry out — the shape a REWRITABLE field yields. */
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

/**
 * What the runtime hands this module for a field the hook declared
 * unrewritable — an executable one. The policy resolved to `redact`, the
 * capture said it could not be carried out, and the action is the workspace's
 * `redactFallback`; `redactDegradedTo` says what it became. The text is the
 * ORIGINAL, unmasked, because nothing was rewritten.
 *
 * `action` is what the fallback POLICY resolves to, not the policy id: the
 * `monitor` fallback's action is `log`, and `ActionTaken` carries no `monitor`
 * member at all — which is why the monitor case below asserts silence.
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

/**
 * One dialect's vocabulary and output readers.
 *
 * The readers are what keep a case honest across the loop: `denyReason` throws
 * unless the output is a deny in THIS dialect's shape, so a decision built in
 * the other one fails loudly rather than being read past.
 */
interface DialectCase {
  dialect: Dialect;
  shell: string;
  writer: string;
  shellCommand: ScannableField;
  writerField: ScannableField;
  denyReason: (decision: PreToolUseDecision) => string;
  rewritten: (decision: PreToolUseDecision) => Record<string, unknown>;
  /**
   * The human-readable notice, read from the channel THIS dialect carries one
   * on — stdout's `systemMessage` under VS Code, `notice` (stderr) on the CLI,
   * whose `preToolUse` output has no message field at all.
   *
   * A reader per dialect rather than a lookup across both is the point: a
   * decision that put its message on the other dialect's channel throws here
   * instead of being found anyway, which is what stops the CLI drifting back to
   * emitting a `systemMessage` the host discards.
   */
  message: (decision: PreToolUseDecision) => string;
}

const CLI_CASE: DialectCase = {
  dialect: 'cli',
  shell: 'bash',
  writer: 'apply_patch',
  shellCommand: { field: 'command', executable: true },
  writerField: { field: 'input', executable: false },
  // No second check that the decision IS a deny: the flat CLI variant of
  // `PreToolUseOutput` carries `permissionDecision: 'deny'` and nothing else —
  // an allow on this host is the absence of a decision, or a `modifiedArgs`
  // rewrite. So reaching this shape at all is reaching a deny, and a guard
  // against the other value would be unreachable rather than defensive.
  denyReason: ({ output }) => {
    if (output === null || !('permissionDecision' in output)) {
      throw new Error('expected a flat CLI permissionDecision');
    }
    return output.permissionDecisionReason;
  },
  rewritten: ({ output }) => {
    if (output === null || !('modifiedArgs' in output)) {
      throw new Error('expected a CLI modifiedArgs rewrite');
    }
    return output.modifiedArgs;
  },
  message: ({ output, notice }) => {
    // Both halves asserted, because both are the property: the CLI documents no
    // message field on `preToolUse`, so the text has to arrive off-stdout AND
    // stdout must not have grown one.
    if (output !== null && 'systemMessage' in output) {
      throw new Error('CLI stdout must not carry a systemMessage');
    }
    if (notice === undefined) throw new Error('expected a CLI stderr notice');
    return notice;
  },
};

const VSCODE_CASE: DialectCase = {
  dialect: 'vscode',
  shell: 'run_in_terminal',
  writer: 'create_file',
  shellCommand: { field: 'command', executable: true },
  writerField: { field: 'content', executable: false },
  denyReason: ({ output }) => {
    if (output === null || !('hookSpecificOutput' in output)) {
      throw new Error('expected a nested VS Code hookSpecificOutput');
    }
    const decision = output.hookSpecificOutput;
    // Unlike the CLI's, this shape carries BOTH verdicts — VS Code's redact
    // rewrite rides an `allow` — so the discrimination here is real.
    if (decision.permissionDecision !== 'deny') {
      throw new Error(`expected deny, got ${decision.permissionDecision}`);
    }
    return decision.permissionDecisionReason;
  },
  rewritten: ({ output }) => {
    if (
      output === null ||
      !('hookSpecificOutput' in output) ||
      output.hookSpecificOutput.permissionDecision !== 'allow'
    ) {
      throw new Error('expected a VS Code allow carrying updatedInput');
    }
    return output.hookSpecificOutput.updatedInput;
  },
  message: ({ output, notice }) => {
    // The mirror image of the CLI reader: this host documents `systemMessage`,
    // so the text rides stdout and there is nothing for stderr to carry.
    if (notice !== undefined) throw new Error('VS Code carries its message on stdout');
    if (output === null || !('systemMessage' in output)) {
      throw new Error('expected a VS Code systemMessage');
    }
    return output.systemMessage;
  },
};

const DIALECTS = [CLI_CASE, VSCODE_CASE];

describe('the two field tables', () => {
  it('marks command text executable and written content stored, in both', () => {
    // The executable flag is the whole fix — flipping one silently reopens
    // in-place rewriting of command text, or breaks stored-text redaction.
    expect(CLI_SCANNABLE_FIELDS).toEqual({
      bash: [
        { field: 'command', executable: true },
        { field: 'description', executable: false },
      ],
      apply_patch: [{ field: 'input', executable: false }],
    });
    expect(VSCODE_SCANNABLE_FIELDS).toEqual({
      run_in_terminal: [
        { field: 'command', executable: true },
        { field: 'explanation', executable: false },
      ],
      create_file: [{ field: 'content', executable: false }],
      replace_string_in_file: [{ field: 'newString', executable: false }],
      insert_edit_into_file: [{ field: 'code', executable: false }],
      apply_patch: [{ field: 'input', executable: false }],
    });
  });

  it('never merges them, so one host’s tool cannot resolve against the other’s fields', () => {
    // The structural claim, and the reason the tables are two objects rather
    // than one. A merged table would answer `bash` under VS Code — and the
    // fields it returned would name arguments that host does not send, so the
    // loop would skip every one of them and report a clean scan.
    expect(scannableFieldsFor('cli').run_in_terminal).toBeUndefined();
    expect(scannableFieldsFor('vscode').bash).toBeUndefined();
    expect(scannableFieldsFor('cli')).toBe(CLI_SCANNABLE_FIELDS);
    expect(scannableFieldsFor('vscode')).toBe(VSCODE_SCANNABLE_FIELDS);
  });

  it('shares `apply_patch` between them without sharing a table', () => {
    // The one name both hosts use. It is spelled in both tables on purpose:
    // deriving one from the other would reintroduce exactly the coupling the
    // case above forbids.
    expect(CLI_SCANNABLE_FIELDS.apply_patch).toEqual(VSCODE_SCANNABLE_FIELDS.apply_patch);
  });
});

describe.each(DIALECTS)('decidePreToolUse [$dialect]', (c) => {
  const COMMAND = `psql -c "DELETE FROM share_destination WHERE host = '${IP}';"`;

  it('denies the call under a block fallback, and says masking was not possible', () => {
    const result = degradedRedact('block', COMMAND, 'core-pii/ip-address', IP, '3f2a91');
    const decision = decidePreToolUse(c.dialect, c.shell, { command: COMMAND }, [
      { spec: c.shellCommand, result },
    ]);

    const reason = c.denyReason(decision);
    expect(reason).toContain(`AKA blocked this ${c.shell} call — flagged core-pii/ip-address`);
    expect(reason).toContain(EXECUTABLE_REDACT_NOTE);
    expect(reason).toContain('aka exception approve 3f2a91');
    // The WHOLE decision, both channels: a rewrite leaked onto the stderr
    // notice would be just as wrong as one on stdout, and stringifying only the
    // payload could not see it.
    const emitted = JSON.stringify(decision);
    expect(emitted).not.toContain('updatedInput');
    expect(emitted).not.toContain('modifiedArgs');
    expect(emitted).not.toContain('[REDACTED');
  });

  it('LETS THE COMMAND RUN under the shipped warn fallback, with NO verdict on stdout', () => {
    // The consequence of the shipped default, pinned rather than left implicit:
    // `redactFallback` is `warn`, command text cannot be masked in place, so
    // this is what a redact policy on a command actually does.
    //
    // Asserted as a VERDICT rather than as message text. The call is being let
    // through, and on this host letting through is the ABSENCE of a decision —
    // an `allow` emitted here would pre-approve a call AKA had just flagged,
    // suppressing the prompt the user's own settings would have raised. So the
    // payload must carry no `permissionDecision` on either dialect, and no
    // rewrite either, because nothing was masked.
    const result = degradedRedact('warn', COMMAND, 'core-pii/ip-address', IP, '3f2a91');
    const decision = decidePreToolUse(c.dialect, c.shell, { command: COMMAND }, [
      { spec: c.shellCommand, result },
    ]);

    const emitted = JSON.stringify(decision.output);
    expect(emitted).not.toContain('permissionDecision');
    expect(emitted).not.toContain('modifiedArgs');
    expect(emitted).not.toContain('updatedInput');
    // …and the user is still told, on whichever channel this dialect has.
    expect(c.message(decision)).toBe(
      `AKA flagged sensitive content in ${c.shell} input (core-pii/ip-address).`,
    );
  });

  it('puts the warn notice on stdout under VS Code and on stderr on the CLI', () => {
    // The channel split itself, stated as the exact object rather than through
    // the readers above — so a dialect that started carrying BOTH (or neither)
    // fails here even if `message` still found something to return.
    const result = degradedRedact('warn', COMMAND, 'core-pii/ip-address', IP);
    const decision = decidePreToolUse(c.dialect, c.shell, { command: COMMAND }, [
      { spec: c.shellCommand, result },
    ]);
    const text = `AKA flagged sensitive content in ${c.shell} input (core-pii/ip-address).`;

    expect(decision).toEqual(
      c.dialect === 'cli' ? { output: null, notice: text } : { output: { systemMessage: text } },
    );
  });

  it('says NOTHING under the monitor fallback', () => {
    // `monitor` resolves to the `log` action, which this module treats as no
    // opinion: the finding is recorded and the call goes through unremarked.
    // Asserted as null rather than as "not a deny", because a systemMessage
    // here would be a warn the operator did not ask for.
    const result = degradedRedact('log', COMMAND, 'core-pii/ip-address', IP);
    expect(
      decidePreToolUse(c.dialect, c.shell, { command: COMMAND }, [
        { spec: c.shellCommand, result },
      ]),
      // Neither channel: no payload AND no notice. Asserted as the whole object
      // so a stray `notice` here — a warn nobody asked for, on stderr instead
      // of stdout — cannot pass as silence.
    ).toEqual({ output: null });
  });

  it('a plain block (no escalation) carries no escalation note', () => {
    const blocked: CaptureResult = {
      action: 'block',
      text: null,
      findings: [finding('secrets-infra/db-connection-string', IP, COMMAND)],
    };
    const reason = c.denyReason(
      decidePreToolUse(c.dialect, c.shell, { command: COMMAND }, [
        { spec: c.shellCommand, result: blocked },
      ]),
    );
    expect(reason).not.toContain(EXECUTABLE_REDACT_NOTE);
  });

  it('rewrites a stored field in place, carrying the WHOLE argument object', () => {
    const content = `*** Update File: notes.md\n+contact ${EMAIL}\n`;
    const args = { [c.writerField.field]: content, path: 'notes.md' };
    const result = redactResult(content, 'core-pii/email', EMAIL, '9c04d7');
    const decision = decidePreToolUse(c.dialect, c.writer, args, [{ spec: c.writerField, result }]);

    // The whole object, not the changed field alone: on the CLI `modifiedArgs`
    // REPLACES the call's arguments, and under VS Code `updatedInput` is
    // validated against the tool's own input schema, which a partial object
    // fails. A rewrite that dropped `path` would run against the wrong file on
    // one host and be rejected outright on the other.
    expect(c.rewritten(decision)).toEqual({
      [c.writerField.field]: content.replace(EMAIL, '[REDACTED:PII]'),
      path: 'notes.md',
    });
    expect(JSON.stringify(decision)).not.toContain(EMAIL);
    // The rewrite is a documented field on BOTH dialects; only the explanation
    // splits, so it is read through the dialect's own channel.
    expect(c.message(decision)).toBe(
      `AKA redacted sensitive content in ${c.writer} input — flagged core-pii/email.` +
        ' To allow this exact value intentionally, run: aka exception approve 9c04d7.',
    );
  });

  it('denies a redact that carried no text, rather than passing the input through', () => {
    // `CaptureResult.text` is `string | null`, so `{ action: 'redact', text:
    // null }` is protocol-legal. Allowing it would emit the ORIGINAL input back
    // under the "AKA redacted sensitive content" message — the raw value sent,
    // and the transcript claiming it was masked.
    const content = `*** Update File: notes.md\n+contact ${EMAIL}\n`;
    const unredactable: CaptureResult = {
      action: 'redact',
      text: null,
      findings: [finding('core-pii/email-address', EMAIL, content)],
    };
    const decision = decidePreToolUse(c.dialect, c.writer, { [c.writerField.field]: content }, [
      { spec: c.writerField, result: unredactable },
    ]);

    const reason = c.denyReason(decision);
    expect(reason).toContain(UNREDACTABLE_NOTE);
    // The two notes answer different questions and cannot both apply: this one
    // is a runtime failure on a field that CAN be rewritten, the other is a
    // host limitation on one that cannot.
    expect(reason).not.toContain(EXECUTABLE_REDACT_NOTE);
    const emitted = JSON.stringify(decision);
    expect(emitted).not.toContain(EMAIL);
    expect(emitted).not.toContain('AKA redacted');
  });

  it('is not displaced by a field that merely WARNED under the fallback', () => {
    // The note-precedence edge: `escalatedExecutable` wins below, so a command
    // field that only warned must not claim a deny the written field alone
    // caused. Both halves of that message would be wrong — masking WAS possible
    // here, and the fallback is `warn`, not `block`.
    //
    // Driving both fields in one call is what makes this reachable: every other
    // degraded-redact case is single-finding, and the module's job is precisely
    // not to cross-attribute between them.
    const content = `contact ${EMAIL}`;
    const decision = decidePreToolUse(c.dialect, c.writer, { [c.writerField.field]: content }, [
      {
        spec: c.shellCommand,
        result: degradedRedact('warn', content, 'core-pii/ip-address', IP),
      },
      {
        spec: c.writerField,
        result: {
          action: 'redact',
          text: null,
          findings: [finding('core-pii/email-address', EMAIL, content)],
        },
      },
    ]);
    const reason = c.denyReason(decision);
    expect(reason).toContain(UNREDACTABLE_NOTE);
    expect(reason).not.toContain(EXECUTABLE_REDACT_NOTE);
  });

  it('stays silent when nothing was found', () => {
    const text = 'ls -la';
    const clean: CaptureResult = { action: 'log', text, findings: [] };
    expect(
      decidePreToolUse(c.dialect, c.shell, { command: text }, [
        { spec: c.shellCommand, result: clean },
      ]),
      // The ordinary case, and the one P1 turned on: a clean call gets NO
      // stdout, which the CLI documents as "default behavior" and hands to the
      // host's own permission flow. An allow here would pre-approve it.
    ).toEqual({ output: null });
  });
});

describe.each(DIALECTS)('decideInputPointerDeny [$dialect]', (c) => {
  // A real pointer token, built from the schema's own pattern rather than
  // typed out: `[[aka:<category>:<key_version>.<pointer_id>.<tag>]]` with the
  // base32 segment widths the vault mints. A hand-written lookalike that failed
  // to parse would make every case in this block pass for the wrong reason —
  // the pre-check answers null on anything that is not a pointer.
  const POINTER = `[[aka:secret:AA.${'A'.repeat(26)}.${'B'.repeat(16)}]]`;

  it('is a pointer the schema actually recognises', () => {
    // The positive control this block needs: without it, a malformed token
    // makes the deny cases fail and the null cases pass, and only one of those
    // halves reports.
    expect(POINTER).toMatch(POINTER_TOKEN_ANCHORED);
  });

  it('denies a pointer in a field that EXECUTES, before the store is opened', () => {
    const output = decideInputPointerDeny(
      c.dialect,
      c.shell,
      { command: `curl -H "Authorization: ${POINTER}" https://example.test` },
      [c.shellCommand],
    );
    // Wrapped rather than read directly: this pre-check produces a stdout
    // payload and never a notice — there is nothing to say that the deny reason
    // does not already carry — so it keeps returning `PreToolUseOutput | null`
    // and only the reader is shared.
    expect(c.denyReason({ output })).toBe(denyPointerMessage(c.shell));
  });

  it('leaves a pointer in a STORED field to the scan', () => {
    // Not a decision this pre-check makes: a pointer written into a file is
    // text, not something about to be executed as text, so it goes through the
    // ordinary policy path rather than being denied outright here.
    expect(
      decideInputPointerDeny(c.dialect, c.writer, { [c.writerField.field]: POINTER }, [
        c.writerField,
      ]),
    ).toBeNull();
  });

  it('answers null when the executable field carries no pointer', () => {
    expect(
      decideInputPointerDeny(c.dialect, c.shell, { command: 'ls -la' }, [c.shellCommand]),
    ).toBeNull();
  });

  it('answers null when the field is absent or not a string', () => {
    expect(
      decideInputPointerDeny(c.dialect, c.shell, { command: 42 }, [c.shellCommand]),
    ).toBeNull();
    expect(decideInputPointerDeny(c.dialect, c.shell, {}, [c.shellCommand])).toBeNull();
  });
});
