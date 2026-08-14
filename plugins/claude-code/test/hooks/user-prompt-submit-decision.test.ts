// Tests the pure UserPromptSubmit decision module directly — NEVER via the hook
// entry file (src/hooks/*.ts run main() on import and hang vitest collection).
// The spawn-driven suite next door (user-prompt-submit.test.ts) stays as the
// wire contract; this one reaches the branches a spawn cannot reach cheaply —
// a vault that faults, a rewrite that minted nothing, and the never-leak gate.
//
// Two shapes here are the whole point, because both are easy to break by
// borrowing from the neighbouring hook:
//
//   - block is `{"decision":"block", reason}` at the TOP LEVEL. PreToolUse's
//     `hookSpecificOutput.permissionDecision` is a DIFFERENT field that
//     UserPromptSubmit does not read, so emitting it here is silently an allow.
//   - a `redact` policy BLOCKS. This surface has no prompt-rewrite channel, so
//     the older "sent unchanged" warn would put the raw value in front of the
//     model under a message claiming it was masked. That regression is pinned
//     by name below.
//
// The fixture secret is assembled at runtime rather than written contiguously:
// this repo is developed with the AKA plugin active, so a contiguous literal
// would be redacted out of the test source as it is written. It is high-entropy
// but deliberately NOT credential-shaped — this repo is public.
import type { CaptureResult } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import type {
  PromptTokenizer,
  UserPromptSubmitOutput,
} from '../../src/hooks/user-prompt-submit-decision.ts';
import {
  decideUserPromptSubmit,
  pointerizedRewrite,
} from '../../src/hooks/user-prompt-submit-decision.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

const SECRET = ['7hK2', 'wQ9x', 'Lm4T', 'vB8z'].join('');
const PROMPT = `please deploy using this key: ${SECRET}`;
const POINTER = '[[aka:secret:c0ffee11]]';
const REWRITTEN = `please deploy using this key: ${POINTER}`;
const RULE = 'secrets/twilio-key';
const REF = { reference: '3f2a91', ruleId: RULE, maskedValue: '7******z' };

// The message the old redact-degrades-to-warn branch printed. It exists in this
// file only so its return can be caught: a `redact` that warns instead of
// blocking sends the raw prompt to the model.
const STALE_REDACT_COPY = 'cannot be redacted';

type Finding = CaptureResult['findings'][number];

function finding(rawMatch: string, text: string): Finding {
  const start = text.indexOf(rawMatch);
  return {
    ruleId: RULE,
    category: 'secret',
    severity: 'high',
    span: { start, end: start + rawMatch.length },
    rawMatch,
    confidence: 0.95,
  };
}

// `text` mirrors what the runtime really hands back per action: null for a
// block (nothing to pass through) and the REDACTED form for a redact. The
// decision reads neither today, but a fixture carrying the raw prompt where
// the runtime carries a masked one would validate a future `result.text`
// reader against data no runtime produces.
const REDACTED = PROMPT.replace(SECRET, '[REDACTED:SECRET]');

function result(action: CaptureResult['action'], opts: { ref?: boolean } = {}): CaptureResult {
  return {
    action,
    text: action === 'block' ? null : action === 'redact' ? REDACTED : PROMPT,
    findings: [finding(SECRET, PROMPT)],
    ...(opts.ref ? { blockedReferences: [REF] } : {}),
  };
}

// A tokenizer that swaps the secret for a pointer — the happy path the vault
// takes when consent is granted and every span vaults cleanly.
const tokenizerOk: PromptTokenizer = () =>
  Promise.resolve({ text: REWRITTEN, pointers: [POINTER] });

function blockReason(output: UserPromptSubmitOutput | null): string {
  if (output === null || !('decision' in output)) {
    throw new Error(`expected a block decision, got ${JSON.stringify(output)}`);
  }
  return output.reason;
}

function warnMessage(output: UserPromptSubmitOutput | null): string {
  if (output === null || !('systemMessage' in output)) {
    throw new Error(`expected a systemMessage, got ${JSON.stringify(output)}`);
  }
  return output.systemMessage;
}

describe('decideUserPromptSubmit — block', () => {
  it('emits the top-level {decision:"block", reason} shape, not PreToolUse\'s', async () => {
    const output = await decideUserPromptSubmit(PROMPT, result('block'));

    expect(output).not.toBeNull();
    // The shape UserPromptSubmit actually reads. Borrowing the sibling hook's
    // `hookSpecificOutput.permissionDecision` here is read as no opinion.
    expect(output).toHaveProperty('decision', 'block');
    expect(typeof blockReason(output)).toBe('string');
    expect(JSON.stringify(output)).not.toContain('hookSpecificOutput');
    expect(JSON.stringify(output)).not.toContain('permissionDecision');
  });

  it('names the flagged rule and leads with removal', async () => {
    const reason = blockReason(await decideUserPromptSubmit(PROMPT, result('block')));

    expect(reason).toMatch(/^AKA blocked this prompt — flagged /);
    expect(reason).toContain(RULE);
    expect(reason).toContain('Remove the flagged content and resubmit');
    expectNoEchoOf(reason, SECRET);
  });

  it('never touches the vault when no tokenizer is supplied (consent absent)', async () => {
    const reason = blockReason(await decideUserPromptSubmit(PROMPT, result('block')));

    // Positive control first: every other assertion here is an absence, and an
    // absence over an empty reason proves nothing.
    expect(reason).toContain('Remove the flagged content and resubmit');
    // Consent-off surfaces mint no pointer and say nothing about a vault.
    expect(reason).not.toContain('[[aka:');
    expect(reason).not.toContain('paste and resubmit');
    expectNoEchoOf(reason, SECRET);
  });
});

describe('decideUserPromptSubmit — redact blocks, it does not degrade to warn', () => {
  it('returns the same block shape a block policy returns', async () => {
    const output = await decideUserPromptSubmit(PROMPT, result('redact'));

    expect(output).toHaveProperty('decision', 'block');
    const reason = blockReason(output);
    expect(reason).toMatch(/^AKA blocked this prompt — flagged /);
    expect(reason).toContain('Remove the flagged content and resubmit');
    expectNoEchoOf(reason, SECRET);
  });

  it('never emits a systemMessage, and never the stale "sent unchanged" copy', async () => {
    const output = await decideUserPromptSubmit(PROMPT, result('redact'));

    // The positive control comes first, and is load-bearing twice over: a null
    // output would make `toHaveProperty` throw a TypeError (red for the wrong
    // reason) and would make both `not.toContain` checks below pass on the
    // string "null".
    expect(output).toHaveProperty('decision', 'block');
    // The regression this pins: warning here passes the raw prompt through to
    // the model, because this surface cannot rewrite it.
    expect(output).not.toHaveProperty('systemMessage');
    expect(JSON.stringify(output)).not.toContain(STALE_REDACT_COPY);
    expect(JSON.stringify(output)).not.toContain('sent unchanged');
  });

  it('upgrades to the pointerized resubmit message when the vault is available', async () => {
    const reason = blockReason(
      await decideUserPromptSubmit(PROMPT, result('redact'), { tokenizePrompt: tokenizerOk }),
    );

    expect(reason).toContain('never reached the model');
    expect(reason).toContain(POINTER);
    expect(reason).toContain('paste and resubmit');
    expectNoEchoOf(reason, SECRET);
  });
});

describe('decideUserPromptSubmit — the pointerized resubmit branch', () => {
  it('reports the clipboard write when one landed', async () => {
    const written: string[] = [];
    const reason = blockReason(
      await decideUserPromptSubmit(PROMPT, result('block'), {
        tokenizePrompt: tokenizerOk,
        writeClipboard: (text) => {
          written.push(text);
          return true;
        },
      }),
    );

    expect(reason).toContain('It is already on your clipboard');
    // Only the pointerized text ever reaches the clipboard — never the raw
    // prompt. Assert what DID land before asserting what did not.
    expect(written).toEqual([REWRITTEN]);
    expectNoEchoOf(written.join('\n'), SECRET);
  });

  it('tells the user to copy by hand when the clipboard write failed', async () => {
    const reason = blockReason(
      await decideUserPromptSubmit(PROMPT, result('block'), {
        tokenizePrompt: tokenizerOk,
        writeClipboard: () => false,
      }),
    );

    expect(reason).toContain('Copy it, then paste and resubmit');
    expect(reason).not.toContain('already on your clipboard');
  });

  it('does not claim a clipboard write when no clipboard seam was supplied', async () => {
    const reason = blockReason(
      await decideUserPromptSubmit(PROMPT, result('block'), { tokenizePrompt: tokenizerOk }),
    );

    expect(reason).toContain('Copy it, then paste and resubmit');
    expect(reason).not.toContain('already on your clipboard');
  });

  it('still blocks when the clipboard seam throws', async () => {
    // The clipboard decides one sentence, never the verdict. An escaping throw
    // would land in the entry's fail-open catch, which writes nothing and exits
    // 0 — and silence is ALLOW on this host, so a clipboard fault would send
    // the very prompt being blocked.
    const output = await decideUserPromptSubmit(PROMPT, result('block'), {
      tokenizePrompt: tokenizerOk,
      writeClipboard: () => {
        throw new Error('no clipboard utility on this machine');
      },
    });

    expect(output).toHaveProperty('decision', 'block');
    const reason = blockReason(output);
    expect(reason).toContain(POINTER);
    // Degraded to the copy-it-yourself sentence, not lost.
    expect(reason).toContain('Copy it, then paste and resubmit');
    expectNoEchoOf(reason, SECRET);
  });

  it('never offers the clipboard the raw prompt on the fallback path', async () => {
    const written: string[] = [];
    const reason = blockReason(
      await decideUserPromptSubmit(PROMPT, result('block'), {
        // A vault that mints nothing: the rewrite is refused, so the clipboard
        // must never be reached at all.
        tokenizePrompt: () => Promise.resolve({ text: PROMPT, pointers: [] }),
        writeClipboard: (text) => {
          written.push(text);
          return true;
        },
      }),
    );

    expect(written).toEqual([]);
    expect(reason).toContain('Remove the flagged content and resubmit');
    expectNoEchoOf(reason, SECRET);
  });
});

describe('pointerizedRewrite — the never-leak gate', () => {
  it('returns the rewrite when every span was pointerized', async () => {
    const rewrite = await pointerizedRewrite(PROMPT, [finding(SECRET, PROMPT)], tokenizerOk);

    expect(rewrite).toBe(REWRITTEN);
  });

  it('refuses a rewrite that still carries the raw match', async () => {
    // The gate: a partial rewrite has pointers in it and reads like a success,
    // so without this check the raw value is printed back to the user under a
    // message saying it never reached the model.
    const leaky = `${PROMPT} (also ${POINTER})`;
    const rewrite = await pointerizedRewrite(PROMPT, [finding(SECRET, PROMPT)], () =>
      Promise.resolve({ text: leaky, pointers: [POINTER] }),
    );

    expect(rewrite).toBeNull();
  });

  it('refuses a rewrite that minted no pointer', async () => {
    const rewrite = await pointerizedRewrite(PROMPT, [finding(SECRET, PROMPT)], () =>
      Promise.resolve({ text: REWRITTEN, pointers: [] }),
    );

    expect(rewrite).toBeNull();
  });

  it('refuses on a vault fault rather than propagating it', async () => {
    const rewrite = await pointerizedRewrite(PROMPT, [finding(SECRET, PROMPT)], () => {
      throw new Error('vault unavailable');
    });

    expect(rewrite).toBeNull();
  });

  it('ignores a finding whose raw match is empty', async () => {
    // An empty rawMatch is `includes('')` === true for every string, so without
    // the `!== ''` guard the gate would refuse every rewrite.
    const blank: Finding = { ...finding(SECRET, PROMPT), rawMatch: '' };
    const rewrite = await pointerizedRewrite(PROMPT, [blank], tokenizerOk);

    expect(rewrite).toBe(REWRITTEN);
  });

  it('falls back to the removal-based block when the gate refuses', async () => {
    const reason = blockReason(
      await decideUserPromptSubmit(PROMPT, result('block'), {
        tokenizePrompt: () => Promise.resolve({ text: PROMPT, pointers: [POINTER] }),
      }),
    );

    expect(reason).toContain('Remove the flagged content and resubmit');
    expect(reason).not.toContain('paste and resubmit');
    expectNoEchoOf(reason, SECRET);
  });
});

describe('decideUserPromptSubmit — warn', () => {
  it('emits a systemMessage and never a block', async () => {
    const output = await decideUserPromptSubmit(PROMPT, result('warn'));

    // Accessor first: it names what it actually got, where a bare
    // `not.toHaveProperty` on a null output throws a TypeError instead.
    const message = warnMessage(output);
    expect(output).not.toHaveProperty('decision');
    expect(message).toContain(RULE);
    expect(message).toContain('sent unchanged');
    expectNoEchoOf(message, SECRET);
  });

  it('never escalates to a block even with a tokenizer available', async () => {
    // A warn is not an enforcement, so the vault must not be reached for it.
    let tokenized = false;
    const output = await decideUserPromptSubmit(PROMPT, result('warn'), {
      tokenizePrompt: () => {
        tokenized = true;
        return Promise.resolve({ text: REWRITTEN, pointers: [POINTER] });
      },
    });

    // Assert the warn shape through the accessor, which names what it got: a
    // bare `not.toHaveProperty` on a null output throws a TypeError instead,
    // which is red for the wrong reason.
    expect(warnMessage(output)).toContain(RULE);
    expect(output).not.toHaveProperty('decision');
    expect(tokenized).toBe(false);
  });
});

describe('decideUserPromptSubmit — allow', () => {
  it('returns null (no output) for a clean prompt', async () => {
    const clean: CaptureResult = { action: 'log', text: PROMPT, findings: [] };

    expect(await decideUserPromptSubmit(PROMPT, clean)).toBeNull();
  });

  it('returns null for a monitor/log action that still carried findings', async () => {
    // Findings without enforcement are not an opinion — this is the slot the
    // entry uses for the onboarding nudge, so a payload here would suppress it.
    expect(await decideUserPromptSubmit(PROMPT, result('log'))).toBeNull();
  });

  it("returns null for the literal 'allow' action", async () => {
    // `ActionTaken` is warn | redact | block | allow | log, and 'allow' reaches
    // this function as a real value — every other case here drives 'log', so
    // without this the enum member the AC is actually named after is untested.
    expect(await decideUserPromptSubmit(PROMPT, result('allow'))).toBeNull();
  });

  it('never reaches the vault on an allow', async () => {
    let tokenized = false;
    const output = await decideUserPromptSubmit(PROMPT, result('log'), {
      tokenizePrompt: () => {
        tokenized = true;
        return Promise.resolve({ text: REWRITTEN, pointers: [POINTER] });
      },
    });

    expect(output).toBeNull();
    expect(tokenized).toBe(false);
  });
});

describe('decideUserPromptSubmit — the exception-pointer suffix', () => {
  it('appends the approve command to a warn when a ledger row exists', async () => {
    const message = warnMessage(
      await decideUserPromptSubmit(PROMPT, result('warn', { ref: true })),
    );

    expect(message).toContain(`aka exception approve ${REF.reference}`);
    expect(message).toContain('To allow this exact value intentionally');
  });

  it('omits it from a warn when nothing was ledgered', async () => {
    const message = warnMessage(await decideUserPromptSubmit(PROMPT, result('warn')));

    // The command would find no block, so it is not offered.
    expect(message).not.toContain('aka exception approve');
  });

  it('carries the ledger reference and masked preview into a block', async () => {
    const reason = blockReason(
      await decideUserPromptSubmit(PROMPT, result('block', { ref: true })),
    );

    expect(reason).toContain(`aka exception approve ${REF.reference}`);
    // Preview and reference come from the same ledger row.
    expect(reason).toContain(REF.maskedValue);
    expectNoEchoOf(reason, SECRET);
  });

  it('degrades a block to the bare approve command when nothing was ledgered', async () => {
    const reason = blockReason(await decideUserPromptSubmit(PROMPT, result('block')));

    expect(reason).toContain('aka exception approve       (asks for scope + reason');
    expect(reason).not.toContain(REF.reference);
  });

  it('appends the approve command to the pointerized resubmit message', async () => {
    const reason = blockReason(
      await decideUserPromptSubmit(PROMPT, result('block', { ref: true }), {
        tokenizePrompt: tokenizerOk,
      }),
    );

    expect(reason).toContain(POINTER);
    expect(reason).toContain(`aka exception approve ${REF.reference}`);
    expectNoEchoOf(reason, SECRET);
  });

  it('omits it from the resubmit message when nothing was ledgered', async () => {
    // The third surface carrying the suffix, and the cell that completes the
    // matrix: present/absent on the warn message, the block message, and the
    // resubmit message alike.
    const reason = blockReason(
      await decideUserPromptSubmit(PROMPT, result('block'), { tokenizePrompt: tokenizerOk }),
    );

    // Positive control first — the absence below is meaningless over a reason
    // that is not the resubmit message at all.
    expect(reason).toContain(POINTER);
    expect(reason).not.toContain('aka exception approve');
  });
});
