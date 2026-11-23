/**
 * The pure decision functions, over hand-built capture results, for the
 * branches the run suites cannot reach through a real store.
 */
import type { CaptureResult } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import {
  decidePreToolUse,
  EXECUTABLE_REDACT_NOTE,
  isMcpTool,
  NO_REWRITE_NOTE,
  UNREDACTABLE_NOTE,
} from '../../src/hooks/pre-tool-use-decision.ts';
import { PROMPT_NO_REWRITE_NOTE, promptDecision } from '../../src/hooks/prompt-decision.ts';
import { responseNotice, scanResponseFields } from '../../src/hooks/scan-response.ts';
import { callKind, FILE_WRITERS } from '../../src/hooks/shared.ts';
import { scannableFields } from '../../src/hooks/tool-response.ts';

const FINDING = { ruleId: 'secrets/example' };

function result(overrides: Partial<CaptureResult>): CaptureResult {
  return { action: 'allow', findings: [], text: '', ...overrides };
}

const SHELL = { field: 'command', executable: true };
const CONTENT = { field: 'contents', executable: false };

describe('decidePreToolUse', () => {
  it('denies a block naming the rule', () => {
    const { output } = decidePreToolUse('Shell', [
      { spec: SHELL, result: result({ action: 'block', findings: [FINDING] as never }) },
    ]);
    expect(output?.permission).toBe('deny');
    expect(output?.agent_message).toContain(FINDING.ruleId);
    expect(output?.user_message).toBe(output?.agent_message);
  });

  it('explains a redact the runtime degraded to block, per field kind', () => {
    const shell = decidePreToolUse('Shell', [
      {
        spec: SHELL,
        result: result({
          action: 'block',
          findings: [FINDING] as never,
          redactDegradedTo: 'block',
        }),
      },
    ]);
    expect(shell.output?.agent_message).toContain(EXECUTABLE_REDACT_NOTE);
    const write = decidePreToolUse('Write', [
      {
        spec: CONTENT,
        result: result({
          action: 'block',
          findings: [FINDING] as never,
          redactDegradedTo: 'block',
        }),
      },
    ]);
    expect(write.output?.agent_message).toContain(NO_REWRITE_NOTE);
  });

  it('carries an undegraded redact out as a block', () => {
    const masked = decidePreToolUse('Write', [
      { spec: CONTENT, result: result({ action: 'redact', findings: [FINDING] as never }) },
    ]);
    expect(masked.output?.agent_message).toContain(NO_REWRITE_NOTE);
    const missing = decidePreToolUse('Write', [
      {
        spec: CONTENT,
        result: result({ action: 'redact', findings: [FINDING] as never, text: null }),
      },
    ]);
    expect(missing.output?.agent_message).toContain(UNREDACTABLE_NOTE);
  });

  it('writes nothing for a warn, and reports it as a notice', () => {
    const decision = decidePreToolUse('Shell', [
      { spec: SHELL, result: result({ action: 'warn', findings: [FINDING] as never }) },
    ]);
    expect(decision.output).toBeNull();
    expect(decision.notice).toContain(FINDING.ruleId);
  });

  it('reports MCP arguments left past the walk bounds without denying', () => {
    const decision = decidePreToolUse('MCP:x', [], true);
    expect(decision.output).toBeNull();
    expect(decision.notice).toContain('was not checked');
    expect(decidePreToolUse('MCP:x', [])).toEqual({ output: null });
  });
});

describe('promptDecision', () => {
  it('blocks a block and a redact, notes the redact, and warns on a warn', () => {
    const block = promptDecision(result({ action: 'block', findings: [FINDING] as never }));
    expect(block.output?.continue).toBe(false);
    expect(block.output?.user_message).not.toContain(PROMPT_NO_REWRITE_NOTE);
    const redact = promptDecision(result({ action: 'redact', findings: [FINDING] as never }));
    expect(redact.output?.user_message).toContain(PROMPT_NO_REWRITE_NOTE);
    const warn = promptDecision(result({ action: 'warn', findings: [FINDING] as never }));
    expect(warn.output).toBeNull();
    expect(warn.notice).toContain(FINDING.ruleId);
  });

  it('says nothing for a clean prompt or a monitor finding', () => {
    expect(promptDecision(result({}))).toEqual({ output: null });
    expect(promptDecision(result({ action: 'allow', findings: [FINDING] as never }))).toEqual({
      output: null,
    });
  });
});

describe('responseNotice', () => {
  it('reports a block it could not carry out, and a partial scan', async () => {
    const outcome = await scanResponseFields('Shell', scannableFields('x'), () =>
      Promise.resolve(result({ action: 'block', findings: [FINDING] as never })),
    );
    expect(responseNotice(outcome)).toContain('reached the model unchanged');
    const timedOut = await scanResponseFields('Shell', scannableFields('x'), () =>
      Promise.resolve(result({ scanIncomplete: 'timeout' })),
    );
    expect(responseNotice(timedOut)).toContain('Shell result');
  });

  it('says nothing for a clean result', async () => {
    const outcome = await scanResponseFields('Shell', scannableFields('x'), () =>
      Promise.resolve(result({})),
    );
    expect(responseNotice(outcome)).toBeUndefined();
  });
});

describe('tool vocabulary', () => {
  it('classifies the file writers as code changes', () => {
    for (const tool of FILE_WRITERS) expect(callKind(tool)).toBe('code_change');
    expect(callKind('Shell')).toBe('tool_use');
  });

  it('recognises MCP tool names', () => {
    expect(isMcpTool('MCP:fetch')).toBe(true);
    expect(isMcpTool('mcp_fetch')).toBe(true);
    expect(isMcpTool('Shell')).toBe(false);
  });
});
