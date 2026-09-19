// The pure half of the prompt hooks. Never imports the entry file —
// src/hooks/*.ts entries run main() on import and would hang collection.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { CaptureResult } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import {
  promptEmitPayload,
  promptPersist,
  readPromptCapture,
} from '../../src/hooks/user-prompt-payload.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, '..', 'fixtures');

function fixture(dir: string, name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(FIXTURES, dir, name), 'utf8')) as Record<string, unknown>;
}

type Outcome = Pick<CaptureResult, 'action' | 'findings'>;

function outcome(action: CaptureResult['action'], ruleIds: string[] = ['aws-access-key']): Outcome {
  return {
    action,
    findings: ruleIds.map((ruleId) => ({ ruleId })) as CaptureResult['findings'],
  };
}

describe('readPromptCapture', () => {
  it('reads the submitted prompt from the recorded CLI payload', () => {
    const capture = readPromptCapture(
      'userPromptSubmitted',
      fixture('cli', 'userPromptSubmitted.json'),
    );
    expect(capture).toEqual({ event: 'submitted', text: 'run the shell command: false' });
  });

  it('reads the submitted prompt from the provisional VS Code payload', () => {
    const capture = readPromptCapture(
      'UserPromptSubmit',
      fixture('vscode-provisional', 'UserPromptSubmit.json'),
    );
    expect(capture).toEqual({ event: 'submitted', text: 'run the shell command: false' });
  });

  /**
   * THE DISCRIMINATING CASE, and the reason the event name comes off argv.
   *
   * `userPromptTransformed` re-carries `prompt` alongside `transformedPrompt`,
   * so a reader that looked for `prompt` first would answer with the
   * untransformed text — scanning the user's words a second time and never
   * seeing the scaffolding the host wrapped around them, which is the only
   * text this event adds.
   */
  it('reads the TRANSFORMED text, not the prompt the same payload also carries', () => {
    const payload = fixture('cli', 'userPromptTransformed.json');
    const capture = readPromptCapture('userPromptTransformed', payload);

    expect(capture?.event).toBe('transformed');
    expect(capture?.text).toBe(payload.transformedPrompt);
    // The premise: this payload really does carry both, and they really differ.
    expect(payload.prompt).toBeTypeOf('string');
    expect(capture?.text).not.toBe(payload.prompt);
    expect(capture?.text).toContain(payload.prompt as string);
    expect(capture?.text).toContain('<system_reminder>');
  });

  it('answers nothing for an event that carries no prompt', () => {
    expect(readPromptCapture('preToolUse', fixture('cli', 'preToolUse.json'))).toBeUndefined();
  });

  it('answers nothing for an unrecognised argv token or an unparseable payload', () => {
    expect(readPromptCapture(undefined, { prompt: 'hi' })).toBeUndefined();
    expect(readPromptCapture('userPromptSubmitted', null)).toBeUndefined();
  });

  // An empty prompt is nothing to scan, and capturing it would put an empty
  // event in the corpus for every accidental Enter.
  it('answers nothing for an empty or non-string prompt', () => {
    expect(readPromptCapture('userPromptSubmitted', { prompt: '' })).toBeUndefined();
    expect(readPromptCapture('userPromptSubmitted', { prompt: 42 })).toBeUndefined();
  });
});

describe('promptPersist', () => {
  it('always records a submitted prompt', () => {
    expect(promptPersist('submitted')).toBe('always');
  });

  // The transformed text CONTAINS the submitted one verbatim, so persisting
  // both unconditionally would double-count every clean turn.
  it('records a transformed prompt only when it carries a finding', () => {
    expect(promptPersist('transformed')).toBe('with-findings');
  });
});

describe('promptEmitPayload', () => {
  it('says nothing when nothing was flagged', () => {
    expect(promptEmitPayload('submitted', outcome('log', []))).toBeUndefined();
    expect(promptEmitPayload('submitted', outcome('block', []))).toBeUndefined();
  });

  /**
   * THE ONE CLAIM THIS MODULE MUST NEVER MAKE. Neither host has an observed
   * prompt-stop channel, so a `block` policy has to be reported as what
   * really happened. A message that read as enforcement would leave the user
   * believing a prompt was stopped while it went to the model.
   */
  it('reports a block policy as flagged-and-sent, never as stopped', () => {
    const payload = promptEmitPayload('submitted', outcome('block'));
    const message = (payload as { systemMessage?: string }).systemMessage;
    expect(message).toBeDefined();
    expect(message).toContain('aws-access-key');
    expect(message).toContain('sent');
    expect(message).toContain('unchanged');
    // No decision key of EITHER dialect: this is a note, not a verdict. Both
    // are checked because a payload shaped for the wrong host is ignored
    // silently rather than refused, so neither absence implies the other.
    expect(payload).not.toHaveProperty('decision');
    expect(payload).not.toHaveProperty('permissionDecision');
    expect(payload).not.toHaveProperty('hookSpecificOutput');
    expect(payload).not.toHaveProperty('modifiedArgs');
  });

  it('reports a redact policy the same way — there is no rewrite channel either', () => {
    expect(promptEmitPayload('submitted', outcome('redact'))).toEqual(
      promptEmitPayload('submitted', outcome('block')),
    );
  });

  /**
   * A warn and a block must not read alike. A user whose policy says block
   * has to be able to tell from the message that it did not take effect
   * here, which is the whole reason the two branches exist.
   */
  it('words a warn differently from a block', () => {
    const warned = (promptEmitPayload('submitted', outcome('warn')) as { systemMessage?: string })
      .systemMessage;
    const blocked = (promptEmitPayload('submitted', outcome('block')) as { systemMessage?: string })
      .systemMessage;
    expect(warned).toBeDefined();
    expect(warned).not.toBe(blocked);
    expect(warned).toContain('aws-access-key');
    // Only the block branch explains that a stop was asked for and not done.
    expect(blocked).toContain('no confirmed way to stop');
    expect(warned).not.toContain('no confirmed way to stop');
  });

  it('says nothing for a monitor-only outcome', () => {
    expect(promptEmitPayload('submitted', outcome('log'))).toBeUndefined();
  });

  // The submitted event owns the user-facing message; the transformed one
  // fires milliseconds later for the same turn and carries the same words.
  it('never speaks for the transformed event, at any action', () => {
    for (const action of ['block', 'redact', 'warn', 'log'] as const) {
      expect(promptEmitPayload('transformed', outcome(action))).toBeUndefined();
    }
  });
});
