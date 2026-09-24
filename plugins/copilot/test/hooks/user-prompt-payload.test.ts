// The pure half of the prompt hook. Never imports the entry file — src/hooks/*
// entries run their body on import and would hang collection.
//
// Every payload is a RECORDED fixture. The two CLI prompt fixtures are what
// make the double-count argument checkable rather than quoted, so they are
// driven directly.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { BlockedDetectionRef, CaptureResult } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import {
  promptDecision,
  promptPersist,
  readPromptCapture,
} from '../../src/hooks/user-prompt-payload.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, '..', 'fixtures');

function fixture(dir: string, name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(FIXTURES, dir, name), 'utf8')) as Record<string, unknown>;
}

// High-entropy and deliberately NOT credential-shaped — this repository is
// public, and a run-by-run absence check only needs entropy, not a real format.
const RAW = 'Zq7Z4LmT2pW9xR5vKd8Nc1Hb6Ya3Ue0Ij';

function findings(...ruleIds: string[]): CaptureResult['findings'] {
  return ruleIds.map((ruleId) => ({
    ruleId,
    category: 'secret',
    severity: 'high',
    maskedMatch: 'Z***j',
    confidence: 'high',
  })) as unknown as CaptureResult['findings'];
}

const REF: BlockedDetectionRef = {
  reference: 'aka-ref-0001',
  maskedValue: 'Z***j',
} as unknown as BlockedDetectionRef;

describe('readPromptCapture', () => {
  it('reads the submitted prompt off the recorded CLI payload', () => {
    expect(
      readPromptCapture('userPromptSubmitted', fixture('cli', 'userPromptSubmitted.json')),
    ).toEqual({ event: 'submitted', text: 'run the shell command: false' });
  });

  it('reads the same field off the provisional VS Code payload', () => {
    expect(
      readPromptCapture('UserPromptSubmit', fixture('vscode-provisional', 'UserPromptSubmit.json')),
    ).toEqual({ event: 'submitted', text: 'run the shell command: false' });
  });

  // THE DISCRIMINATING CASE, and the reason `userPromptTransformed` is not
  // registered in hooks.json: its payload re-carries `prompt` VERBATIM, so a
  // reader keyed on the payload's fields rather than on the argv event name
  // would scan the user's own words twice and never see the scaffolding — and
  // registering both events would record every prompt twice.
  it('the transformed payload re-carries the submitted prompt verbatim', () => {
    const submitted = fixture('cli', 'userPromptSubmitted.json');
    const transformed = fixture('cli', 'userPromptTransformed.json');
    expect(transformed.prompt).toBe(submitted.prompt);
    // …and the transformed text is a strict superset of it, which is what makes
    // reading the scaffolding worth anything at all.
    expect(String(transformed.transformedPrompt)).toContain(String(submitted.prompt));
    expect(String(transformed.transformedPrompt)).toContain('<system_reminder>');
  });

  it('reads the TRANSFORMED field for the transformed event, not the untransformed one', () => {
    const payload = fixture('cli', 'userPromptTransformed.json');
    const capture = readPromptCapture('userPromptTransformed', payload);
    expect(capture?.event).toBe('transformed');
    expect(capture?.text).toBe(payload.transformedPrompt);
    expect(capture?.text).not.toBe(payload.prompt);
  });

  it('answers undefined for an event with no prompt field, a null payload, or no event', () => {
    expect(
      readPromptCapture('preToolUse', fixture('cli', 'userPromptSubmitted.json')),
    ).toBeUndefined();
    expect(readPromptCapture('userPromptSubmitted', null)).toBeUndefined();
    expect(
      readPromptCapture(undefined, fixture('cli', 'userPromptSubmitted.json')),
    ).toBeUndefined();
  });

  it('answers undefined for an empty prompt, which is nothing to scan', () => {
    expect(readPromptCapture('userPromptSubmitted', { prompt: '' })).toBeUndefined();
    expect(readPromptCapture('userPromptSubmitted', { prompt: 42 })).toBeUndefined();
  });
});

describe('promptPersist', () => {
  it('always records a submitted prompt — it is the corpus every surface reads', () => {
    expect(promptPersist('submitted')).toBe('always');
  });

  it('records a transformed prompt only with findings, so a clean turn is not doubled', () => {
    expect(promptPersist('transformed')).toBe('with-findings');
  });
});

describe('promptDecision', () => {
  it('says nothing on a clean scan, on either dialect', () => {
    for (const dialect of ['cli', 'vscode'] as const) {
      expect(promptDecision('submitted', dialect, { action: 'log', findings: [] })).toEqual({
        output: null,
      });
    }
  });

  it('says nothing for the transformed event even with findings', () => {
    // The submitted event owns the user-facing message, and the user's own
    // words are inside both — a second copy for the same secret is noise.
    expect(
      promptDecision('transformed', 'vscode', { action: 'block', findings: findings('r1') }),
    ).toEqual({ output: null });
  });

  // THE TWO-CHANNEL SPLIT. On the CLI `systemMessage` is not an output field on
  // this event, so a message put on stdout is dropped and the user is told
  // nothing; it comes back as `notice` for stderr instead. Both halves are
  // asserted, because a decision that returned the same object for both
  // dialects would pass either one alone.
  it('routes the CLI message to stderr and the VS Code one to stdout', () => {
    const result = { action: 'warn' as const, findings: findings('generic.secret') };
    const cli = promptDecision('submitted', 'cli', result);
    const vscode = promptDecision('submitted', 'vscode', result);

    expect(cli.output).toBeNull();
    expect(cli.notice).toContain('generic.secret');

    expect(cli.notice).toBe((vscode.output as { systemMessage: string } | null)?.systemMessage);
    expect(vscode.notice).toBeUndefined();
  });

  // A block or redact policy did NOT take effect here, and the sentence has to
  // say so — the whole reason this path takes `rewritable: false`.
  it.each(['block', 'redact'] as const)(
    'reports a %s policy as recorded-and-sent-unchanged, never as stopped',
    (action) => {
      const { notice } = promptDecision('submitted', 'cli', {
        action,
        findings: findings('generic.secret'),
        blockedReferences: [REF],
      });
      expect(notice).toBeDefined();
      expect(notice).toContain('sent');
      expect(notice).toContain('unchanged');
      // The claims this surface cannot make. A wording change that introduced
      // one would be an enforcement claim the host silently ignores.
      expect(notice).not.toMatch(/\bblocked\b/iu);
      expect(notice).not.toMatch(/\bredacted\b/iu);
      expect(notice).not.toMatch(/did not reach|never reached|withheld/iu);
      // The exception pointer still rides along, so a user who meant it can act.
      expect(notice).toContain('aka exception approve aka-ref-0001');
    },
  );

  it('reads differently from a warn, so a user can tell their policy did not apply', () => {
    const blocked = promptDecision('submitted', 'cli', {
      action: 'block',
      findings: findings('r1'),
    }).notice;
    const warned = promptDecision('submitted', 'cli', {
      action: 'warn',
      findings: findings('r1'),
    }).notice;
    expect(blocked).toBeDefined();
    expect(warned).toBeDefined();
    expect(blocked).not.toBe(warned);
  });

  it('says nothing for an action with no message, even when findings exist', () => {
    // `log` and `allow` record without telling the user anything: there is no
    // policy outcome to report, so stdout and stderr both stay empty.
    for (const action of ['log', 'allow'] as const) {
      expect(promptDecision('submitted', 'cli', { action, findings: findings('r1') })).toEqual({
        output: null,
      });
    }
  });

  // Run by run, on every message this module can build. The findings carry a
  // masked preview and never the raw value, so nothing here should be able to
  // reach it — which is exactly the kind of claim that stops being true when
  // somebody adds "the offending value was: …" to help a user find it.
  it.each(['block', 'redact', 'warn'] as const)(
    'echoes no run of the raw value on %s',
    (action) => {
      for (const dialect of ['cli', 'vscode'] as const) {
        const decision = promptDecision('submitted', dialect, {
          action,
          findings: findings('generic.secret'),
          blockedReferences: [REF],
        });
        const text =
          decision.notice ?? (decision.output as { systemMessage: string } | null)?.systemMessage;
        // The positive control: without it every absence check below is satisfied
        // by a decision that said nothing at all.
        expect(text).toContain('generic.secret');
        expectNoEchoOf(text, RAW);
      }
    },
  );
});
