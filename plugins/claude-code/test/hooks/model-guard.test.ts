import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { recordSessionModel } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  decidePreModelSwitch,
  decideProhibitedModelTurn,
  resolveSessionModel,
} from '../../src/hooks/model-guard.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-model-guard-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('decidePreModelSwitch', () => {
  it('denies a switch onto a prohibited model, in PreModelSwitch vocabulary', () => {
    // The shape is the substantive claim, not the denial: PreToolUse's
    // `hookSpecificOutput` is structurally identical apart from
    // `hookEventName`, and the host honors only the one naming its own event —
    // so a borrowed shape emits valid JSON and silently allows.
    const output = decidePreModelSwitch('claude-opus-5', ['claude-opus-5']);
    expect(output?.hookSpecificOutput.hookEventName).toBe('PreModelSwitch');
    expect(output?.hookSpecificOutput.permissionDecision).toBe('deny');
    expect(output?.hookSpecificOutput.permissionDecisionReason).toContain('claude-opus-5');
  });

  it('denies a dated build of a prohibited base model', () => {
    expect(decidePreModelSwitch('claude-haiku-4-5-20251001', ['claude-haiku-4-5'])).not.toBeNull();
  });

  it.each([
    ['an approved model', 'claude-sonnet-4-5', ['claude-opus-5']],
    ['no target model', undefined, ['claude-opus-5']],
    ['no prohibition list', 'claude-opus-5', undefined],
    ['an empty prohibition list', 'claude-opus-5', []],
  ])('has no opinion on %s', (_label, model, prohibited) => {
    expect(decidePreModelSwitch(model, prohibited)).toBeNull();
  });
});

describe('decideProhibitedModelTurn', () => {
  it('blocks the turn with UserPromptSubmit\'s own top-level shape', () => {
    // Deliberately NOT `hookSpecificOutput` — the sibling decision above uses
    // that, and the two hooks read different fields.
    const output = decideProhibitedModelTurn('claude-opus-5', ['claude-opus-5']);
    expect(output?.decision).toBe('block');
    expect(output?.reason).toContain('claude-opus-5');
    expect(Object.keys(output ?? {}).sort()).toEqual(['decision', 'reason']);
  });

  it.each([
    ['an approved model', 'claude-sonnet-4-5', ['claude-opus-5']],
    ['an unresolvable model', undefined, ['claude-opus-5']],
    ['no prohibition list', 'claude-opus-5', undefined],
  ])('allows a turn on %s', (_label, model, prohibited) => {
    expect(decideProhibitedModelTurn(model, prohibited)).toBeNull();
  });
});

describe('resolveSessionModel', () => {
  it('prefers the recorded marker over the transcript', () => {
    // The marker is written by the model-switch hooks at the moment the model
    // changes, so it is newer than anything the transcript can show.
    const transcript = join(dir, 't.jsonl');
    writeFileSync(
      transcript,
      JSON.stringify({ type: 'assistant', message: { model: 'claude-haiku-4-5' } }),
    );
    recordSessionModel(dir, 's1', 'claude-opus-5');
    expect(resolveSessionModel(dir, 's1', transcript)).toBe('claude-opus-5');
  });

  it('falls back to the transcript when no marker covers this session', () => {
    const transcript = join(dir, 't.jsonl');
    writeFileSync(
      transcript,
      JSON.stringify({ type: 'assistant', message: { model: 'claude-haiku-4-5' } }),
    );
    recordSessionModel(dir, 'other-session', 'claude-opus-5');
    expect(resolveSessionModel(dir, 's1', transcript)).toBe('claude-haiku-4-5');
  });

  it('returns undefined when neither source can answer', () => {
    // The known hole, pinned rather than glossed: the first turn of a session
    // that started on a prohibited model without SessionStart announcing it has
    // no marker and no assistant record, and is therefore ALLOWED.
    expect(resolveSessionModel(dir, 's1', join(dir, 'missing.jsonl'))).toBeUndefined();
  });
});
