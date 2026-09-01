import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  isModelProhibited,
  modelFromTranscript,
  normalizeModelId,
  prohibitedModelMessage,
  readSessionModel,
  recordSessionModel,
} from '../src/model-governance.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-model-gov-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

/** One transcript line, in the shape the harness really writes. */
function assistantLine(model: string): string {
  return JSON.stringify({ type: 'assistant', message: { model, role: 'assistant' } });
}

describe('normalizeModelId', () => {
  it('lowercases and strips a dated release suffix', () => {
    expect(normalizeModelId('Claude-Haiku-4-5-20251001')).toBe('claude-haiku-4-5');
    expect(normalizeModelId('  claude-opus-5  ')).toBe('claude-opus-5');
  });

  it('strips only an anchored eight-digit suffix, so near-miss ids stay distinct', () => {
    // The whole risk of normalizing: two genuinely different models must not
    // collapse onto each other and make a prohibition over-reach.
    expect(normalizeModelId('claude-opus-4')).not.toBe(normalizeModelId('claude-opus-45'));
    expect(normalizeModelId('gpt-4-1234567')).toBe('gpt-4-1234567');
    expect(normalizeModelId('gpt-4-123456789')).toBe('gpt-4-123456789');
  });
});

describe('isModelProhibited', () => {
  it('matches an exact id, and a dated build of a prohibited base', () => {
    expect(isModelProhibited('claude-opus-5', ['claude-opus-5'])).toBe(true);
    expect(isModelProhibited('claude-haiku-4-5-20251001', ['claude-haiku-4-5'])).toBe(true);
    expect(isModelProhibited('claude-haiku-4-5', ['claude-haiku-4-5-20251001'])).toBe(true);
  });

  it('does not match a model that is merely similar', () => {
    expect(isModelProhibited('claude-opus-5', ['claude-opus-4'])).toBe(false);
    expect(isModelProhibited('claude-opus-45', ['claude-opus-4'])).toBe(false);
  });

  // The chosen posture, and the property the whole feature rests on: this
  // control refuses on knowledge and never on ignorance. Each row below is a
  // way of not knowing.
  it.each([
    ['an unresolvable model', undefined, ['claude-opus-5']],
    ['an empty model', '', ['claude-opus-5']],
    ['no prohibition list', 'claude-opus-5', undefined],
    ['an empty prohibition list', 'claude-opus-5', []],
  ])('allows on %s', (_label, model, prohibited) => {
    expect(isModelProhibited(model, prohibited)).toBe(false);
  });
});

describe('recordSessionModel / readSessionModel', () => {
  it('round-trips the model for the session that recorded it', () => {
    recordSessionModel(dir, 's1', 'claude-opus-5');
    expect(readSessionModel(dir, 's1')).toBe('claude-opus-5');
  });

  it('refuses a marker belonging to a DIFFERENT session', () => {
    // The isolation that makes a clobbered marker degrade to "unknown" rather
    // than to blocking a session on another session's model.
    recordSessionModel(dir, 's1', 'claude-opus-5');
    expect(readSessionModel(dir, 's2')).toBeUndefined();
  });

  it('overwrites rather than accumulating, so the newest switch wins', () => {
    recordSessionModel(dir, 's1', 'claude-opus-5');
    recordSessionModel(dir, 's1', 'claude-haiku-4-5');
    expect(readSessionModel(dir, 's1')).toBe('claude-haiku-4-5');
  });

  it('records nothing when either the session or the model is unknown', () => {
    recordSessionModel(dir, undefined, 'claude-opus-5');
    recordSessionModel(dir, 's1', undefined);
    expect(readSessionModel(dir, 's1')).toBeUndefined();
  });

  it('reads a torn or absent marker as unknown', () => {
    expect(readSessionModel(dir, 's1')).toBeUndefined();
    writeFileSync(join(dir, 'session-model'), '{"sessionId":"s1","mod');
    expect(readSessionModel(dir, 's1')).toBeUndefined();
  });
});

describe('modelFromTranscript', () => {
  it('returns the model of the LATEST assistant record', () => {
    // A mid-session /model switch means only the newest record is current.
    const path = join(dir, 't.jsonl');
    writeFileSync(
      path,
      [
        assistantLine('claude-haiku-4-5'),
        JSON.stringify({ type: 'user', message: { role: 'user' } }),
        assistantLine('claude-opus-5'),
      ].join('\n'),
    );
    expect(modelFromTranscript(path)).toBe('claude-opus-5');
  });

  it('survives a transcript larger than the tail it reads', () => {
    const path = join(dir, 'big.jsonl');
    const filler = JSON.stringify({ type: 'user', text: 'x'.repeat(4096) });
    writeFileSync(
      path,
      [...Array<string>(200).fill(filler), assistantLine('claude-opus-5')].join('\n'),
    );
    expect(modelFromTranscript(path)).toBe('claude-opus-5');
  });

  it('reads a single-record transcript, which the tail slice must not drop', () => {
    const path = join(dir, 'one.jsonl');
    writeFileSync(path, assistantLine('claude-opus-5'));
    expect(modelFromTranscript(path)).toBe('claude-opus-5');
  });

  it.each([
    ['an absent path', () => join(dir, 'missing.jsonl')],
    [
      'a transcript with no assistant record',
      () => {
        const p = join(dir, 'none.jsonl');
        writeFileSync(p, JSON.stringify({ type: 'user', message: { role: 'user' } }));
        return p;
      },
    ],
    [
      'unparseable lines',
      () => {
        const p = join(dir, 'junk.jsonl');
        writeFileSync(p, 'not json\n{oops');
        return p;
      },
    ],
  ])('returns undefined for %s', (_label, make) => {
    expect(modelFromTranscript(make())).toBeUndefined();
  });

  it('returns undefined when no path is given', () => {
    expect(modelFromTranscript(undefined)).toBeUndefined();
  });
});

describe('prohibitedModelMessage', () => {
  it('names the model, the remedy, and never claims the call was intercepted', () => {
    for (const action of ['switch', 'turn'] as const) {
      const message = prohibitedModelMessage('claude-opus-5', action);
      expect(message).toContain('claude-opus-5');
      expect(message).toContain('/model');
      // Nothing here sits in the network path; saying otherwise would overstate
      // the control, which is the product claim this feature must not make.
      expect(message).not.toMatch(/proxy|intercept|network|blocked the (call|request)/iu);
    }
  });
});
