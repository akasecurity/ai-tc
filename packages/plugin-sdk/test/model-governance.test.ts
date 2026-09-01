import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  isModelProhibited,
  modelFromTranscript,
  normalizeModelId,
  prohibitedModelMessage,
  readSessionModel,
  recordSessionModel,
} from '../src/model-governance.ts';

// ONE temp root for the file, with a cheap subdirectory per test, rather than a
// mkdtemp + recursive remove around each one.
//
// These cases need an isolated marker file, not an isolated filesystem, and the
// difference is not free: this package also holds `runtime-isolation.test.ts`,
// whose ratio is a TIMING measurement taken while vitest runs other files in
// parallel. Two dozen recursive removes are slow enough on Windows to starve
// the worker thread that measurement depends on, which inflates the ratio and
// fails a guard this file has no business touching.
let root: string;
let dir: string;
let n = 0;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-model-gov-'));
});

beforeEach(() => {
  n += 1;
  dir = join(root, `t${String(n)}`);
  mkdirSync(dir, { recursive: true });
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
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

describe('modelFromTranscript reads only the tail', () => {
  // WHY THIS IS STRUCTURAL. The property is "bytes read is bounded by the
  // constant, not the file", and neither obvious behavioural form can state it
  // here: `vi.spyOn(fs, 'readSync')` is refused outright (an ESM namespace is
  // not configurable), and an elapsed-time bound on a large file is a statement
  // about the runner rather than about the code — the reading this repo has
  // already retracted twice elsewhere.
  //
  // So this reads the source. What that CAN see is the shape: a positional
  // `readSync` behind an `openSync`, and no whole-file read of the caller's
  // path. What it CANNOT see is whether the offsets are right — the correctness
  // cases above cover that, and this covers the cost they cannot.
  const SOURCE = readFileSync(new URL('../src/model-governance.ts', import.meta.url), 'utf8');

  it('seeks to the tail rather than reading the file and slicing', () => {
    expect(SOURCE).toContain('readSync(');
    expect(SOURCE).toContain('openSync(');
  });

  it('never whole-file-reads the path it was handed', () => {
    // `readFileSync(fd, …)` inside the small-file branch is fine and must stay
    // reachable — that is the file that IS its own tail. What must not come
    // back is a read of the PATH, which is the form that decodes everything
    // before it slices.
    expect(SOURCE).not.toMatch(/readFileSync\(\s*(transcriptPath|path)\b/u);
  });

  it('still answers correctly from a file far larger than the window', () => {
    // The behavioural half, and the control for the two above: a guard on
    // source text is worth nothing if the thing it describes stopped working.
    const big = join(dir, 'big-tail.jsonl');
    const filler = JSON.stringify({ type: 'user', text: 'x'.repeat(64 * 1024) });
    writeFileSync(
      big,
      [...Array<string>(64).fill(filler), assistantLine('claude-opus-5')].join('\n'),
    );
    expect(modelFromTranscript(big)).toBe('claude-opus-5');
  });
});
