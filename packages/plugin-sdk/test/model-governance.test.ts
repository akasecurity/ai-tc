import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  buildModelRefusalEvent,
  claudeCodeModelFromRecord,
  codexModelFromRecord,
  decideProhibitedModelTurn,
  isModelProhibited,
  matchProhibitedSpawnModel,
  modelFromTranscript,
  modelFromTranscriptTail,
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

describe('modelFromTranscriptTail with a per-harness extractor', () => {
  it('reads the Codex rollout shape: model on a turn_context payload', () => {
    // Codex names the model per TURN, not per response, so there is no
    // assistant record to read and the Claude Code extractor finds nothing in
    // the same file.
    const path = join(dir, 'rollout.jsonl');
    writeFileSync(
      path,
      [
        JSON.stringify({ type: 'turn_context', payload: { model: 'gpt-4o' } }),
        JSON.stringify({ type: 'event_msg', payload: { type: 'token_count' } }),
        JSON.stringify({ type: 'turn_context', payload: { model: 'o3' } }),
      ].join('\n'),
    );
    expect(modelFromTranscriptTail(path, codexModelFromRecord)).toBe('o3');
    expect(modelFromTranscriptTail(path, claudeCodeModelFromRecord)).toBeUndefined();
  });

  it('keeps each extractor blind to the other harness’s records', () => {
    // The control for the pair above: an extractor that matched any `model` key
    // anywhere would pass both directions and silently read a foreign shape.
    const path = join(dir, 'cc.jsonl');
    writeFileSync(path, assistantLine('claude-opus-5'));
    expect(modelFromTranscriptTail(path, claudeCodeModelFromRecord)).toBe('claude-opus-5');
    expect(modelFromTranscriptTail(path, codexModelFromRecord)).toBeUndefined();
  });

  it('ignores a record whose model is absent or not a string', () => {
    const path = join(dir, 'bad.jsonl');
    writeFileSync(
      path,
      [
        JSON.stringify({ type: 'turn_context', payload: { model: 'o3' } }),
        JSON.stringify({ type: 'turn_context', payload: { model: 42 } }),
        JSON.stringify({ type: 'turn_context', payload: {} }),
      ].join('\n'),
    );
    // Scanning is newest-first, so the two unusable records are skipped rather
    // than ending the scan at the newest line.
    expect(modelFromTranscriptTail(path, codexModelFromRecord)).toBe('o3');
  });
});

describe('decideProhibitedModelTurn', () => {
  // Hoisted here from the two plugins, which held byte-identical copies. The
  // decision is not harness-specific — both hosts spell a blocked prompt the
  // same way — and two copies of one decision drift on exactly what they share.
  it("blocks with the hosts' shared top-level shape", () => {
    const output = decideProhibitedModelTurn('claude-opus-5', ['claude-opus-5']);
    expect(output?.decision).toBe('block');
    expect(output?.reason).toContain('claude-opus-5');
    expect(Object.keys(output ?? {}).sort()).toEqual(['decision', 'reason']);
  });

  it.each([
    ['an approved model', 'claude-sonnet-5', ['claude-opus-5']],
    ['an unresolvable model', undefined, ['claude-opus-5']],
    ['no prohibition list', 'claude-opus-5', undefined],
    ['an empty prohibition list', 'claude-opus-5', []],
  ])('allows a turn on %s', (_label, model, prohibited) => {
    expect(decideProhibitedModelTurn(model, prohibited)).toBeNull();
  });
});

describe('buildModelRefusalEvent', () => {
  const base = {
    id: 'evt-1',
    sessionId: 's1',
    model: 'claude-opus-5',
    seam: 'switch' as const,
    sourceTool: 'claude-code',
    occurredAt: '2026-09-02T10:30:00.000Z',
  };

  it('carries the model, the seam and the session, and nothing the user typed', () => {
    const event = buildModelRefusalEvent(base);
    expect(event.eventType).toBe('model_refusal');
    expect(event.rootSessionId).toBe('s1');
    expect(event.attributes).toEqual({
      model: 'claude-opus-5',
      refusal_seam: 'switch',
      source_tool: 'claude-code',
    });
  });

  it('has NO content field at all, not merely an empty one', () => {
    // The property that keeps prompt text from creeping in later: there is no
    // field for it. An empty string would be a slot someone fills.
    expect(Object.keys(buildModelRefusalEvent(base))).not.toContain('content');
    expect(Object.keys(buildModelRefusalEvent(base))).not.toContain('contentHash');
  });

  it('OMITS rootSessionId when the session is unknown, rather than nulling it', () => {
    // `root_session_id` is a self-FK: an id naming no row fails the insert, and
    // an explicit null would be a different (allowed) statement than omission.
    const event = buildModelRefusalEvent({ ...base, sessionId: undefined });
    expect('rootSessionId' in event).toBe(false);
  });

  it('records the turn seam distinctly from the switch seam', () => {
    expect(buildModelRefusalEvent({ ...base, seam: 'turn' }).attributes.refusal_seam).toBe('turn');
  });
});

// A subagent spawn names its model in a vocabulary nothing else here speaks,
// and — unlike the switch and turn seams — the string is CALLER-CHOSEN rather
// than read from a marker or a transcript. So the exactness argument that makes
// `normalizeModelId` safe elsewhere does not carry here: every spelling that
// names a prohibited build without being its id is a bypass.
describe('matchProhibitedSpawnModel', () => {
  const PROHIBITED = ['claude-opus-5'];

  it('returns the MATCHED id, not a boolean and not the caller string', () => {
    // The audit row is keyed on it: recording the caller's spelling would file
    // every spawn refusal under a string no prohibition list contains.
    expect(matchProhibitedSpawnModel('opus', PROHIBITED)).toBe('claude-opus-5');
    expect(matchProhibitedSpawnModel('claude-opus-5', PROHIBITED)).toBe('claude-opus-5');
  });

  it.each([
    ['an exact id', 'claude-opus-5'],
    ['casing and whitespace', '  CLAUDE-OPUS-5 '],
    ['a dated build of a bare listing', 'claude-opus-5-20250805'],
    ['the bare tier word', 'opus'],
    ['a 1M-context variant', 'claude-opus-5[1m]'],
    ['a floating alias', 'claude-opus-5-latest'],
    ['a Bedrock-decorated spelling', 'us.anthropic.claude-opus-5-v1:0'],
    ['a Vertex-decorated spelling', 'claude-opus-5@20250805'],
  ])('catches %s', (_label, requested) => {
    expect(matchProhibitedSpawnModel(requested, PROHIBITED)).toBe('claude-opus-5');
  });

  it('derives the tier word from the prohibition list, not from a fixed set', () => {
    // The list this replaced named opus/sonnet/haiku from memory and the
    // harness had already added a fourth. A hardcoded harness vocabulary drifts
    // toward ALLOW and is invisible when it drifts — the same failure as the
    // Task/Agent rename. Deriving it covers a tier that does not exist yet.
    expect(matchProhibitedSpawnModel('fable', ['claude-fable-1'])).toBe('claude-fable-1');
    expect(matchProhibitedSpawnModel('haiku', ['claude-haiku-4-5-20251001'])).toBe(
      'claude-haiku-4-5-20251001',
    );
  });

  it('scans EVERY occurrence, not just the first', () => {
    // `indexOf` stops at the first hit. Here the first sits inside a longer
    // token (no boundary) and the second is a real one, so stopping early
    // reports no match and a crafted spelling becomes an allow. The
    // `claude-opus-45` case below passes either way and cannot catch this.
    expect(matchProhibitedSpawnModel('claude-opus-51-claude-opus-5', PROHIBITED)).toBe(
      'claude-opus-5',
    );
  });

  it('does not let one id swallow a longer one at a non-boundary', () => {
    // The boundary is what keeps the containment rule from over-reaching:
    // `claude-opus-45` merely starts with `claude-opus-4`.
    expect(matchProhibitedSpawnModel('claude-opus-45', ['claude-opus-4'])).toBeUndefined();
  });

  it('allows the inherit words — the parent model is already vetted', () => {
    expect(matchProhibitedSpawnModel('inherit', PROHIBITED)).toBeUndefined();
    expect(matchProhibitedSpawnModel('default', PROHIBITED)).toBeUndefined();
  });

  it.each([
    ['an empty request', '', PROHIBITED],
    ['an unrelated id', 'claude-sonnet-5', PROHIBITED],
    ['an unrelated tier', 'haiku', PROHIBITED],
    ['no prohibition list', 'opus', undefined],
    ['an empty prohibition list', 'opus', []],
  ])('allows on %s — knowledge, never ignorance', (_label, requested, prohibited) => {
    expect(matchProhibitedSpawnModel(requested, prohibited)).toBeUndefined();
  });
});

describe('buildModelRefusalEvent carries the caller spelling beside the id', () => {
  it('records requested_model when the two differ', () => {
    const event = buildModelRefusalEvent({
      id: 'e1',
      sessionId: 's1',
      model: 'claude-opus-5',
      requestedModel: 'opus',
      seam: 'spawn',
      sourceTool: 'claude-code',
      occurredAt: '2026-09-02T00:00:00.000Z',
    });
    expect(event.attributes).toMatchObject({
      model: 'claude-opus-5',
      requested_model: 'opus',
      refusal_seam: 'spawn',
    });
  });

  it('omits it when the caller named the id itself', () => {
    // Not duplicated: a row carrying the same string twice reads as two facts.
    const event = buildModelRefusalEvent({
      id: 'e1',
      sessionId: 's1',
      model: 'claude-opus-5',
      requestedModel: 'claude-opus-5',
      seam: 'spawn',
      sourceTool: 'claude-code',
      occurredAt: '2026-09-02T00:00:00.000Z',
    });
    expect(event.attributes).not.toHaveProperty('requested_model');
  });
});

describe('prohibitedModelMessage names the right remedy per seam', () => {
  it('sends a spawn refusal to the subagent argument, not to /model', () => {
    // A spawn is refused on an argument the caller chose, so pointing them at
    // /model would name a control that cannot fix it.
    const message = prohibitedModelMessage('sonnet', 'spawn');
    expect(message).toContain('Cannot start a subagent on sonnet');
    expect(message).toContain('Name an approved model on the subagent');
    expect(message).not.toContain('/model');
  });

  it('still sends switch and turn refusals to /model', () => {
    expect(prohibitedModelMessage('claude-sonnet-5', 'switch')).toContain('/model');
    expect(prohibitedModelMessage('claude-sonnet-5', 'turn')).toContain('/model');
  });
});
