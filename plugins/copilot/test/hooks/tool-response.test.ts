// The tool-result reader. Driven from the RECORDED `cli/postToolUse.json` and
// the provisional `vscode-provisional/PostToolUse.json`, never from literals
// written to match the table.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  responseKey,
  RESULT_WALK_MAX_DEPTH,
  RESULT_WALK_MAX_LEAF_CHARS,
  RESULT_WALK_MAX_LEAVES,
  RESULT_WALK_MAX_TOTAL_CHARS,
  scannableResponseFields,
} from '../../src/hooks/tool-response.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, '..', 'fixtures');
const SOURCE_PATH = join(HERE, '..', '..', 'src', 'hooks', 'tool-response.ts');

function fixture(dir: string, name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(FIXTURES, dir, name), 'utf8')) as Record<string, unknown>;
}

describe('responseKey', () => {
  it('names the key each dialect actually sends', () => {
    // Read off the fixtures rather than restated, so a host that renamed its
    // envelope reddens here instead of silently scanning nothing.
    expect(fixture('cli', 'postToolUse.json')).toHaveProperty(responseKey('cli'));
    expect(fixture('vscode-provisional', 'PostToolUse.json')).toHaveProperty(responseKey('vscode'));
    // …and the two keys are genuinely different, which is what makes the pair
    // of tables load-bearing rather than duplication.
    expect(responseKey('cli')).not.toBe(responseKey('vscode'));
  });
});

const NOTHING = { fields: [], truncated: false };

describe('scannableResponseFields', () => {
  it('reads the model-visible text out of the recorded CLI envelope', () => {
    const payload = fixture('cli', 'postToolUse.json');
    const fields = scannableResponseFields('cli', payload[responseKey('cli')]);
    expect(fields).toEqual({
      fields: [{ path: ['textResultForLlm'], text: '\n<shellId: 0 completed with exit code 1>' }],
      truncated: false,
    });
  });

  it('reads the whole string out of the provisional VS Code envelope', () => {
    const payload = fixture('vscode-provisional', 'PostToolUse.json');
    const fields = scannableResponseFields('vscode', payload[responseKey('vscode')]);
    expect(fields).toEqual({
      fields: [{ path: [], text: '\n<shellId: 0 completed with exit code 1>' }],
      truncated: false,
    });
  });

  // THE TRAP. `resultType` reports whether the INVOCATION succeeded, not
  // whether the command exited zero — the recorded fixture runs `false` and
  // still reports "success", with the real exit code only as free text inside
  // the result. A module that branched on it would be wrong on every failing
  // command and would look right, because a failing command should be scanned
  // exactly like a succeeding one.
  it('the recorded fixture proves resultType is not an exit status', () => {
    const result = fixture('cli', 'postToolUse.json')[responseKey('cli')] as Record<
      string,
      unknown
    >;
    expect(fixture('cli', 'postToolUse.json').toolArgs).toMatchObject({ command: 'false' });
    expect(result.resultType).toBe('success');
    expect(String(result.textResultForLlm)).toContain('exit code 1');
  });

  it('never reads resultType — pinned over the comment-stripped source', () => {
    // Comment-stripped, because the module comment above discusses `resultType`
    // at length: a plain text match would be satisfied by the explanation of
    // why the field is not read.
    const source = readFileSync(SOURCE_PATH, 'utf8')
      .replaceAll(/\/\*[\s\S]*?\*\//gu, '')
      .replaceAll(/\/\/.*$/gmu, '');
    expect(source).not.toContain('resultType');
    // The positive control: an emptied file would pass the line above.
    expect(source).toContain('textResultForLlm');
    expect(source).toContain('export function scannableResponseFields');
  });

  it('exports no writer, because no result-rewrite channel is confirmed', async () => {
    // `postToolUse.modifiedResult` is under "Not measured" in
    // test/fixtures/cli/README.md. A path-based replace here would have exactly
    // one use — building a rewrite the host may ignore — and recording a
    // withhold for it would let the audit trail claim a redaction that never
    // happened. Asserted rather than left to review, so adding one is a
    // deliberate act that comes with a recording.
    const module: Record<string, unknown> = await import('../../src/hooks/tool-response.ts');
    expect(Object.keys(module).sort()).toEqual([
      'RESULT_WALK_MAX_DEPTH',
      'RESULT_WALK_MAX_LEAF_CHARS',
      'RESULT_WALK_MAX_LEAVES',
      'RESULT_WALK_MAX_TOTAL_CHARS',
      'responseKey',
      'scannableResponseFields',
    ]);
  });

  it('handles a bare string result whatever the dialect says', () => {
    // A host that simplified its envelope must not make this scan nothing and
    // report success — the failure mode the whole adapter is shaped against.
    expect(scannableResponseFields('cli', 'plain text').fields).toEqual([
      { path: [], text: 'plain text' },
    ]);
  });

  it('skips an empty result, which has nothing in it to find', () => {
    expect(scannableResponseFields('cli', '')).toEqual(NOTHING);
    expect(scannableResponseFields('cli', { textResultForLlm: '' })).toEqual(NOTHING);
    expect(scannableResponseFields('vscode', '')).toEqual(NOTHING);
    expect(scannableResponseFields('vscode', { a: '', b: [''] })).toEqual(NOTHING);
  });

  it('skips a result that carries no text anywhere', () => {
    expect(scannableResponseFields('cli', { textResultForLlm: 42 })).toEqual(NOTHING);
    expect(scannableResponseFields('cli', { resultType: 7, ok: true })).toEqual(NOTHING);
    expect(scannableResponseFields('cli', null)).toEqual(NOTHING);
    expect(scannableResponseFields('cli', undefined)).toEqual(NOTHING);
    expect(scannableResponseFields('vscode', null)).toEqual(NOTHING);
    expect(scannableResponseFields('vscode', 42)).toEqual(NOTHING);
  });

  // A CLI result that does not carry the recorded text field is a changed
  // envelope or a structured result. Either way it reaches the model, so its
  // string leaves are walked rather than skipped in silence.
  it('walks a CLI result that does not carry textResultForLlm', () => {
    expect(scannableResponseFields('cli', { output: 'text under another key' })).toEqual({
      fields: [{ path: ['output'], text: 'text under another key' }],
      truncated: false,
    });
    expect(
      scannableResponseFields('cli', { textResultForLlm: { nested: 'moved one level down' } }),
    ).toEqual({
      fields: [{ path: ['textResultForLlm', 'nested'], text: 'moved one level down' }],
      truncated: false,
    });
    expect(scannableResponseFields('cli', ['a', { b: 'c' }]).fields).toEqual([
      { path: ['0'], text: 'a' },
      { path: ['1', 'b'], text: 'c' },
    ]);
  });

  it('reads only textResultForLlm when the CLI result carries it as a string', () => {
    // The recorded envelope: `resultType` beside the text is not scanned.
    expect(
      scannableResponseFields('cli', { resultType: 'success', textResultForLlm: 'the text' }),
    ).toEqual({ fields: [{ path: ['textResultForLlm'], text: 'the text' }], truncated: false });
    // The control: without the text field, the same sibling IS read.
    expect(scannableResponseFields('cli', { resultType: 'success' }).fields).toEqual([
      { path: ['resultType'], text: 'success' },
    ]);
  });

  it('holds a walked CLI result to the walk bounds and says when it cut', () => {
    const at = Array.from({ length: RESULT_WALK_MAX_LEAVES }, (_, i) => `leaf ${String(i)}`);
    expect(scannableResponseFields('cli', { items: at })).toMatchObject({ truncated: false });
    const past = scannableResponseFields('cli', { items: [...at, 'one more'] });
    expect(past.fields).toHaveLength(RESULT_WALK_MAX_LEAVES);
    expect(past.truncated).toBe(true);
  });
});

describe('an object-shaped VS Code result', () => {
  it('scans every non-empty string leaf, with its path', () => {
    const response = {
      content: [
        { type: 'text', text: 'first block' },
        { type: 'image', data: '' },
      ],
      meta: { note: 'a note', count: 3, ok: true, none: null },
    };
    expect(scannableResponseFields('vscode', response)).toEqual({
      fields: [
        { path: ['content', '0', 'type'], text: 'text' },
        { path: ['content', '0', 'text'], text: 'first block' },
        { path: ['content', '1', 'type'], text: 'image' },
        { path: ['meta', 'note'], text: 'a note' },
      ],
      truncated: false,
    });
  });

  it('walks a bare array result too', () => {
    expect(scannableResponseFields('vscode', ['a', ['b']]).fields).toEqual([
      { path: ['0'], text: 'a' },
      { path: ['1', '0'], text: 'b' },
    ]);
  });

  function nested(depth: number, leaf: unknown): unknown {
    let node = leaf;
    for (let i = 0; i < depth; i += 1) node = { k: node };
    return node;
  }

  it('reads a leaf at the depth bound and marks one deeper truncated', () => {
    expect(scannableResponseFields('vscode', nested(RESULT_WALK_MAX_DEPTH, 'deep'))).toEqual({
      fields: [{ path: Array.from({ length: RESULT_WALK_MAX_DEPTH }, () => 'k'), text: 'deep' }],
      truncated: false,
    });
    expect(scannableResponseFields('vscode', nested(RESULT_WALK_MAX_DEPTH + 1, 'deep'))).toEqual({
      fields: [],
      truncated: true,
    });
    // An empty container at the bound holds nothing that went unscanned.
    expect(scannableResponseFields('vscode', nested(RESULT_WALK_MAX_DEPTH, {}))).toEqual(NOTHING);
  });

  it('holds the depth bound the way the sibling walk does: by the depth of the LEAF', () => {
    // The bound is `depth > RESULT_WALK_MAX_DEPTH` on the node itself, so what
    // decides is how deep the text sits, not how deep its container does. A
    // node past the bound marks the result truncated only when it could have
    // carried text — a container test (`depth >= MAX` on the parent) would
    // also flag a number or an empty string one level down, which left
    // nothing unscanned.
    const past = RESULT_WALK_MAX_DEPTH + 1;
    expect(scannableResponseFields('vscode', nested(past, 7))).toEqual(NOTHING);
    expect(scannableResponseFields('vscode', nested(past, null))).toEqual(NOTHING);
    expect(scannableResponseFields('vscode', nested(past, ''))).toEqual(NOTHING);
    expect(scannableResponseFields('vscode', nested(past, {}))).toEqual(NOTHING);
    expect(scannableResponseFields('vscode', nested(past, []))).toEqual(NOTHING);
    // The positive controls: text past the bound, bare or still wrapped, is
    // reported — so the five rows above are not passing on a walk that never
    // flags anything.
    expect(scannableResponseFields('vscode', nested(past, { inner: 'x' }))).toEqual({
      fields: [],
      truncated: true,
    });
    expect(scannableResponseFields('vscode', nested(past, ['x']))).toEqual({
      fields: [],
      truncated: true,
    });
    // A sibling at a readable depth is still read beside a truncated one.
    expect(
      scannableResponseFields('vscode', { shallow: 'kept', deep: nested(past - 1, 'lost') }),
    ).toEqual({ fields: [{ path: ['shallow'], text: 'kept' }], truncated: true });
  });

  it('stops at the leaf-count bound and says it did', () => {
    const at = Array.from({ length: RESULT_WALK_MAX_LEAVES }, (_, i) => `leaf ${String(i)}`);
    expect(scannableResponseFields('vscode', at)).toMatchObject({ truncated: false });
    const past = scannableResponseFields('vscode', [...at, 'one more']);
    expect(past.fields).toHaveLength(RESULT_WALK_MAX_LEAVES);
    expect(past.truncated).toBe(true);
  });

  // The leaf count bounds the TRAVERSAL, not only what is collected: once it is
  // reached, nothing further down is entered. A getter counts every read of
  // the node past the bound, which only entering that node makes.
  // And the stop is literal: once the count is reached no later sibling is
  // walked at all, even one that would refuse at the top of the walk. A Proxy
  // counts every key lookup on a sibling container, which only walking it
  // (Object.keys at the top of the walk, or Object.entries below) makes;
  // `couldCarryText`'s check reads its keys once, so the count tells the
  // remaining-sibling check apart from a walk of every sibling.
  it('enters no sibling past the one that reached the leaf count', () => {
    const at = Array.from({ length: RESULT_WALK_MAX_LEAVES }, (_, i) => `leaf ${String(i)}`);
    let keyReads = 0;
    const watched = (): object =>
      new Proxy(
        { k: 'text' },
        {
          ownKeys(target) {
            keyReads += 1;
            return Reflect.ownKeys(target);
          },
        },
      );
    const siblings = Array.from({ length: 5 }, watched);
    const past = scannableResponseFields('vscode', [...at, ...siblings]);
    expect(past.fields).toHaveLength(RESULT_WALK_MAX_LEAVES);
    expect(past.truncated).toBe(true);
    // Only the first remaining sibling is looked at: the check stops at the
    // first one that could carry text, and no sibling is walked.
    expect(keyReads).toBe(1);
    // The control: below the bound each watched sibling is walked.
    keyReads = 0;
    scannableResponseFields('vscode', siblings);
    expect(keyReads).toBeGreaterThanOrEqual(siblings.length);
  });

  it('stops walking once the leaf count is reached', () => {
    const at = Array.from({ length: RESULT_WALK_MAX_LEAVES }, (_, i) => `leaf ${String(i)}`);
    let reads = 0;
    const counted = {
      get probe(): string {
        reads += 1;
        return 'past the bound';
      },
    };
    const past = scannableResponseFields('vscode', [...at, counted]);
    expect(past.fields).toHaveLength(RESULT_WALK_MAX_LEAVES);
    expect(past.truncated).toBe(true);
    expect(reads).toBe(0);
    // The control: below the bound the same node is entered and read.
    expect(scannableResponseFields('vscode', [counted]).fields).toEqual([
      { path: ['0', 'probe'], text: 'past the bound' },
    ]);
    expect(reads).toBe(1);
  });

  it('marks a leaf over the per-leaf cap truncated rather than dropping it silently', () => {
    const long = 'x'.repeat(RESULT_WALK_MAX_LEAF_CHARS + 1);
    expect(scannableResponseFields('vscode', { long, short: 'kept' })).toEqual({
      fields: [{ path: ['short'], text: 'kept' }],
      truncated: true,
    });
    // The control: at the cap exactly it is read.
    const atCap = 'x'.repeat(RESULT_WALK_MAX_LEAF_CHARS);
    expect(scannableResponseFields('vscode', { atCap })).toMatchObject({ truncated: false });
  });

  it('stops at the character total and says it did', () => {
    const leaf = 'y'.repeat(RESULT_WALK_MAX_LEAF_CHARS);
    const fit = RESULT_WALK_MAX_TOTAL_CHARS / RESULT_WALK_MAX_LEAF_CHARS;
    const at = Array.from({ length: fit }, () => leaf);
    expect(scannableResponseFields('vscode', at)).toMatchObject({ truncated: false });
    const past = scannableResponseFields('vscode', [...at, 'z']);
    expect(past.fields).toHaveLength(fit);
    expect(past.truncated).toBe(true);
  });
});
