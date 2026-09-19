// The PostToolUse result-shape readers, driven from the recorded CLI payload
// and the provisional VS Code one. Never imports the hook entry.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  replaceResponseField,
  responseKey,
  scannableResponseFields,
} from '../../src/hooks/tool-response.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, '..', 'fixtures');

function fixture(dir: string, name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(FIXTURES, dir, name), 'utf8')) as Record<string, unknown>;
}

describe('responseKey', () => {
  it('names each dialect’s own result key', () => {
    expect(responseKey('cli')).toBe('toolResult');
    expect(responseKey('vscode')).toBe('tool_response');
  });
});

describe('scannableResponseFields', () => {
  it('reads textResultForLlm out of the recorded CLI result', () => {
    const payload = fixture('cli', 'postToolUse.json');
    const fields = scannableResponseFields('cli', payload[responseKey('cli')]);
    expect(fields).toEqual([
      { path: ['textResultForLlm'], text: '\n<shellId: 0 completed with exit code 1>' },
    ]);
  });

  it('reads the whole string result out of the provisional VS Code payload', () => {
    const payload = fixture('vscode-provisional', 'PostToolUse.json');
    const fields = scannableResponseFields('vscode', payload[responseKey('vscode')]);
    expect(fields).toEqual([{ path: [], text: '\n<shellId: 0 completed with exit code 1>' }]);
  });

  // A bare string is handled whatever the dialect claims, because a host that
  // simplified its envelope would otherwise scan nothing and report success.
  it('handles a bare string result under the CLI dialect too', () => {
    expect(scannableResponseFields('cli', 'plain output')).toEqual([
      { path: [], text: 'plain output' },
    ]);
  });

  it('skips an empty, absent or non-string result', () => {
    expect(scannableResponseFields('cli', '')).toEqual([]);
    expect(scannableResponseFields('cli', undefined)).toEqual([]);
    expect(scannableResponseFields('cli', { textResultForLlm: '' })).toEqual([]);
    expect(scannableResponseFields('cli', { textResultForLlm: 42 })).toEqual([]);
    expect(scannableResponseFields('vscode', 42)).toEqual([]);
  });

  /**
   * THE TRAP, driven from the recording that carries it.
   *
   * The recorded command is literally `false`, which exits 1, and the payload
   * reports `resultType: "success"` — the tool INVOCATION succeeded. So the
   * exit status is not in that field at all; it is free text inside the result
   * the model reads. A reader that branched on `resultType` to decide whether a
   * command worked would be wrong on every failing command and would look
   * right, because it would go on scanning both the same way.
   */
  it('scans the result of a command that exited non-zero, which reports "success"', () => {
    const payload = fixture('cli', 'postToolUse.json');
    const result = payload[responseKey('cli')] as Record<string, unknown>;

    // The premise, from the recording rather than from prose.
    expect((payload.toolArgs as Record<string, unknown>).command).toBe('false');
    expect(result.resultType).toBe('success');
    expect(result.textResultForLlm).toContain('exit code 1');

    // And the module scans it regardless.
    expect(scannableResponseFields('cli', result)).toHaveLength(1);
  });

  /**
   * The structural half of the same claim, and the one that survives a
   * rewrite: this module must not READ `resultType` on any branch. The
   * behavioural case above cannot see a branch it does not happen to take, and
   * the failure mode is silent — a reader that treated `resultType` as an exit
   * status would go on scanning both outcomes identically and surface the
   * defect somewhere else entirely.
   *
   * Comments are stripped first: the module NAMES the field repeatedly to
   * explain why it is ignored, so a raw substring check would be satisfied by
   * that prose for ever.
   */
  it('reads resultType on no branch at all', () => {
    const source = readFileSync(join(HERE, '..', '..', 'src', 'hooks', 'tool-response.ts'), 'utf8');
    const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
    // The control: the prose really does name it, so the strip is doing work.
    expect(source).toContain('resultType');
    expect(code).not.toContain('resultType');
  });
});

describe('replaceResponseField', () => {
  it('replaces the string at a path and leaves the original untouched', () => {
    const original = { resultType: 'success', textResultForLlm: 'raw AKIA…' };
    const replaced = replaceResponseField(original, ['textResultForLlm'], 'masked');
    expect(replaced).toEqual({ resultType: 'success', textResultForLlm: 'masked' });
    expect(original.textResultForLlm).toBe('raw AKIA…');
  });

  // The empty path means "the value itself", which is how the VS Code string
  // result is rewritten.
  it('replaces the whole value for an empty path', () => {
    expect(replaceResponseField('raw', [], 'masked')).toBe('masked');
  });

  it('leaves a non-object alone when the path goes deeper than the value', () => {
    expect(replaceResponseField('raw', ['a', 'b'], 'masked')).toBe('raw');
  });
});
