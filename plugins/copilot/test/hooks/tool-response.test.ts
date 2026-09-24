// The tool-result reader. Driven from the RECORDED `cli/postToolUse.json` and
// the provisional `vscode-provisional/PostToolUse.json`, never from literals
// written to match the table.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { responseKey, scannableResponseFields } from '../../src/hooks/tool-response.ts';

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

describe('scannableResponseFields', () => {
  it('reads the model-visible text out of the recorded CLI envelope', () => {
    const payload = fixture('cli', 'postToolUse.json');
    const fields = scannableResponseFields('cli', payload[responseKey('cli')]);
    expect(fields).toEqual([
      { path: ['textResultForLlm'], text: '\n<shellId: 0 completed with exit code 1>' },
    ]);
  });

  it('reads the whole string out of the provisional VS Code envelope', () => {
    const payload = fixture('vscode-provisional', 'PostToolUse.json');
    const fields = scannableResponseFields('vscode', payload[responseKey('vscode')]);
    expect(fields).toEqual([{ path: [], text: '\n<shellId: 0 completed with exit code 1>' }]);
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
    expect(Object.keys(module).sort()).toEqual(['responseKey', 'scannableResponseFields']);
  });

  it('handles a bare string result whatever the dialect says', () => {
    // A host that simplified its envelope must not make this scan nothing and
    // report success — the failure mode the whole adapter is shaped against.
    expect(scannableResponseFields('cli', 'plain text')).toEqual([
      { path: [], text: 'plain text' },
    ]);
  });

  it('skips an empty result, which has nothing in it to find', () => {
    expect(scannableResponseFields('cli', '')).toEqual([]);
    expect(scannableResponseFields('cli', { textResultForLlm: '' })).toEqual([]);
    expect(scannableResponseFields('vscode', '')).toEqual([]);
  });

  it('skips a result whose text field is absent or not a string', () => {
    expect(scannableResponseFields('cli', { resultType: 'success' })).toEqual([]);
    expect(scannableResponseFields('cli', { textResultForLlm: 42 })).toEqual([]);
    expect(scannableResponseFields('cli', null)).toEqual([]);
    expect(scannableResponseFields('cli', undefined)).toEqual([]);
  });

  // The two envelopes must not resolve against each other: a CLI envelope read
  // as VS Code returns the whole object rather than its text, and a VS Code
  // string read as CLI would find no `textResultForLlm` at all. Both are the
  // silent-wrong-answer shape the separate tables exist to prevent.
  it('does not resolve one dialect’s envelope through the other’s table', () => {
    const cliResult = fixture('cli', 'postToolUse.json')[responseKey('cli')];
    // Read as VS Code the object is not a string, and its empty path yields no
    // string either — so nothing is scanned rather than the wrong thing.
    expect(scannableResponseFields('vscode', cliResult)).toEqual([]);
  });
});
