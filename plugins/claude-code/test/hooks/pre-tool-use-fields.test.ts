// Tests the per-tool field map directly — NEVER via the hook entry file
// (src/hooks/*.ts run main() on import and hang vitest collection).
//
// What this pins: which tool inputs get scanned at all. A tool absent from
// this map is a silent bypass — an agent writes a secret through MultiEdit or
// ships one out through an MCP call and nothing sees it — and the failure is
// invisible, because the hook still exits 0 and the session looks protected.
// The `executable` flag is the other half: flipping one either reopens
// in-place rewriting of text the host acts on (the incident pinned in
// pre-tool-use-decision.test.ts) or breaks stored-text redaction.
import { describe, expect, it } from 'vitest';

import {
  inputEventKind,
  inputFilePath,
  scannableInputFields,
} from '../../src/hooks/pre-tool-use-fields.ts';

describe('scannableInputFields — the tools that execute their text', () => {
  it('marks Bash command and WebFetch url executable, and the prompts stored', () => {
    expect(scannableInputFields('Bash', { command: 'ls' })).toEqual([
      { path: ['command'], executable: true },
    ]);
    expect(
      scannableInputFields('WebFetch', { url: 'https://x.test', prompt: 'summarize' }),
    ).toEqual([
      { path: ['url'], executable: true },
      { path: ['prompt'], executable: false },
    ]);
  });

  it('marks Write/Edit content stored, so redaction rewrites in place', () => {
    expect(scannableInputFields('Write', { content: 'x' })).toEqual([
      { path: ['content'], executable: false },
    ]);
    expect(scannableInputFields('Edit', { old_string: 'a', new_string: 'b' })).toEqual([
      { path: ['new_string'], executable: false },
    ]);
  });
});

describe('scannableInputFields — MultiEdit', () => {
  const INPUT = {
    file_path: '/app/config.ts',
    edits: [
      { old_string: 'a', new_string: 'harmless' },
      { old_string: 'b', new_string: 'token here' },
    ],
  };

  it('scans every edit replacement, addressed by index', () => {
    expect(scannableInputFields('MultiEdit', INPUT)).toEqual([
      { path: ['edits', 0, 'new_string'], executable: false },
      { path: ['edits', 1, 'new_string'], executable: false },
    ]);
  });

  it('NEVER scans old_string — masking the match anchor breaks the edit', () => {
    // old_string is existing file content used as an exact-match anchor, not
    // text the agent authored. Redacting inside it makes the edit match
    // nothing and the tool call fail, which breaks the session the plugin
    // promises never to break — and it carries no secret the agent is
    // introducing, so there is nothing to gain either.
    const paths = scannableInputFields('MultiEdit', INPUT).map((f) => f.path);
    expect(paths.some((p) => p.includes('old_string'))).toBe(false);
  });

  it('skips empty replacements and survives a malformed edits array', () => {
    expect(
      scannableInputFields('MultiEdit', { edits: [{ new_string: '' }, { new_string: 'x' }] }),
    ).toEqual([{ path: ['edits', 1, 'new_string'], executable: false }]);
    // A payload shape we don't recognize must degrade to "nothing to scan",
    // never throw — a throw here is a fail-open allow.
    expect(scannableInputFields('MultiEdit', { edits: 'not-an-array' })).toEqual([]);
    expect(scannableInputFields('MultiEdit', {})).toEqual([]);
    expect(scannableInputFields('MultiEdit', { edits: [null, 'str', { new_string: 3 }] })).toEqual(
      [],
    );
  });
});

describe('scannableInputFields — NotebookEdit and Task', () => {
  it('scans the notebook cell replacement as stored text', () => {
    expect(
      scannableInputFields('NotebookEdit', { notebook_path: '/n.ipynb', new_source: 'print(1)' }),
    ).toEqual([{ path: ['new_source'], executable: false }]);
  });

  it('scans the subagent prompt as stored text', () => {
    expect(scannableInputFields('Task', { prompt: 'go find things', subagent_type: 'x' })).toEqual([
      { path: ['prompt'], executable: false },
    ]);
  });

  it('scans it under the CURRENT spelling of that tool as well', () => {
    // The harness renamed this tool to `Agent`. A table naming only `Task`
    // returns no fields on a current build, and no fields means the hook
    // returns before any decision — so the subagent prompt went unscanned with
    // every assertion above still green.
    expect(scannableInputFields('Agent', { prompt: 'go find things', subagent_type: 'x' })).toEqual(
      [{ path: ['prompt'], executable: false }],
    );
  });
});

// A field with `text` set is one of the synthetic joined-keys chunks (see
// mcpKeyChunks in pre-tool-use-fields.ts): its text was computed during the
// walk rather than addressable at `path` in the tool input. Every other
// field is a real value leaf, resolved by the caller via stringAtPath.
function keyChunks(fields: readonly { path: unknown; executable: boolean; text?: string }[]) {
  return fields.filter((f) => f.text !== undefined);
}
function valueLeaves(fields: readonly { path: unknown; executable: boolean; text?: string }[]) {
  return fields.filter((f) => f.text === undefined);
}

// Asserts `fields` carries EXACTLY ONE joined-keys chunk, executable, with
// this exact text — decomposed rather than one `toEqual` against a literal
// carrying `expect.anything()` for `path`, which is deliberately synthetic
// and untyped (see ScannableField.text) and trips no-unsafe-assignment when
// assigned into a typed object literal.
function expectOneKeyChunk(
  fields: readonly { path: unknown; executable: boolean; text?: string }[],
  text: string,
): void {
  const chunks = keyChunks(fields);
  expect(chunks).toHaveLength(1);
  expect(chunks[0]?.executable).toBe(true);
  expect(chunks[0]?.text).toBe(text);
}

describe('scannableInputFields — MCP tools', () => {
  it('finds a secret-bearing leaf nested inside an arbitrary payload', () => {
    const fields = scannableInputFields('mcp__slack__post', {
      channel: 'C123',
      blocks: [{ text: { body: 'deploy key: abc' } }],
    });
    expect(fields).toContainEqual({
      path: ['blocks', 0, 'text', 'body'],
      executable: true,
    });
    expect(fields).toContainEqual({ path: ['channel'], executable: true });
  });

  it('marks every MCP leaf executable: an unknown schema must not be rewritten', () => {
    // The server on the other end defines the shape, so a string could be a
    // message body (safe to mask) or a query/id/path (masking changes what
    // happens). We cannot tell which, and guessing wrong silently changes
    // semantics — so a redact denies instead. See pre-tool-use-fields.ts.
    const fields = scannableInputFields('mcp__db__query', { sql: 'SELECT 1', db: 'main' });
    expect(fields.length).toBeGreaterThan(0);
    expect(fields.every((f) => f.executable)).toBe(true);
  });

  it('ignores non-string leaves and empty strings, but still scans the keys', () => {
    const fields = scannableInputFields('mcp__x__y', {
      n: 1,
      b: true,
      nil: null,
      empty: '',
      s: 'scan me',
    });
    expect(valueLeaves(fields)).toEqual([{ path: ['s'], executable: true }]);
    // Every own key of the object, joined in encounter order — including
    // `empty`'s, which has no scannable VALUE but is still a key someone
    // could smuggle a secret into.
    expectOneKeyChunk(fields, 'n\nb\nnil\nempty\ns');
  });

  it('stops descending past the depth bound instead of hanging on deep input', () => {
    // Bounded so a pathological payload can't burn the hook's 10s budget: a
    // timed-out hook fails open and allows EVERYTHING unscanned, which is
    // strictly worse than scanning what fits.
    let deep: Record<string, unknown> = { leaf: 'too deep to reach' };
    for (let i = 0; i < 12; i++) deep = { nest: deep };
    // The leaf itself is unreachable, but the shallow `nest` keys up to the
    // depth bound were still visited on the way down, and their key text is
    // collected exactly like it would be for any other object visited within
    // bounds — a key beyond the bound is not, matching the value leaves.
    const deepFields = scannableInputFields('mcp__x__y', deep);
    expect(valueLeaves(deepFields)).toEqual([]);
    expectOneKeyChunk(deepFields, 'nest\nnest\nnest\nnest\nnest\nnest\nnest');

    const shallow = { a: { b: { c: 'reachable' } } };
    const shallowFields = scannableInputFields('mcp__x__y', shallow);
    expect(valueLeaves(shallowFields)).toEqual([{ path: ['a', 'b', 'c'], executable: true }]);
    expectOneKeyChunk(shallowFields, 'a\nb\nc');
  });

  it('skips a leaf past the per-leaf size cap but keeps scanning its siblings', () => {
    const fields = scannableInputFields('mcp__x__y', {
      huge: 'x'.repeat(1_000_001),
      small: 'scan me',
    });
    expect(valueLeaves(fields)).toEqual([{ path: ['small'], executable: true }]);
    expectOneKeyChunk(fields, 'huge\nsmall');
  });

  it('bounds the leaf COUNT, not just total size', () => {
    // Cost is per leaf — pre-tool-use.ts awaits one capture() per field, in
    // sequence — so the char bounds alone leave it unbounded: a million
    // one-char leaves is only a megabyte, far under MCP_MAX_TOTAL_CHARS, but a
    // million detection passes. The hook would time out, and a timed-out
    // PreToolUse fails open and allows the WHOLE call unscanned, flagged
    // leaves included. Truncating keeps enforcement on what was scanned.
    const many = Object.fromEntries(
      Array.from({ length: 5_000 }, (_, i) => [`k${String(i)}`, 'x']),
    );
    const fields = scannableInputFields('mcp__x__y', many);
    expect(valueLeaves(fields)).toHaveLength(2_000);
    // The 5,000 keys total well under MCP_MAX_LEAF_CHARS, so they collapse
    // into ONE combined unit rather than one per key — the count grows by
    // the chunk count (here, 1), never by the key count.
    expect(keyChunks(fields)).toHaveLength(1);
    expect(fields).toHaveLength(2_001);
  });

  it('caps a padded payload rather than letting it exhaust the budget', () => {
    // The evasion shape: bury the secret behind enough cheap leaves that the
    // scan never reaches it. It stays unscanned either way — the fix is that
    // the hook returns in bounded time instead of timing out into a
    // fail-open allow of everything.
    const padded: Record<string, unknown> = Object.fromEntries(
      Array.from({ length: 10_000 }, (_, i) => [`pad${String(i)}`, 'x']),
    );
    padded.zzz_secret = 'deploy key here';
    const fields = scannableInputFields('mcp__x__y', padded);
    expect(valueLeaves(fields)).toHaveLength(2_000);
    expect(keyChunks(fields)).toHaveLength(1);
    expect(fields).toHaveLength(2_001);
    expect(fields.every((f) => f.executable)).toBe(true);
  });
});

describe('scannableInputFields — MCP object keys', () => {
  it('scans a secret placed as a top-level object key', () => {
    const fields = scannableInputFields('mcp__x__y', { ghp_secrettoken1234567890: 'x' });
    const [chunk] = keyChunks(fields);
    expect(chunk?.text).toContain('ghp_secrettoken1234567890');
    // Marked executable like every other MCP field: there is no safe way to
    // rewrite an object's key in place, so a redact on it must degrade to
    // the same fallback an unrewritable value would — never a silent allow.
    expect(chunk?.executable).toBe(true);
  });

  it('scans a secret placed as a key nested inside the payload', () => {
    const fields = scannableInputFields('mcp__x__y', {
      wrapper: { inner: { ghp_secrettoken1234567890: 'x' } },
    });
    expect(keyChunks(fields)[0]?.text).toContain('ghp_secrettoken1234567890');
  });

  it('scans a secret placed as a key inside an array of objects', () => {
    const fields = scannableInputFields('mcp__x__y', {
      items: [{ note: 'benign' }, { ghp_secrettoken1234567890: 'x' }],
    });
    expect(keyChunks(fields)[0]?.text).toContain('ghp_secrettoken1234567890');
  });

  it('scans a key alongside its sibling value in the same walk', () => {
    const fields = scannableInputFields('mcp__x__y', {
      ghp_secrettoken1234567890: 'harmless',
      other: 'scan me too',
    });
    expect(keyChunks(fields)[0]?.text).toContain('ghp_secrettoken1234567890');
    expect(valueLeaves(fields)).toContainEqual({ path: ['other'], executable: true });
  });

  it('joins keys with a newline so two keys cannot fuse into one match', () => {
    // 'ab' + 'cd' concatenated raw would read 'abcd'; joined with the
    // separator it reads 'ab\ncd' — a rule matching only the contiguous
    // string cannot fire across the boundary.
    const fields = scannableInputFields('mcp__x__y', { ab: 1, cd: 1 });
    expectOneKeyChunk(fields, 'ab\ncd');
  });

  it('drops a single key over the per-unit size cap, like an over-long value', () => {
    const fields = scannableInputFields('mcp__x__y', {
      // Empty value: isolates the key-length drop from also exercising the
      // (already-covered) over-long VALUE drop on the same entry.
      ['k'.repeat(1_000_001)]: '',
      small: 'scan me',
    });
    // The over-long key contributes nothing; 'small' — an ordinary key —
    // still does.
    expectOneKeyChunk(fields, 'small');
    expect(valueLeaves(fields)).toEqual([{ path: ['small'], executable: true }]);
  });

  it('never splits a key across a chunk boundary, even under padding', () => {
    // A filler key sized to leave just under 31 chars of room in the first
    // chunk, then a 30-char secret key — joined with its separator that is
    // 31 chars, one over. A fixed-offset cut would let the filler's exact
    // length push the secret to straddle the boundary; bin-packing instead
    // starts a fresh chunk and keeps the secret whole.
    const filler = 'f'.repeat(1_000_000 - 30);
    const secretKey = 's'.repeat(30);
    const fields = scannableInputFields('mcp__x__y', { [filler]: 1, [secretKey]: 1 });
    const chunks = keyChunks(fields);
    expect(chunks.length).toBeGreaterThanOrEqual(2);
    // The secret key appears WHOLE in exactly one chunk, never split.
    const withSecret = chunks.filter((c) => c.text?.includes(secretKey));
    expect(withSecret).toHaveLength(1);
    expect(withSecret[0]?.text).toBe(secretKey);
    // No chunk exceeds the per-unit size cap.
    for (const chunk of chunks) expect(chunk.text?.length).toBeLessThanOrEqual(1_000_000);
  });

  it('charges key characters against the SAME shared total-size budget as values', () => {
    // Four value leaves at the per-leaf cap (1,000,000 chars each, plus
    // their short keys) consume all but 999,992 of the 5,000,000 total
    // budget. A later key of 999,995 chars — itself well under the per-key
    // cap — cannot fit in what's left and is dropped, along with its value:
    // proof keys and values draw from the SAME shared pool, not two
    // independent ones.
    const bigLeaves = Object.fromEntries(
      Array.from({ length: 4 }, (_, i) => [`v${String(i)}`, 'x'.repeat(1_000_000)]),
    );
    const fields = scannableInputFields('mcp__x__y', {
      ...bigLeaves,
      [`y`.repeat(999_995)]: 'z',
    });
    expect(valueLeaves(fields)).toHaveLength(4);
    // The four SHORT keys (v0..v3) fit easily and are still collected; only
    // the budget-exhausting 999,995-char key was dropped.
    expectOneKeyChunk(fields, 'v0\nv1\nv2\nv3');
  });
});

describe('scannableInputFields — tools with no coverage', () => {
  it('returns nothing for an unmapped tool, so the hook returns before opening the store', () => {
    expect(scannableInputFields('Glob', { pattern: '**/*.ts' })).toEqual([]);
    expect(scannableInputFields('', {})).toEqual([]);
  });

  it('does not resolve a tool name off Object.prototype', () => {
    // A bare index would hand back Object.prototype.constructor — non-nullish,
    // so `?? []` would not catch it — and the loop would walk a function.
    expect(scannableInputFields('constructor', { command: 'ls' })).toEqual([]);
    expect(scannableInputFields('toString', { command: 'ls' })).toEqual([]);
  });
});

describe('inputEventKind', () => {
  it('records text a tool acts on as tool_use', () => {
    // The gap this closes: Bash enforcement used to be recorded NOWHERE, so a
    // blocked command left no audit trail and every dashboard count missed it.
    expect(inputEventKind('Bash')).toBe('tool_use');
    expect(inputEventKind('WebFetch')).toBe('tool_use');
    expect(inputEventKind('Task')).toBe('tool_use');
    expect(inputEventKind('mcp__slack__post')).toBe('tool_use');
  });

  it('keeps durable authored content as code_change', () => {
    // code_change is the at-rest trail the re-scan resolver reconciles
    // against; moving these would strand it.
    expect(inputEventKind('Write')).toBe('code_change');
    expect(inputEventKind('Edit')).toBe('code_change');
    expect(inputEventKind('MultiEdit')).toBe('code_change');
    expect(inputEventKind('NotebookEdit')).toBe('code_change');
  });
});

describe('inputFilePath', () => {
  it('reads file_path, falling back to NotebookEdit’s notebook_path', () => {
    // Without the fallback a notebook finding carries no file attribution and
    // extension-scoped rules never apply to it.
    expect(inputFilePath({ file_path: '/a.ts' })).toBe('/a.ts');
    expect(inputFilePath({ notebook_path: '/n.ipynb' })).toBe('/n.ipynb');
    expect(inputFilePath({ command: 'ls' })).toBeUndefined();
  });
});
