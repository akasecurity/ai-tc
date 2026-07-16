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
});

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

  it('ignores non-string leaves and empty strings', () => {
    expect(
      scannableInputFields('mcp__x__y', { n: 1, b: true, nil: null, empty: '', s: 'scan me' }),
    ).toEqual([{ path: ['s'], executable: true }]);
  });

  it('stops descending past the depth bound instead of hanging on deep input', () => {
    // Bounded so a pathological payload can't burn the hook's 10s budget: a
    // timed-out hook fails open and allows EVERYTHING unscanned, which is
    // strictly worse than scanning what fits.
    let deep: Record<string, unknown> = { leaf: 'too deep to reach' };
    for (let i = 0; i < 12; i++) deep = { nest: deep };
    expect(scannableInputFields('mcp__x__y', deep)).toEqual([]);

    const shallow = { a: { b: { c: 'reachable' } } };
    expect(scannableInputFields('mcp__x__y', shallow)).toEqual([
      { path: ['a', 'b', 'c'], executable: true },
    ]);
  });

  it('skips a leaf past the per-leaf size cap but keeps scanning its siblings', () => {
    const fields = scannableInputFields('mcp__x__y', {
      huge: 'x'.repeat(1_000_001),
      small: 'scan me',
    });
    expect(fields).toEqual([{ path: ['small'], executable: true }]);
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
    expect(fields).toHaveLength(2_000);
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
    expect(fields).toHaveLength(2_000);
    expect(fields.every((f) => f.executable)).toBe(true);
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
