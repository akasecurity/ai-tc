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
import { bundledDetections, scanText } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import type { ScannableField } from '../../src/hooks/pre-tool-use-fields.ts';
import {
  inputEventKind,
  inputFilePath,
  inputLineBasis,
  isSyntheticField,
  MCP_KEY_JOIN,
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

describe('scannableInputFields — Read and Grep paths', () => {
  it('scans a Read path that names a credential file, as executable text', () => {
    for (const filePath of [
      '/home/agent/proj/.env',
      '/home/agent/proj/.env.production',
      '/home/agent/.ssh/id_ed25519',
      '/home/agent/.netrc',
      '/home/agent/.pgpass',
      '/home/agent/.git-credentials',
      '/home/agent/.aws/credentials',
      '/home/agent/.config/somecli/credentials.json',
      '/home/agent/.cli/auth.json',
      'C:\\Users\\agent\\repo\\.env',
    ]) {
      expect(scannableInputFields('Read', { file_path: filePath }), filePath).toEqual([
        { path: ['file_path'], executable: true },
      ]);
    }
  });

  it('scans a Grep path that names a credential file', () => {
    expect(scannableInputFields('Grep', { pattern: 'TOKEN', path: '/srv/app/.env' })).toEqual([
      { path: ['path'], executable: true },
    ]);
  });

  it('leaves an ordinary path unscanned, so a Read costs no capture', () => {
    for (const filePath of [
      '/home/agent/proj/src/index.ts',
      '/home/agent/.config/editor/settings.json',
      '/home/agent/proj/README.md',
    ]) {
      expect(scannableInputFields('Read', { file_path: filePath }), filePath).toEqual([]);
    }
    expect(scannableInputFields('Grep', { pattern: 'x', path: '/home/agent/proj' })).toEqual([]);
    expect(scannableInputFields('Grep', { pattern: 'x' })).toEqual([]);
  });

  it('names no Read or Grep field the PostToolUse scan already covers', () => {
    // The guard reads the PATH only; the content is PostToolUse's.
    expect(scannableInputFields('Read', { file_path: '/a/.env', offset: 1, limit: 5 })).toEqual([
      { path: ['file_path'], executable: true },
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

// A neutral, distinctive marker rather than a credential-shaped literal: most
// of these tests exercise field COLLECTION, not detection, so nothing here
// needs to match a rule. See CLAUDE.md's Testing section.
const MARKER = 'key_marker_7f3a';

// A field synthetic per isSyntheticField (see pre-tool-use-fields.ts) is one
// of the joined-keys chunks mcpKeyChunks builds: its text was computed during
// the walk rather than addressable at `path` in the tool input. Every other
// field is a real value leaf, resolved by the caller via stringAtPath.
function keyChunks(fields: readonly ScannableField[]): ScannableField[] {
  return fields.filter(isSyntheticField);
}
function valueLeaves(fields: readonly ScannableField[]): ScannableField[] {
  return fields.filter((f) => !isSyntheticField(f));
}

// Asserts `fields` carries EXACTLY ONE joined-keys chunk, executable, with
// this exact text.
function expectOneKeyChunk(fields: readonly ScannableField[], text: string): void {
  const chunks = keyChunks(fields);
  expect(chunks).toHaveLength(1);
  expect(chunks[0]?.executable).toBe(true);
  expect(chunks[0]?.text).toBe(text);
}

// Asserts `fields` carries exactly these joined-keys chunk texts, one per
// originating object — order-independent, since group-push order is the
// walk's own post-order (deepest object first) and no test here depends on
// that being stable.
function expectKeyChunkTexts(fields: readonly ScannableField[], texts: readonly string[]): void {
  const chunks = keyChunks(fields);
  expect(chunks.every((c) => c.executable)).toBe(true);
  expect(chunks.map((c) => c.text).sort()).toEqual([...texts].sort());
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
    // Every own key of this ONE object, joined in encounter order —
    // including `empty`'s, which has no scannable VALUE but is still a key
    // someone could smuggle a secret into.
    expectOneKeyChunk(fields, ['n', 'b', 'nil', 'empty', 's'].join(MCP_KEY_JOIN));
  });

  it('stops descending past the depth bound instead of hanging on deep input', () => {
    // Bounded so a pathological payload can't burn the hook's 10s budget: a
    // timed-out hook fails open and allows EVERYTHING unscanned, which is
    // strictly worse than scanning what fits.
    let deep: Record<string, unknown> = { leaf: 'too deep to reach' };
    for (let i = 0; i < 12; i++) deep = { nest: deep };
    // The leaf itself is unreachable, but the shallow `nest`-keyed objects up
    // to the depth bound were still visited on the way down, and each one's
    // own key is collected exactly like it would be for any object visited
    // within bounds — a key beyond the bound is not, matching the value
    // leaves. Every one of those objects holds the SAME single key ('nest'),
    // so their chunk texts are byte-identical and dedupe to one chunk.
    const deepFields = scannableInputFields('mcp__x__y', deep);
    expect(valueLeaves(deepFields)).toEqual([]);
    expectOneKeyChunk(deepFields, 'nest');

    // Three DISTINCT objects here, each with its own single key: partitioned
    // by parent (see mcpFields' own comment), so 'a', 'b' and 'c' are three
    // separate chunks rather than one joined string.
    const shallow = { a: { b: { c: 'reachable' } } };
    const shallowFields = scannableInputFields('mcp__x__y', shallow);
    expect(valueLeaves(shallowFields)).toEqual([{ path: ['a', 'b', 'c'], executable: true }]);
    expectKeyChunkTexts(shallowFields, ['a', 'b', 'c']);
  });

  it('records a shallower object’s keys BEFORE a deeper one’s, in walk order', () => {
    // Group push order is what mcpKeyChunks spends its per-object dedicated
    // chunks on FIRST — see MCP_MAX_KEY_GROUPS. Recording deepest-first would
    // make the outermost, most likely to matter keys the first casualty of
    // any limit further down; walk order (parent before its children) keeps
    // them first instead.
    const shallow = { a: { b: { c: 'reachable' } } };
    const chunks = keyChunks(scannableInputFields('mcp__x__y', shallow));
    expect(chunks.map((c) => c.text)).toEqual(['a', 'b', 'c']);
  });

  it('skips a leaf past the per-leaf size cap but keeps scanning its siblings', () => {
    const fields = scannableInputFields('mcp__x__y', {
      huge: 'x'.repeat(1_000_001),
      small: 'scan me',
    });
    expect(valueLeaves(fields)).toEqual([{ path: ['small'], executable: true }]);
    // Both keys are the SAME (root) object's own, so one chunk.
    expectOneKeyChunk(fields, ['huge', 'small'].join(MCP_KEY_JOIN));
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
    // Every one of the 5,000 keys is this ONE (root) object's own — this
    // loop is never gated by the value leaf count (see mcpFields' own
    // comment) — and their combined length sits well under the per-chunk
    // cap, so they collapse into ONE combined unit rather than one per key:
    // the count grows by the chunk count (here, 1), never by the key count.
    expect(keyChunks(fields)).toHaveLength(1);
    expect(fields).toHaveLength(2_001);
  });

  it('caps a padded payload rather than letting it exhaust the budget', () => {
    // The evasion shape: bury the secret behind enough cheap leaves that the
    // scan never reaches it. Its VALUE stays unscanned, dropped by the same
    // leaf-count cap as the test above — but its KEY, `zzz_secret`, is still
    // collected: every key of this one root object is, regardless of the
    // value leaf count (see mcpFields' own comment), so this padding shape
    // no longer hides a secret placed in the key rather than the value.
    const padded: Record<string, unknown> = Object.fromEntries(
      Array.from({ length: 10_000 }, (_, i) => [`pad${String(i)}`, 'x']),
    );
    padded.zzz_secret = 'deploy key here';
    const fields = scannableInputFields('mcp__x__y', padded);
    expect(valueLeaves(fields)).toHaveLength(2_000);
    const chunks = keyChunks(fields);
    expect(chunks).toHaveLength(1);
    expect(chunks[0]?.text).toContain('zzz_secret');
    expect(fields).toHaveLength(2_001);
    expect(fields.every((f) => f.executable)).toBe(true);
  });

  it('bounds the number of DEDICATED key-chunk groups, packing the rest into overflow', () => {
    // MCP_MAX_KEY_GROUPS protects against the shape a shared char/leaf budget
    // does not: many DISTINCT small sibling objects (an array of 1,000
    // two-key records with a unique id each), where grouping by parent —
    // needed to stop cross-branch proximity corroboration, see mcpFields'
    // own comment — would otherwise cost close to one capture per record.
    // Past the cap, a group no longer gets its own chunk, but its keys are
    // still scanned — packed into a shared overflow chunk instead of being
    // silently dropped (see MCP_MAX_KEY_GROUPS's own comment).
    const items = Array.from({ length: 1_000 }, (_, i) => ({ [`id${String(i)}`]: i }));
    const fields = scannableInputFields('mcp__x__y', { items });
    const chunks = keyChunks(fields);
    // The root's own 'items' key plus 199 record chunks fill the dedicated
    // cap (200); the remaining 800 records' keys are small enough to all
    // fit in ONE overflow chunk, well under the char budget.
    expect(chunks).toHaveLength(201);
    const total = chunks.reduce((n, c) => n + (c.text?.length ?? 0), 0);
    expect(total).toBeGreaterThan(0);
  });

  it('never drops a key past the dedicated-chunk cap — it lands in an overflow chunk', () => {
    // Reproduces the exact shape a hard drop missed: 200 distinct benign
    // single-key objects, THEN one more object whose key is the marker.
    // Before packing overflow, the marker's group was simply discarded once
    // MCP_MAX_KEY_GROUPS dedicated chunks already existed.
    const pad = Array.from({ length: 200 }, (_, i) => ({ [`a${String(i)}`]: 1 }));
    const fields = scannableInputFields('mcp__x__y', {
      items: [...pad, { [MARKER]: 1 }],
    });
    expect(keyChunks(fields).some((c) => c.text?.includes(MARKER))).toBe(true);
  });

  it('scans a top-level secret placed BEFORE 200 padding objects', () => {
    // With keys recorded in walk order (parent before children — see the
    // depth-bound test above), the root's own key sits in the first
    // dedicated chunk regardless of how much padding follows it.
    const pad = Array.from({ length: 200 }, (_, i) => ({ [`a${String(i)}`]: 1 }));
    const fields = scannableInputFields('mcp__x__y', { [MARKER]: 1, items: pad });
    expect(keyChunks(fields).some((c) => c.text?.includes(MARKER))).toBe(true);
  });

  it('dedupes identically-shaped sibling groups into one chunk', () => {
    // A paginated array of uniformly-shaped records (the realistic version
    // of the shape above) produces byte-identical chunk text per record —
    // scanning the second one adds no coverage the first didn't already
    // provide, so the repeat is skipped rather than captured again.
    const items = Array.from({ length: 500 }, () => ({ id: 'x', status: 'active' }));
    const fields = scannableInputFields('mcp__x__y', { items });
    // 'items' (the root's own key) plus ONE deduped record chunk.
    expect(keyChunks(fields)).toHaveLength(2);
    const recordChunk = keyChunks(fields).find((c) => c.text !== 'items');
    expect(recordChunk?.text).toBe(['id', 'status'].join(MCP_KEY_JOIN));
  });
});

describe('scannableInputFields — MCP object keys', () => {
  it('scans a secret placed as a top-level object key', () => {
    const fields = scannableInputFields('mcp__x__y', { [MARKER]: 'x' });
    const [chunk] = keyChunks(fields);
    expect(chunk?.text).toBe(MARKER);
    // Marked executable like every other MCP field: there is no safe way to
    // rewrite an object's key in place, so a redact on it must degrade to
    // the same fallback an unrewritable value would — never a silent allow.
    expect(chunk?.executable).toBe(true);
  });

  it('scans a secret placed as a key nested inside the payload', () => {
    const fields = scannableInputFields('mcp__x__y', {
      wrapper: { inner: { [MARKER]: 'x' } },
    });
    expect(keyChunks(fields).some((c) => c.text === MARKER)).toBe(true);
  });

  it('scans a secret placed as a key inside an array of objects', () => {
    const fields = scannableInputFields('mcp__x__y', {
      items: [{ note: 'benign' }, { [MARKER]: 'x' }],
    });
    // The marker's OWN object's keys are a separate chunk from 'note's and
    // from 'items' — see mcpFields' own comment on why an unrelated key
    // never rides along in the same unit.
    expect(keyChunks(fields).some((c) => c.text === MARKER)).toBe(true);
  });

  it('scans a key alongside its sibling value in the same walk', () => {
    const fields = scannableInputFields('mcp__x__y', {
      [MARKER]: 'harmless',
      other: 'scan me too',
    });
    // MARKER and 'other' are the SAME (root) object's own keys, so one chunk.
    expectOneKeyChunk(fields, [MARKER, 'other'].join(MCP_KEY_JOIN));
    expect(valueLeaves(fields)).toContainEqual({ path: ['other'], executable: true });
  });

  it('drops a single key over the per-unit size cap, like an over-long value', () => {
    const fields = scannableInputFields('mcp__x__y', {
      // Empty value: isolates the key-length drop from also exercising the
      // (already-covered) over-long VALUE drop on the same entry.
      ['k'.repeat(1_000_001)]: '',
      small: 'scan me',
    });
    // The over-long key contributes nothing; 'small' — an ordinary key of
    // the SAME (root) object — still does.
    expectOneKeyChunk(fields, 'small');
    expect(valueLeaves(fields)).toEqual([{ path: ['small'], executable: true }]);
  });

  it('never splits a key across a chunk boundary, even under padding', () => {
    // A filler key and a 30-char secret key, siblings of the SAME (root)
    // object, sized so joining them would exceed the per-chunk cap. A
    // fixed-offset cut would let the filler's exact length push the secret
    // to straddle the boundary; bin-packing instead starts a fresh chunk and
    // keeps the secret whole.
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

  it('charges keys only from what the value walk leaves over, never evicting a value', () => {
    // Five value leaves at the per-leaf cap (1,000,000 chars each) consume
    // the ENTIRE 5,000,000 total budget between them. Before this fix, each
    // sibling's KEY was charged first, during the same pass, and could push
    // a LATER sibling's value over budget and drop it. Now every value leaf
    // is scanned in full regardless of how many keys the payload carries;
    // keys are charged only from whatever the value walk didn't need.
    const bigLeaves = Object.fromEntries(
      Array.from({ length: 5 }, (_, i) => [`v${String(i)}`, 'x'.repeat(1_000_000)]),
    );
    const fields = scannableInputFields('mcp__x__y', bigLeaves);
    expect(valueLeaves(fields)).toHaveLength(5);
    // Nothing left in the shared budget for the keys themselves.
    expect(keyChunks(fields)).toEqual([]);
  });

  it('still scans keys from whatever budget the value walk leaves over', () => {
    const fields = scannableInputFields('mcp__x__y', { small: 'x', another: 'y' });
    expect(valueLeaves(fields)).toHaveLength(2);
    expectOneKeyChunk(fields, ['small', 'another'].join(MCP_KEY_JOIN));
  });
});

describe('scannableInputFields — MCP keys are grouped by their own object, never pooled', () => {
  // Reproduces the exact false positive a flat, ungrouped join produced: an
  // unrelated key ('billing') fell inside a `requiresNearby` rule's
  // proximity window of a key from a COMPLETELY different branch ('12345',
  // an order id, read as a ZIP code). Grouping by parent means 'billing' and
  // '12345' never occupy the same scanned text at all.
  const PAYLOAD = { billing: { plan: 'pro' }, orders: { '12345': { qty: 1 } } };

  it('never joins two different objects’ keys into one chunk', () => {
    const fields = scannableInputFields('mcp__x__y', PAYLOAD);
    // Four objects visited: the root (whose own two keys, 'billing' and
    // 'orders', DO share one chunk — they are siblings of the SAME object),
    // billing's value, orders' value, and orders['12345']'s value.
    expectKeyChunkTexts(fields, [['billing', 'orders'].join(MCP_KEY_JOIN), 'plan', '12345', 'qty']);
  });

  it('produces no bundled-rule finding on any chunk this payload builds', () => {
    // The real regression test: run every chunk mcpFields actually produces
    // through the bundled detection engine (the same one pre-tool-use.ts
    // calls via runtime.capture), not a hand-picked string. A flat '\n'-joined
    // design fires core-pii/zip on the '12345' chunk here.
    const fields = scannableInputFields('mcp__x__y', PAYLOAD);
    for (const chunk of keyChunks(fields)) {
      const { findings } = scanText(chunk.text ?? '');
      expect(findings).toEqual([]);
    }
  });
});

describe('scannableInputFields — MCP key separator defeats real bundled-rule fusion', () => {
  // Reproduces the exact false positives the OLD '\n'-only separator
  // produced: several bundled PHI rules match keyword+value with a `\s*`
  // pattern, and `\s` matches `\n`, so ordinary sibling keys joined by a bare
  // newline read as one contiguous phrase to those rules. Each triple below
  // is a single object's OWN sibling keys (a realistic CRM/EHR-shaped
  // update), run through the real bundled detection engine exactly as
  // pre-tool-use.ts's runtime.capture would scan them.
  const CASES: readonly (readonly string[])[] = [
    ['member', 'id', 'status'],
    ['mrn', 'patient', 'name'],
    ['subscriber', 'firstName', 'lastName'],
  ];

  it('fires on the old bare-newline join (documents the bug this fixes)', () => {
    for (const keys of CASES) {
      const { findings } = scanText(keys.join('\n'));
      expect(findings.length).toBeGreaterThan(0);
    }
  });

  it('is silent on the actual joined text mcpFields produces today', () => {
    for (const keys of CASES) {
      const payload = Object.fromEntries(keys.map((k) => [k, 1]));
      const fields = scannableInputFields('mcp__x__y', payload);
      expectOneKeyChunk(fields, keys.join(MCP_KEY_JOIN));
      const { findings } = scanText(keys.join(MCP_KEY_JOIN));
      expect(findings).toEqual([]);
    }
  });

  it('still catches a real secret taken from a bundled rule’s own example, used as a key', () => {
    // Detection coverage itself is unaffected by the separator or grouping
    // change: a genuine secret-shaped key, alone, still fires. Taken from a
    // bundled rule's own `examples` — the same source fail-open.e2e.test.ts
    // draws its fixture from — rather than a hand-written literal, per
    // CLAUDE.md's Testing section.
    let found: { ruleId: string; example: string } | undefined;
    for (const rule of bundledDetections().flatMap((p) => p.rules)) {
      const example = rule.examples?.find((e) => !e.includes(' '));
      if (example === undefined) continue;
      if (scanText(example).findings.some((f) => f.ruleId === rule.id)) {
        found = { ruleId: rule.id, example };
        break;
      }
    }
    if (!found) {
      throw new Error(
        'no bundled rule has a single-token example that matches its own rule alone, so ' +
          'this test would drive a false fixture through the walk and assert nothing',
      );
    }
    const { ruleId, example } = found;

    const fields = scannableInputFields('mcp__x__y', { [example]: 'x' });
    const [chunk] = keyChunks(fields);
    const { findings } = scanText(chunk?.text ?? '');
    expect(findings.some((f) => f.ruleId === ruleId)).toBe(true);
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

describe('inputLineBasis', () => {
  it("counts a Write's lines in the file and every other tool's in its fragment", () => {
    expect(inputLineBasis('Write')).toBe('file');
    expect(inputLineBasis('Edit')).toBe('excerpt');
    expect(inputLineBasis('MultiEdit')).toBe('excerpt');
    expect(inputLineBasis('Bash')).toBe('excerpt');
  });
});
