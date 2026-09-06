import { describe, expect, it, vi } from 'vitest';

import type { SanitizeInput, SanitizeResult } from '../../src/sanitize/sanitize-capture.ts';
import {
  findResidueRun,
  numberSurrogate,
  sanitizeCapture,
} from '../../src/sanitize/sanitize-capture.ts';
import { assertFixtureFullySanitised, assertValidFixture } from '../helpers/fixture-bar.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

// Random-looking, high-entropy, and matches no bundled detection rule.
const RAW = 'qZ7hLm2XvB9tRw4sKcN6pJ1dGf3yUa8e';
const RAW2 = 'wT5nHq0ZbC8xVm3rLd6kPj2gYs9fAu4i';

function baseInput(overrides: Partial<SanitizeInput> = {}): SanitizeInput {
  return {
    raw: '{}',
    url: 'https://chatgpt.com/backend-api/x',
    site: 'chatgpt',
    kind: 'conversation',
    direction: 'request',
    format: 'json',
    allowedHosts: ['chatgpt.com'],
    approvedKeys: new Set(),
    approvedValues: new Set(),
    detect: () => [],
    ...overrides,
  };
}

/** Narrow a SanitizeResult to its ok:true arm, failing the test with the refusal otherwise. */
function assertOk(result: SanitizeResult): asserts result is Extract<SanitizeResult, { ok: true }> {
  if (!result.ok) {
    throw new Error(`expected ok:true, got refusal "${result.refusal}": ${result.error}`);
  }
}

function assertRefused(
  result: SanitizeResult,
): asserts result is Extract<SanitizeResult, { ok: false }> {
  if (result.ok) {
    throw new Error('expected ok:false, got ok:true');
  }
}

/** The fixture's first (and, in every test here, only) chunk. */
function firstChunk(result: Extract<SanitizeResult, { ok: true }>): string {
  const chunk = result.fixture.chunks[0];
  if (chunk === undefined) throw new Error('fixture carries no chunks');
  return chunk;
}

describe('leak surfaces', () => {
  it('L1: a value nested inside a JSON string inside a JSON document is replaced', () => {
    const raw = JSON.stringify({ payload: JSON.stringify({ secret: RAW }) });
    const result = sanitizeCapture(
      baseInput({ raw, approvedKeys: new Set(['payload', 'secret']) }),
    );
    assertOk(result);
    const out = JSON.parse(firstChunk(result)) as { payload: string };
    const inner = JSON.parse(out.payload) as { secret: string };
    expect(inner.secret).not.toBe(RAW);
    expect(typeof inner.secret).toBe('string');
    expectNoEchoOf(result.text, RAW);
  });

  it('L1b: a string that parses as a JSON scalar is not treated as nested JSON', () => {
    const raw = JSON.stringify({ a: 'true', b: '5' });
    const result = sanitizeCapture(baseInput({ raw, approvedKeys: new Set(['a', 'b']) }));
    assertOk(result);
    const out = JSON.parse(firstChunk(result)) as { a: unknown; b: unknown };
    // Both stay strings — a widened recursion would parse 'true' as a JS
    // boolean (bypassing the vocabulary approval gate entirely, since a
    // boolean is always kept) and '5' as a JS number (hitting the
    // NUMBER_KEEP_MAX shortcut and surviving verbatim, even though a numeric
    // STRING must always be replaced).
    expect(typeof out.a).toBe('string');
    expect(out.a).not.toBe('true');
    expect(typeof out.b).toBe('string');
    expect(out.b).not.toBe('5');
  });

  it('L2: an object key is classified and replaced independently of its value', () => {
    const uuid = '123e4567-e89b-12d3-a456-426614174000';
    const raw = JSON.stringify({ [uuid]: { a: 1 }, user_name: 'x', other_key: 'y' });
    const result = sanitizeCapture(
      baseInput({ raw, approvedKeys: new Set(['user_name']), approvedValues: new Set(['x']) }),
    );
    assertOk(result);
    const out = JSON.parse(firstChunk(result)) as Record<string, unknown>;
    const keys = Object.keys(out);
    expect(keys).toContain('user_name');
    expect(keys.some((k) => /^00000000-0000-4000-8000-\d{12}$/.test(k))).toBe(true);
    expect(keys).not.toContain('other_key');
    expect(keys.some((k) => /^KEY_\d+$/.test(k))).toBe(true);
    expect(result.report.candidateKeys).toContain('other_key');
  });

  it('L2b: a detector-flagged key is replaced even when approved', () => {
    const raw = JSON.stringify({ user_name: 'x' });
    const result = sanitizeCapture(
      baseInput({
        raw,
        approvedKeys: new Set(['user_name']),
        approvedValues: new Set(['x']),
        detect: (t) => (t === 'user_name' ? ['fake-rule'] : []),
      }),
    );
    assertOk(result);
    const out = JSON.parse(firstChunk(result)) as Record<string, unknown>;
    expect(Object.keys(out)).not.toContain('user_name');
    expect(result.report.flaggedKeys).toEqual([{ ruleIds: ['fake-rule'] }]);
  });

  it('L3: numbers keep small integers, replace large ones and decimals', () => {
    const raw = JSON.stringify({ small: 7, id: 8837462091, ratio: 0.735 });
    const result = sanitizeCapture(
      baseInput({ raw, approvedKeys: new Set(['small', 'id', 'ratio']) }),
    );
    assertOk(result);
    const out = JSON.parse(firstChunk(result)) as { small: number; id: number; ratio: number };
    expect(out.small).toBe(7);
    expect(out.id).not.toBe(8837462091);
    expect(String(Math.trunc(out.id)).length).toBe(10);
    expect(out.ratio).not.toBe(0.735);
    const decPart = String(out.ratio).split('.')[1] ?? '';
    expect(decPart.length).toBe(3);
  });

  it('L3b: booleans and null round-trip unchanged', () => {
    const raw = JSON.stringify({ a: true, b: null, c: '' });
    const result = sanitizeCapture(baseInput({ raw, approvedKeys: new Set(['a', 'b', 'c']) }));
    assertOk(result);
    const out = JSON.parse(firstChunk(result)) as { a: boolean; b: null; c: string };
    expect(out).toEqual({ a: true, b: null, c: '' });
  });

  it('L3c: array elements keep length and share surrogates for equal values', () => {
    const raw = JSON.stringify([RAW, RAW2, RAW]);
    const result = sanitizeCapture(baseInput({ raw }));
    assertOk(result);
    const out = JSON.parse(firstChunk(result)) as string[];
    expect(out.length).toBe(3);
    expect(out[0]).toBe(out[2]);
    expect(out[0]).not.toBe(out[1]);
  });

  it('L3d: an unrepresentable number refuses the run', () => {
    const huge = sanitizeCapture(baseInput({ raw: '{"n":1e21}' }));
    assertRefused(huge);
    expect(huge.refusal).toBe('unrepresentable-number');

    const infinite = sanitizeCapture(baseInput({ raw: '{"n":1e400}' }));
    assertRefused(infinite);
    expect(infinite.refusal).toBe('unrepresentable-number');
  });

  it('L4: SSE output chunks each end in a blank line and re-parse as the same event count', () => {
    const raw = [
      'data: {"a":1}',
      '',
      'event: message',
      'data: {"a":2}',
      '',
      'data: {"a":3}',
      '',
      '',
    ].join('\n');
    const result = sanitizeCapture(baseInput({ raw, format: 'sse' }));
    assertOk(result);
    expect(result.fixture.chunks.length).toBe(3);
    for (const chunk of result.fixture.chunks) expect(chunk.endsWith('\n\n')).toBe(true);
  });

  it('L4b: a value deep inside a large prose leaf is still replaced', () => {
    const filler = 'the quick brown fox jumps over the lazy dog. '.repeat(200);
    const withRaw = `${filler.slice(0, 4090)}${RAW}${filler.slice(4090)}`;
    const raw = JSON.stringify({ body: withRaw });
    const result = sanitizeCapture(baseInput({ raw }));
    assertOk(result);
    expectNoEchoOf(result.text, RAW);
  });

  it('L5: a top-level HAR refuses with an error naming HAR', () => {
    const raw = JSON.stringify({ log: { entries: [{ request: { url: RAW } }] } });
    const result = sanitizeCapture(baseInput({ raw }));
    assertRefused(result);
    expect(result.refusal).toBe('envelope-not-a-body');
    expect(result.error).toContain('HAR');
    expectNoEchoOf(result.error, RAW);
  });

  it('L5b: a top-level headers key refuses the run', () => {
    const raw = JSON.stringify({ headers: { authorization: `Bearer ${RAW}` } });
    const result = sanitizeCapture(baseInput({ raw }));
    assertRefused(result);
    expect(result.refusal).toBe('envelope-not-a-body');
    expectNoEchoOf(result.error, RAW);
  });

  it('L5c: a NESTED headers key does not over-refuse', () => {
    const raw = JSON.stringify({ body: { headers: { x: 'y' } } });
    const result = sanitizeCapture(baseInput({ raw }));
    expect(result.ok).toBe(true);
  });

  it('L6/L7: url host, path segments (approved vocabulary vs uuid) and query/fragment are sanitised', () => {
    const uuid = '123e4567-e89b-12d3-a456-426614174000';
    const url = `https://chatgpt.com/backend-api/conversation/${uuid}?ids=${RAW}#frag`;
    const result = sanitizeCapture(
      baseInput({
        url,
        approvedValues: new Set(['backend-api', 'conversation']),
      }),
    );
    assertOk(result);
    const outUrl = new URL(result.fixture.url);
    expect(outUrl.hostname).toBe('chatgpt.com');
    const segments = outUrl.pathname.split('/');
    expect(segments.length).toBe(4);
    expect(segments[1]).toBe('backend-api');
    expect(segments[2]).toBe('conversation');
    expect(segments[3]).not.toBe(uuid);
    expect(segments[3]).toMatch(/^00000000-0000-4000-8000-\d{12}$/);
    expect(outUrl.searchParams.has('ids')).toBe(false);
    const entries = [...outUrl.searchParams.entries()];
    expect(entries.length).toBe(1);
    const entry = entries[0];
    if (entry === undefined) throw new Error('expected one query entry');
    expect(entry[1]).not.toBe(RAW);
    expect(outUrl.hash).not.toBe('#frag');
    expectNoEchoOf(result.text, RAW);
  });

  it('L6b: a non-allowlisted host becomes host-<n>.invalid', () => {
    const result = sanitizeCapture(
      baseInput({ url: 'https://acme-corp.internal/x', allowedHosts: ['chatgpt.com'] }),
    );
    assertOk(result);
    const outUrl = new URL(result.fixture.url);
    expect(outUrl.hostname).toBe('host-1.invalid');
  });

  it('L8: a url appearing as a body value is sanitised as a url, not opaque text', () => {
    const uuid = '123e4567-e89b-12d3-a456-426614174000';
    const raw = JSON.stringify({ link: `https://chatgpt.com/c/${uuid}` });
    const result = sanitizeCapture(baseInput({ raw, approvedKeys: new Set(['link']) }));
    assertOk(result);
    const out = JSON.parse(firstChunk(result)) as { link: string };
    expect(out.link.startsWith('https://chatgpt.com/')).toBe(true);
    expect(out.link).not.toContain(uuid);
  });

  it('L9: base64ish blobs are replaced same-length with the same trailing = count', () => {
    const blob = `${'A'.repeat(62)}==`;
    const raw = JSON.stringify({ blob });
    const result = sanitizeCapture(baseInput({ raw, approvedKeys: new Set(['blob']) }));
    assertOk(result);
    const out = JSON.parse(firstChunk(result)) as { blob: string };
    expect(out.blob.length).toBe(64);
    expect(out.blob.endsWith('==')).toBe(true);
    expect(out.blob).not.toBe(blob);
    expect(/^[A-Za-z0-9]+==$/.test(out.blob)).toBe(true);
  });

  it('L9b: a JWT is replaced as three dot-joined segments of the same lengths', () => {
    const jwt =
      'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
    const raw = JSON.stringify({ token: jwt });
    const result = sanitizeCapture(baseInput({ raw, approvedKeys: new Set(['token']) }));
    assertOk(result);
    const out = JSON.parse(firstChunk(result)) as { token: string };
    const segs = out.token.split('.');
    const origSegs = jwt.split('.');
    expect(segs.length).toBe(3);
    segs.forEach((s, i) => {
      expect(s.length).toBe(origSegs[i]?.length);
    });
    expect(new Set(segs).size).toBe(3);
    expect(out.token).not.toBe(jwt);
    expectNoEchoOf(result.text, jwt);
  });

  it('L9c: a urlencoded body is decoded, sanitised entry by entry, and re-encoded', () => {
    const raw = `prompt=${RAW}&model=gpt-4o`;
    const result = sanitizeCapture(
      baseInput({
        raw,
        format: 'urlencoded',
        approvedKeys: new Set(['prompt', 'model']),
        approvedValues: new Set(['gpt-4o']),
      }),
    );
    assertOk(result);
    const out = new URLSearchParams(firstChunk(result));
    expect(out.get('model')).toBe('gpt-4o');
    expect(out.get('prompt')).not.toBe(RAW);
    expect(out.get('prompt')).not.toBeNull();
    expectNoEchoOf(result.text, RAW);
  });

  it('L9d: a percent-encoded value inside a JSON string is replaced and carries no %', () => {
    const raw = JSON.stringify({ q: 'a%20b%20c%20d%20e%20f%20g%20h' });
    const result = sanitizeCapture(baseInput({ raw, approvedKeys: new Set(['q']) }));
    assertOk(result);
    const out = JSON.parse(firstChunk(result)) as { q: string };
    expect(out.q).not.toContain('%');
  });

  it('L10: a residue the detector flags in the OUTPUT refuses the run', () => {
    // 'gpt-4o' is approved and kept verbatim; 'other-model' is not, so it
    // becomes the FIRST vocabulary surrogate emitted (TOKEN_1) — and that
    // literal surrogate text is what the fake detector below flags, proving
    // the residue check runs the detector over the OUTPUT rather than
    // trusting that every replaced value is automatically safe.
    const result = sanitizeCapture(
      baseInput({
        raw: JSON.stringify({ approved_field: 'gpt-4o', other_field: 'other-model' }),
        approvedKeys: new Set(['approved_field', 'other_field']),
        approvedValues: new Set(['gpt-4o']),
        detect: (t) => (t.includes('TOKEN_1') ? ['fake-rule'] : []),
      }),
    );
    assertRefused(result);
    expect(result.refusal).toBe('residue-detected');
    expect(result.error).toContain('fake-rule');
  });

  it('L10b: an approved token that also appears inside a separately-replaced prose leaf does NOT refuse', () => {
    // The approval itself is what puts `assistant` in the output. A window of
    // the replaced prose that coincides with it discloses nothing the
    // approval did not already, so refusing here is over-refusal — and it is
    // the shape that made the canonical capture unprocessable.
    const token = 'assistant'; // 9 chars, a vocabulary candidate, and not any envelope enum value
    const prose = `some long prose text mentioning the word ${token} and the value ${RAW} in the middle of a sentence so it is not itself a vocabulary candidate`;
    const result = sanitizeCapture(
      baseInput({
        raw: JSON.stringify({ kind_field: token, note: prose }),
        approvedKeys: new Set(['kind_field', 'note']),
        approvedValues: new Set([token]),
      }),
    );
    assertOk(result);
    const out = JSON.parse(firstChunk(result)) as { kind_field: string; note: string };
    // The approved token survives because it was approved; the prose around
    // it — which is what the leaf actually carried — does not.
    expect(out.kind_field).toBe(token);
    expect(out.note).toMatch(/^TEXT_\d+$/);
    expectNoEchoOf(result.text, RAW);
  });

  it('L10d: the canonical capture shapes the residue check used to refuse are processed', () => {
    // Each of these refused with no workaround: the path segment
    // `conversation` collided with the envelope's own `"kind":
    // "conversation"`; a uuid carrying an eight-zero run collided with the
    // fixed uuid surrogate; a body value quoting the allow-listed host
    // collided with the host kept verbatim in `url`; and prose quoting a link
    // collided with the url's own `https://`.
    const cases: { name: string; input: Partial<SanitizeInput> }[] = [
      { name: 'empty body at the canonical url', input: { raw: '{}' } },
      {
        name: 'a key whose window matches the envelope kind',
        input: { raw: JSON.stringify({ conversation_mode: { kind: 'primary_assistant' } }) },
      },
      {
        name: 'a uuid carrying an eight-zero run',
        input: { raw: JSON.stringify({ a: '0f8e2a1b-4c3d-4e5f-8a9b-000000000001' }) },
      },
      {
        name: 'a body value quoting the allow-listed host',
        input: { raw: JSON.stringify({ a: 'chatgpt.com/share/abc' }) },
      },
      {
        name: 'prose quoting a link',
        input: {
          raw: JSON.stringify({ a: 'see https://elsewhere.example/docs for the details we sent' }),
        },
      },
    ];
    for (const { name, input } of cases) {
      const result = sanitizeCapture(
        baseInput({ url: 'https://chatgpt.com/backend-api/conversation', ...input }),
      );
      expect(result.ok, `${name}: ${result.ok ? '' : `${result.refusal} ${result.error}`}`).toBe(
        true,
      );
    }
  });

  it('L10c: the same input without that approval does not over-refuse', () => {
    const token = 'assistant';
    const prose = `some long prose text mentioning the word ${token} in the middle of a sentence and going on for a while so it is not itself a vocabulary candidate`;
    const result = sanitizeCapture(
      baseInput({
        raw: JSON.stringify({ kind_field: token, note: prose }),
        approvedKeys: new Set(['kind_field', 'note']),
      }),
    );
    expect(result.ok).toBe(true);
  });
});

describe('contract', () => {
  it('S1: output is byte-identical regardless of the system clock or RNG state', () => {
    const raw = JSON.stringify({ a: RAW, b: 8837462091, c: 0.5 });
    const input = baseInput({ raw });

    vi.useFakeTimers();
    vi.setSystemTime(new Date('2020-01-01T00:00:00Z'));
    const randomSpy = vi.spyOn(Math, 'random').mockReturnValue(0.123456);
    const r1 = sanitizeCapture(input);

    vi.setSystemTime(new Date('2031-06-15T12:34:56Z'));
    randomSpy.mockReturnValue(0.987654);
    const r2 = sanitizeCapture(input);

    randomSpy.mockRestore();
    vi.useRealTimers();

    assertOk(r1);
    assertOk(r2);
    expect(r1.text).toBe(r2.text);
  });

  it('S2: equal originals share one surrogate; different originals get different ones', () => {
    const raw = JSON.stringify({ a: RAW, b: RAW, c: RAW2 });
    const result = sanitizeCapture(baseInput({ raw }));
    assertOk(result);
    const out = JSON.parse(firstChunk(result)) as Record<string, string>;
    // Read by VALUE, not by key name: 'a'/'b'/'c' are unapproved keys and get
    // replaced too, so their surrogate names are an implementation detail —
    // insertion order survives JSON round-tripping and is what is asserted on.
    const [va, vb, vc] = Object.values(out);
    expect(va).toBe(vb);
    expect(va).not.toBe(vc);
  });

  it('S3: content-independence — identical shape, different values, identical output', () => {
    const rawA = JSON.stringify({ a: RAW });
    const rawB = JSON.stringify({ a: RAW2 });
    const rA = sanitizeCapture(baseInput({ raw: rawA }));
    const rB = sanitizeCapture(baseInput({ raw: rawB }));
    assertOk(rA);
    assertOk(rB);
    expect(rA.text).toBe(rB.text);
  });

  it('S4: the envelope is well-formed and surrogates are sorted and distinct', () => {
    const raw = JSON.stringify({ a: RAW, b: RAW2, c: 8837462091 });
    const result = sanitizeCapture(baseInput({ raw }));
    assertOk(result);
    expect(() => {
      assertValidFixture('t', result.fixture);
    }).not.toThrow();
    expect(result.text).toBe(`${JSON.stringify(result.fixture, null, 2)}\n`);
    const strings = result.fixture.surrogates.strings;
    expect(strings).toEqual([...strings].sort());
    expect(new Set(strings).size).toBe(strings.length);
  });

  it('S5: the produced fixture passes assertFixtureFullySanitised (coupling test)', () => {
    const uuid = '123e4567-e89b-12d3-a456-426614174000';
    const raw = JSON.stringify({
      a: RAW,
      b: RAW2,
      id: 8837462091,
      ratio: 0.735,
      nested: JSON.stringify({ inner: RAW }),
      link: `https://chatgpt.com/c/${uuid}`,
    });
    const result = sanitizeCapture(
      baseInput({
        raw,
        url: `https://chatgpt.com/backend-api/conversation/${uuid}?q=${RAW2}`,
        approvedValues: new Set(['backend-api', 'conversation']),
      }),
    );
    assertOk(result);
    expect(() => {
      assertFixtureFullySanitised(
        't',
        result.fixture,
        { keys: new Set(), values: new Set(['backend-api', 'conversation']) },
        { allowedHosts: ['chatgpt.com'], detect: () => [] },
      );
    }).not.toThrow();
  });

  it('S5b: an SSE fixture the tool produced passes the bar, metadata lines included', () => {
    // The bar decodes an SSE chunk's `event:`/`id:`/comment lines as leaves
    // now, and sanitizeSseEvent sanitises exactly those — so the two must
    // agree about what the payload IS, on real tool output rather than on a
    // hand-built one.
    const raw = [
      'event: delta',
      `id: ${RAW}`,
      `data: {"v":"${RAW2}"}`,
      '',
      ': a stream comment carrying prose',
      'data: {"v":"done"}',
      '',
    ].join('\n');
    const result = sanitizeCapture(
      baseInput({ raw, format: 'sse', direction: 'response', approvedKeys: new Set(['v']) }),
    );
    assertOk(result);
    expect(result.fixture.chunks.length).toBe(2);
    expect(() => {
      assertFixtureFullySanitised(
        't',
        result.fixture,
        { keys: new Set(['v']), values: new Set() },
        { allowedHosts: ['chatgpt.com'], detect: () => [] },
      );
    }).not.toThrow();
    expectNoEchoOf(result.text, RAW);
    expectNoEchoOf(result.text, RAW2);
  });

  it('S6: a subtree past MAX_DEPTH becomes a single text surrogate', () => {
    let deep: unknown = RAW;
    for (let i = 0; i < 200; i += 1) deep = { nested: deep };
    const raw = JSON.stringify(deep);
    const result = sanitizeCapture(baseInput({ raw }));
    assertOk(result);
    expectNoEchoOf(result.text, RAW);
  });

  it('S7: an oversized input refuses without building output text', () => {
    const raw = JSON.stringify({ a: 'x'.repeat(33 * 1024 * 1024) });
    const result = sanitizeCapture(baseInput({ raw }));
    assertRefused(result);
    expect(result.refusal).toBe('input-too-large');
  });

  it('S8: detect has no default — omitting it is a compile-time error', () => {
    // @ts-expect-error detect has no default; omitting it must fail to typecheck
    const input: SanitizeInput = {
      raw: '{}',
      url: 'https://chatgpt.com/x',
      site: 'chatgpt',
      kind: 'conversation',
      direction: 'request',
      format: 'json',
      allowedHosts: [],
      approvedKeys: new Set(),
      approvedValues: new Set(),
    };
    expect(input).toBeDefined();
  });

  it('S9: an unparseable input refuses without echoing it', () => {
    const raw = `{"a": "${RAW}", malformed`;
    const result = sanitizeCapture(baseInput({ raw }));
    assertRefused(result);
    expect(result.refusal).toBe('unparseable-input');
    expectNoEchoOf(result.error, RAW);
  });
});

describe('numberSurrogate', () => {
  it('never drops a digit to a leading or trailing zero collapse', () => {
    // Sweep enough ordinals that a naive digit generator would eventually hit
    // a leading-zero integer part or a trailing-zero decimal part.
    for (let ordinal = 1; ordinal <= 40; ordinal += 1) {
      const surrogate = numberSurrogate(12345.678, ordinal);
      const [intPart, decPart] = String(Math.abs(surrogate)).split('.');
      expect(intPart?.length).toBe(5);
      expect(decPart?.length ?? 0).toBe(3);
    }
  });
});

describe('findResidueRun (the backstop, driven directly)', () => {
  it('does NOT catch a run that a content-derived surrogate carried into the output', () => {
    // The limit, pinned as behaviour rather than prose. A surrogate built from
    // the original's CONTENT leaks it, and this backstop cannot see the leak:
    // the run sits inside a string the walker registered as deliberately
    // emitted, so the positional accounting skips it. What actually prevents
    // this is surrogateFor's own rule that a surrogate MUST NOT read the
    // original's content. Break that rule and nothing here fires — which is
    // why the rule is written as a prohibition and not as a guard.
    const leaked = `TEXT_1_${RAW.slice(0, 12)}`;
    expect(
      findResidueRun(
        [{ where: 'chunks[0]', text: `{"a":"${leaked}"}` }],
        new Map([[RAW, 'text #1']]),
        [leaked],
      ),
    ).toBeNull();
    // The control: the same run, in the same place, with nothing accounting for
    // it, IS caught — so the case above is a statement about the accounting and
    // not about the search.
    expect(
      findResidueRun(
        [{ where: 'chunks[0]', text: `{"a":"${leaked}"}` }],
        new Map([[RAW, 'text #1']]),
        [],
      ),
    ).not.toBeNull();
  });

  // The walker replaces every original it reaches, so a genuine survival is
  // unreachable through sanitizeCapture — which is the whole point of a
  // backstop and also why it cannot be given an end-to-end positive control.
  // Driving it directly is what keeps it from being a check that can only
  // ever report clean.
  const originals = new Map([[RAW, 'text #1']]);

  it('R1: reports a surviving original, naming its class and ordinal but never its value', () => {
    const found = findResidueRun([{ where: 'chunks[0]', text: `{"a":"${RAW}"}` }], originals, [
      'TEXT_1',
    ]);
    expect(found).not.toBeNull();
    expect(found?.label).toBe('text #1');
    expect(found?.where).toBe('chunks[0]');
    expectNoEchoOf(`${found?.label ?? ''} ${found?.where ?? ''}`, RAW);
  });

  it('R2: a sanitised output carrying only the surrogate is clean', () => {
    expect(
      findResidueRun([{ where: 'chunks[0]', text: '{"a":"TEXT_1"}' }], originals, ['TEXT_1']),
    ).toBeNull();
  });

  it('R3: a run landing entirely on material the sanitiser emitted is not a survival', () => {
    // The uuid surrogate's own eight-zero run, an allow-listed host, and the
    // url scheme — each of which used to refuse an unrelated original.
    const collisions: [string, string, string[]][] = [
      [
        '00000000',
        '"00000000-0000-4000-8000-000000000001"',
        ['00000000-0000-4000-8000-000000000001'],
      ],
      [
        'chatgpt.com/share/abc',
        'https://chatgpt.com/TOKEN_1',
        ['chatgpt.com', 'https://', 'TOKEN_1'],
      ],
      ['see https://elsewhere.example/x', 'https://chatgpt.com/', ['chatgpt.com', 'https://']],
    ];
    for (const [original, text, accounted] of collisions) {
      expect(
        findResidueRun([{ where: 'url', text }], new Map([[original, 'text #1']]), accounted),
        original,
      ).toBeNull();
    }
  });

  it('R4: a run that only PARTLY lands on emitted material is still reported', () => {
    // The mirror of R3, and the control that stops the coverage rule turning
    // the whole check off: `chatgpt.com` is accounted, the rest is not.
    const found = findResidueRun(
      [{ where: 'chunks[0]', text: '"chatgpt.com/share/abcdefgh"' }],
      new Map([['chatgpt.com/share/abcdefgh', 'text #1']]),
      ['chatgpt.com'],
    );
    expect(found?.label).toBe('text #1');
  });

  it('R5: a survival carrying a quote or a newline is found in its JSON-escaped form', () => {
    const withQuote = 'he said "the merger closes friday" out loud';
    const found = findResidueRun(
      [{ where: 'chunks[0]', text: JSON.stringify({ a: withQuote }) }],
      new Map([[withQuote, 'text #1']]),
      [],
    );
    expect(found?.label).toBe('text #1');
  });

  it('R6: the envelope constants are not part of the haystack', () => {
    // `conversation` as a path segment against the envelope's own
    // `"kind": "conversation"` is the collision that refused every canonical
    // capture; the fix is that the envelope is never searched at all.
    const result = sanitizeCapture(
      baseInput({ url: 'https://chatgpt.com/backend-api/conversation' }),
    );
    assertOk(result);
    expect(result.text).toContain('"kind": "conversation"');
  });
});

describe('a detector that cannot answer refuses the run', () => {
  const unavailable = (): never => {
    throw new Error('engine unavailable');
  };

  it('D1: refuses rather than treating an unanswerable scan as clean, mid-walk', () => {
    // Throws only for the PER-VALUE scans, so the final whole-document
    // backstop is not what produces the refusal. Left unwrapped, this run
    // preserves an operator-approved value on a scan that never happened and
    // then passes every check on the way out.
    const result = sanitizeCapture(
      baseInput({
        raw: JSON.stringify({ model: 'gpt-4o' }),
        approvedKeys: new Set(['model']),
        approvedValues: new Set(['gpt-4o']),
        detect: (text) => {
          if (text === 'model' || text === 'gpt-4o') unavailable();
          return [];
        },
      }),
    );
    assertRefused(result);
    expect(result.refusal).toBe('detector-unavailable');
  });

  it('D2: refuses when the final whole-document scan cannot answer', () => {
    // Nothing in this body reaches a per-value scan (no key or value is
    // approvable), so the only detector call is the last backstop.
    let calls = 0;
    const result = sanitizeCapture(
      baseInput({
        raw: JSON.stringify({ a: RAW }),
        detect: () => {
          calls += 1;
          throw new Error('engine unavailable');
        },
      }),
    );
    assertRefused(result);
    expect(result.refusal).toBe('detector-unavailable');
    expect(calls).toBe(1);
  });
});

describe('the small-scalar carve-outs are reported', () => {
  it('N1: counts the integers and booleans kept verbatim', () => {
    const result = sanitizeCapture(
      baseInput({ raw: JSON.stringify({ d: [4, 1, 9, 2], b: [true, false, true], n: 12345 }) }),
    );
    assertOk(result);
    expect(result.report.smallIntegersKept).toBe(4);
    expect(result.report.booleansKept).toBe(3);
    expect(result.report.replaced['numeric-string']).toBe(0);
  });
});
