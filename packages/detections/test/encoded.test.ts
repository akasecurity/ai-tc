import type { Rule } from '@akasecurity/schema';
import { Rule as RuleSchema } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  decodeEncodedSegments,
  decodeEncodedWithCoverage,
  MAX_DECODED_CHARS,
  MAX_ENCODED_SEARCH_CHARS,
  sourceSpanOf,
} from '../src/encoded.ts';
import { redact, scan } from '../src/engine.ts';
import { maskMatch } from '../src/mask.ts';
import { loadRule, RULES_DIR } from './helpers/rules.ts';

// A synthetic secret rule, so no credential-shaped literal lives in this file.
const CANARY_RULE: Rule = RuleSchema.parse({
  specVersion: 1,
  id: 'test/canary',
  name: 'canary',
  category: 'secret',
  severity: 'high',
  matcher: { type: 'regex', pattern: 'CANARY-[A-Z0-9]{12}', flags: 'g' },
});
// A non-secret rule: decoded text is scanned with secret rules only.
const NAME_RULE: Rule = RuleSchema.parse({
  specVersion: 1,
  id: 'test/name',
  name: 'name',
  category: 'pii',
  severity: 'low',
  matcher: { type: 'regex', pattern: 'PERSON-[A-Z]{6}', flags: 'g' },
});

const SECRET = 'CANARY-7Q2W9E4R1T6Y';
const ENV_FILE = `# shell setup\nexport EDITOR=vim\nexport SERVICE_TOKEN=${SECRET}\nexport PAGER=less\n`;

const b64 = (s: string): string => Buffer.from(s, 'utf8').toString('base64');
const hex = (s: string): string => Buffer.from(s, 'utf8').toString('hex');

// `xxd` default layout: offset, eight 2-byte groups, two spaces, ASCII column.
function xxd(s: string): string {
  const bytes = Buffer.from(s, 'utf8');
  const lines: string[] = [];
  for (let at = 0; at < bytes.length; at += 16) {
    const row = bytes.subarray(at, at + 16);
    const groups: string[] = [];
    for (let g = 0; g < row.length; g += 2) groups.push(row.subarray(g, g + 2).toString('hex'));
    const ascii = [...row].map((b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.'));
    lines.push(
      `${at.toString(16).padStart(8, '0')}: ${groups.join(' ').padEnd(39)}  ${ascii.join('')}`,
    );
  }
  return `${lines.join('\n')}\n`;
}

// `hexdump -C` layout: offset, two spaces, 16 bytes split 8+8, `|ASCII|`.
function hexdumpC(s: string): string {
  const bytes = Buffer.from(s, 'utf8');
  const lines: string[] = [];
  for (let at = 0; at < bytes.length; at += 16) {
    const row = [...bytes.subarray(at, at + 16)];
    const cells = row.map((b) => b.toString(16).padStart(2, '0'));
    const left = cells.slice(0, 8).join(' ');
    const right = cells.slice(8).join(' ');
    const ascii = row.map((b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.')).join('');
    lines.push(`${at.toString(16).padStart(8, '0')}  ${`${left}  ${right}`.padEnd(49)}|${ascii}|`);
  }
  return `${lines.join('\n')}\n`;
}

// Every encoded form a leak scorer would look for: the secret's hex, and its
// base64 at each of the three byte alignments minus the last, context-bound,
// group. None of these may survive a redaction.
function encodedForms(secret: string): string[] {
  const forms = [hex(secret), hex(secret).toUpperCase()];
  for (let k = 0; k < 3; k++) {
    const enc = b64(secret.slice(k)).replace(/=+$/, '');
    forms.push(enc.slice(4, Math.max(4, enc.length - 4)));
  }
  return forms.filter((f) => f.length >= 8);
}

function expectNoEncodedLeak(text: string, secret: string): void {
  const flat = text.replace(/\s+/g, '');
  for (const form of encodedForms(secret)) expect(flat).not.toContain(form);
}

describe('encoded secrets — base64', () => {
  it('finds a secret inside a single-line base64 dump and masks the encoded span', () => {
    const text = `$ base64 < ~/.zshenv\n${b64(ENV_FILE)}\n`;
    const findings = scan(text, [CANARY_RULE]);
    expect(findings.map((f) => f.ruleId)).toEqual(['test/canary']);
    const [finding] = findings;
    expect(finding?.span.start).toBeGreaterThan(text.indexOf('\n'));
    // The span covers the encoding; the value is the decoded secret itself.
    expect(finding?.rawMatch).toBe(SECRET);
    const redacted = redact(text, findings);
    expect(redacted).toContain('[REDACTED:SECRET]');
    expectNoEncodedLeak(redacted, SECRET);
  });

  it('follows base64 wrapped across lines, as GNU base64 prints it', () => {
    const wrapped = (b64(ENV_FILE).match(/.{1,76}/g) ?? []).join('\n');
    const findings = scan(`${wrapped}\n`, [CANARY_RULE]);
    expect(findings).toHaveLength(1);
    expectNoEncodedLeak(redact(`${wrapped}\n`, findings), SECRET);
  });

  it('reads a run glued onto a preceding word on its own 4-character grid', () => {
    const text = `blob=xyz${b64(ENV_FILE)}`;
    const findings = scan(text, [CANARY_RULE]);
    expect(findings).toHaveLength(1);
    expectNoEncodedLeak(redact(text, findings), SECRET);
  });

  it('reports a plain copy and an encoded copy of the same secret separately', () => {
    const text = `${ENV_FILE}\n${b64(ENV_FILE)}\n`;
    const findings = scan(text, [CANARY_RULE]);
    expect(findings).toHaveLength(2);
    const redacted = redact(text, findings);
    expect(redacted).not.toContain(SECRET);
    expectNoEncodedLeak(redacted, SECRET);
  });

  it('runs the bundled secret rules over the decoded text', () => {
    const envRule = loadRule(`${RULES_DIR}/secrets-infra`, 'env-key-value');
    const value = 'q8Zr2LmX0vT4bN7kY1sD5fH9jW3pC6aE';
    const text = b64(`export WIDGET_API_KEY=${value}\n`);
    const findings = scan(text, [envRule]);
    expect(findings.map((f) => f.ruleId)).toEqual(['secrets-infra/env-key-value']);
    expectNoEncodedLeak(redact(text, findings), value);
  });

  it('does not decode for non-secret rules', () => {
    const text = b64('contact record PERSON-ABCDEF on file\n');
    expect(scan(text, [NAME_RULE])).toEqual([]);
    expect(scan(text, [NAME_RULE, CANARY_RULE])).toEqual([]);
  });

  it('drops runs that decode to binary: random bytes, hashes, long identifiers', () => {
    const random = Buffer.from(Array.from({ length: 300 }, (_, i) => (i * 167 + 13) % 256));
    const text = [
      random.toString('base64'),
      'integrity sha512-' +
        Buffer.from(Array.from({ length: 64 }, (_, i) => (i * 31) % 256)).toString('base64'),
      'ThisIsAVeryLongCamelCaseIdentifierName',
      '/usr/local/lib/node_modules/some/package/dist/index',
    ].join('\n');
    expect(decodeEncodedSegments(text)).toEqual([]);
  });

  it('does not decode twice: base64 of base64 is out of reach', () => {
    expect(scan(b64(b64(ENV_FILE)), [CANARY_RULE])).toEqual([]);
  });
});

describe('encoded secrets — the finding carries the decoded value', () => {
  it('reports the same value, and so the same identity, as the plain secret', () => {
    const plain = scan(ENV_FILE, [CANARY_RULE]);
    for (const text of [b64(ENV_FILE), xxd(ENV_FILE), hexdumpC(ENV_FILE), hex(ENV_FILE)]) {
      const encoded = scan(text, [CANARY_RULE]);
      expect(encoded.map((f) => f.rawMatch)).toEqual(plain.map((f) => f.rawMatch));
    }
  });

  it('builds the masked preview from the secret, never from the dump around it', () => {
    // An email earlier on the dump line used to land in the encoded span, and
    // the email branch of maskMatch then revealed everything after its '@'.
    const text = xxd(`mail=a@b.com ${SECRET}\n`);
    const [finding] = scan(text, [CANARY_RULE]);
    expect(finding?.rawMatch).toBe(SECRET);
    const preview = maskMatch(finding?.rawMatch ?? '');
    for (let k = 0; k + 4 <= SECRET.length; k++) {
      expect(preview).not.toContain(SECRET.slice(k, k + 4));
    }
    expect(preview).not.toContain('@');
  });
});

describe('encoded secrets — decoding every value', () => {
  it('decodes each padded base64 value on its own line', () => {
    const text = `${b64('ordinary harmless message')}\n${b64(`token ${SECRET}`)}\n`;
    expect(scan(text, [CANARY_RULE]).map((f) => f.rawMatch)).toEqual([SECRET]);
  });

  it('decodes two padded values back to back on consecutive lines', () => {
    const first = b64(`ab ${SECRET}`);
    const second = b64(`b CANARY-0000AAAA1111`);
    expect(first.endsWith('=')).toBe(true);
    const found = scan(`${first}\n${second}\n`, [CANARY_RULE]).map((f) => f.rawMatch);
    expect(found).toEqual([SECRET, 'CANARY-0000AAAA1111']);
  });

  it('does not let a printable but wrong alignment hide the right one', () => {
    const text = `blob=xyz${b64(`${'A'.repeat(500)}${SECRET}`)}`;
    expect(scan(text, [CANARY_RULE]).map((f) => f.rawMatch)).toEqual([SECRET]);
  });

  it('decodes UTF-8, so invisible-character normalization still applies', () => {
    const padded = `${SECRET.slice(0, 10)}\u200b${SECRET.slice(10)}`;
    expect(scan(`token ${padded}`, [CANARY_RULE])).toHaveLength(1);
    const findings = scan(b64(`token ${padded}\n`), [CANARY_RULE]);
    expect(findings).toHaveLength(1);
    const [segment] = decodeEncodedSegments(b64(`passé ${padded}\n`));
    expect(segment?.text).toBe(`passé ${padded}\n`);
  });

  it('reads a short credential: eight bytes is enough', () => {
    const pinRule: Rule = RuleSchema.parse({
      specVersion: 1,
      id: 'test/pin',
      name: 'pin',
      category: 'secret',
      severity: 'high',
      matcher: { type: 'regex', pattern: 'pin=([0-9]{4})', flags: 'g', captureGroup: 1 },
    });
    expect(scan(b64('pin=4417'), [pinRule]).map((f) => f.rawMatch)).toEqual(['4417']);
    expect(scan(hex('pin=4417'), [pinRule]).map((f) => f.rawMatch)).toEqual(['4417']);
  });
});

describe('encoded secrets — od and plain hexdump', () => {
  it('finds a secret in od -An -tx1 output (space-separated bytes)', () => {
    const bytes = [...Buffer.from(ENV_FILE)].map((b) => b.toString(16).padStart(2, '0'));
    const lines: string[] = [];
    for (let at = 0; at < bytes.length; at += 16)
      lines.push(` ${bytes.slice(at, at + 16).join(' ')}`);
    const text = `${lines.join('\n')}\n`;
    const findings = scan(text, [CANARY_RULE]);
    expect(findings.map((f) => f.rawMatch)).toEqual([SECRET]);
    expectNoEncodedLeak(redact(text, findings).replace(/ /g, ''), SECRET);
  });

  it('finds a secret in plain hexdump output (little-endian 16-bit words)', () => {
    const buf = Buffer.from(ENV_FILE.length % 2 ? `${ENV_FILE} ` : ENV_FILE);
    const lines: string[] = [];
    for (let at = 0; at < buf.length; at += 16) {
      const words: string[] = [];
      for (let w = at; w < Math.min(at + 16, buf.length); w += 2) {
        words.push(
          `${(buf[w + 1] ?? 0).toString(16).padStart(2, '0')}${(buf[w] ?? 0).toString(16).padStart(2, '0')}`,
        );
      }
      lines.push(`${at.toString(16).padStart(7, '0')} ${words.join(' ')}`);
    }
    const findings = scan(`${lines.join('\n')}\n`, [CANARY_RULE]);
    expect(findings.map((f) => f.rawMatch)).toEqual([SECRET]);
  });
});

describe('encoded secrets — hex', () => {
  it('finds a secret in xxd -p output (plain hex, 60 digits per line)', () => {
    const text = `${(hex(ENV_FILE).match(/.{1,60}/g) ?? []).join('\n')}\n`;
    const findings = scan(text, [CANARY_RULE]);
    expect(findings).toHaveLength(1);
    expectNoEncodedLeak(redact(text, findings), SECRET);
  });

  it('finds a secret in default xxd output and masks the hex and the ASCII column', () => {
    const text = xxd(ENV_FILE);
    const findings = scan(text, [CANARY_RULE]);
    expect(findings).toHaveLength(1);
    const redacted = redact(text, findings);
    expectNoEncodedLeak(redacted, SECRET);
    // The ASCII column shows the secret in 16-byte pieces; no piece of 6+
    // characters may survive on any line.
    for (let k = 0; k + 6 <= SECRET.length; k++) {
      expect(redacted).not.toContain(SECRET.slice(k, k + 6));
    }
  });

  it('finds a secret in hexdump -C output and masks the hex and the ASCII column', () => {
    const text = hexdumpC(ENV_FILE);
    const findings = scan(text, [CANARY_RULE]);
    expect(findings).toHaveLength(1);
    const redacted = redact(text, findings);
    expectNoEncodedLeak(redacted.replace(/ /g, ''), SECRET);
    for (let k = 0; k + 6 <= SECRET.length; k++) {
      expect(redacted).not.toContain(SECRET.slice(k, k + 6));
    }
  });

  it('drops hex that decodes to binary: digests and random tokens', () => {
    const text = [
      'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3a94a8fe5ccb19ba61c4c0873',
      'SESSION_SECRET=0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a6978',
      '00000000: 0001 0203 0405 0607 0809 0a0b 0c0d 0e0f  ................',
    ].join('\n');
    expect(decodeEncodedSegments(text)).toEqual([]);
  });

  it('ignores lines that only look like a dump offset', () => {
    expect(decodeEncodedSegments('2026100400: job finished\n')).toEqual([]);
    expect(decodeEncodedSegments('00000000: zz\n')).toEqual([]);
  });

  it('maps a partial last dump line and a missing ASCII column to the hex alone', () => {
    const line = `00000000: ${
      hex('token CANARY-')
        .match(/.{1,4}/g)
        ?.join(' ') ?? ''
    }`;
    const [segment] = decodeEncodedSegments(`${line}\n`);
    if (segment === undefined) throw new Error('the dump line did not decode');
    expect(segment.text).toBe('token CANARY-');
    const span = sourceSpanOf(segment, 0, 1);
    expect(line.slice(span.start, span.end)).toBe('74');
  });
});

describe('encoded secrets — bounds', () => {
  it('searches only the first MAX_ENCODED_SEARCH_CHARS characters', () => {
    const pad = '.'.repeat(MAX_ENCODED_SEARCH_CHARS);
    expect(scan(`${pad}\n${b64(ENV_FILE)}\n`, [CANARY_RULE])).toEqual([]);
    // Coverage stopped: the report must be able to say so, not run silently.
    const coverage = decodeEncodedWithCoverage(`${pad}\n${b64(ENV_FILE)}\n`);
    expect(coverage.truncated).toBe(true);
    expect(coverage.unscannedChars).toBeGreaterThan(0);
  });

  it('refuses the segment that crosses the decoded budget instead of scanning a truncated prefix', () => {
    const text = `${b64('x'.repeat(121))}\n${b64(ENV_FILE)}\n`;
    const uncapped = decodeEncodedSegments(text).reduce((n, s) => n + s.text.length, 0);
    expect(uncapped).toBeGreaterThan(150);
    const coverage = decodeEncodedWithCoverage(text, { maxDecodedChars: 150 });
    // The first value still fits; the value that would have been SLICED at
    // the old bound is refused whole — a sliced prefix lets a rule match a
    // partial value (`CANARY-7` for `CANARY-7Q2W…`) and redact only it, leaving
    // the secret's encoded tail one base64 group away from the mask.
    expect(coverage.segments.map((s) => s.text.length)).toEqual([121]);
    expect(coverage.truncated).toBe(true);
    expect(coverage.unscannedChars).toBeGreaterThan(0);
    for (const segment of coverage.segments) {
      expect(segment.starts.length).toBe(segment.text.length);
      expect(segment.ends.length).toBe(segment.text.length);
    }
  });

  it('keeps the default cap at MAX_DECODED_CHARS', () => {
    expect(MAX_DECODED_CHARS).toBe(200_000);
  });

  it('decodes the worst shapes at the search bound within a pinned budget', () => {
    // the assertion, the timeout only bounds the harness. // vitest's 20 s default on a busy machine; the per-shape bound below is // Six shapes × four runs of ~200,000-character decodes take well over
    // Measured with the module memo bypassed (`limits` passed, warmed, minimum
    // of three runs, 200,000-character inputs): uninstrumented, Node 26 on this
    // machine, the worst shape is ~250 ms (single base64 run ~180, single hex
    // run ~245, wrapped base64 ~230, hexdump ~45, hex tokens ~210). Under the
    // suite's v8 coverage instrumentation the same shapes read ~4-5x higher
    // (~1300 ms alone, more when several suites share a core), so the bound
    // pins the instrumented worst at ~4x — a 5x regression of the real cost
    // (the claim this test exists to catch) pushes the instrumented reading
    // past 6 s and fails. Measured worst shapes: single base64 run and hex
    // tokens.
    //
    // Production edge this protects: the MCP walk carries up to
    // MCP_MAX_TOTAL_CHARS = 5,000,000 characters per tool input
    // (plugins/claude-code/src/hooks/pre-tool-use-fields.ts) and the decode is
    // charged per capture, so ~25 captures of 200,000 characters cost ~25x one
    // decode — seconds against the hook's 10 s timeout, which fails OPEN
    // unscanned when it fires.
    const shapes = [
      'A'.repeat(MAX_ENCODED_SEARCH_CHARS),
      'ab\n'.repeat(MAX_ENCODED_SEARCH_CHARS / 3),
      `${'QUJD'.repeat(19)}\n`.repeat(MAX_ENCODED_SEARCH_CHARS / 77),
      `${'0'.repeat(60)}\n`.repeat(MAX_ENCODED_SEARCH_CHARS / 61),
      '00000000: 4142 4344  ABCD\n'.repeat(MAX_ENCODED_SEARCH_CHARS / 26),
      `${'41'.repeat(30)}\n`.repeat(MAX_ENCODED_SEARCH_CHARS / 61),
    ];
    for (const text of shapes) {
      decodeEncodedSegments(text, {}); // warm
      const times: number[] = [];
      for (let run = 0; run < 3; run++) {
        const started = performance.now();
        decodeEncodedSegments(text, {}); // `{}` bypasses the module memo
        times.push(performance.now() - started);
      }
      expect(Math.min(...times), `shape ${JSON.stringify(text.slice(0, 20))}`).toBeLessThan(5_000);
    }
  }, 120_000);
});

describe('encoded secrets — truncated coverage', () => {
  const envRule = loadRule(`${RULES_DIR}/secrets-infra`, 'env-key-value');
  const keyRule: Rule = RuleSchema.parse({
    specVersion: 1,
    id: 'test/key',
    name: 'key',
    category: 'secret',
    severity: 'high',
    matcher: { type: 'regex', pattern: 'WIDGET_API_KEY=[A-Za-z0-9]+', flags: 'g' },
  });

  it('does not report a secret whose encoded span the search window cut', () => {
    // The window slices the encoded run, so the decode stops mid-value: the
    // rules matched `CANARY-7` of `CANARY-7Q2W9E4R1T6Y8U3I5O0P` and the
    // redaction masked only that group, leaving the secret's tail one base64
    // group away from the `[REDACTED]` marker. A segment the window could cut
    // is refused whole instead.
    const text = `${'.'.repeat(199_960)}\n${b64('export SERVICE_TOKEN=CANARY-7Q2W9E4R1T6Y8U3I5O0P')}`;
    expect(scan(text, [envRule])).toEqual([]);
    const coverage = decodeEncodedWithCoverage(text);
    expect(coverage.truncated).toBe(true);
    expect(coverage.unscannedChars).toBeGreaterThan(0);
  });

  it('reports a base64 secret followed by a glued word, with or without a line break', () => {
    // The run's continuation used to absorb any following alphabet-only text,
    // and when the concatenation failed the printable ratio the WHOLE segment
    // was dropped — the same blob alone was found, with a trailing word it
    // was neither reported nor redacted.
    const blob = b64(`token=token=${SECRET}\n\n`);
    for (const suffix of ['trailer', 'success', '\ntrailer\n', '\nsuccess']) {
      const found = scan(`${blob}${suffix}`, [CANARY_RULE]).map((f) => f.rawMatch);
      expect(found, suffix).toEqual([SECRET]);
      const segments = decodeEncodedSegments(`${blob}${suffix}`);
      expect(
        segments.some((s) => s.text.includes(SECRET)),
        suffix,
      ).toBe(true);
    }
  });

  it('keeps the finding identity free of replacement characters when a word is glued to the run', () => {
    // The glued word's bits decoded into the value's tail as U+FFFD, so the
    // fingerprint, the ledger and the masked preview keyed on a value that
    // never matches the same secret seen in the clear.
    const glueRule: Rule = RuleSchema.parse({
      specVersion: 1,
      id: 'test/glue',
      name: 'glue',
      category: 'secret',
      severity: 'high',
      matcher: { type: 'regex', pattern: 'token=[A-Za-z0-9=-]+', flags: 'g' },
    });
    const value = `token=${SECRET}8U3I5O0P`;
    const encodedText = b64(value) + 'success';
    const [encoded] = scan(encodedText, [glueRule]);
    const [plain] = scan(`${value} plain`, [glueRule]);
    expect(encoded, 'the encoded spelling must still be found').toBeDefined();
    expect(encoded?.rawMatch).not.toContain('\ufffd');
    expect(encoded?.rawMatch).toBe(plain?.rawMatch);
  });

  it('a dump earlier in the payload must not hide a key later in it', () => {
    // Four alignments of one large run used to charge the same budget once
    // per offer, so the run exhausted it before the secret's segment was
    // reached — and the drop was invisible. The run is now charged its longest
    // view once, so the later key is found and coverage stays whole. (The dump
    // is sized so the whole text stays inside the 200,000-character search
    // window; past it, the window itself hides what follows — see the
    // window-cut test above.)
    const text =
      b64('A'.repeat(74_002)) +
      '\n' +
      b64('export WIDGET_API_KEY=q8Zr2LmX0vT4bN7kY1sD5fH9jW3pC6aE\n');
    expect(
      scan(b64('export WIDGET_API_KEY=q8Zr2LmX0vT4bN7kY1sD5fH9jW3pC6aE\n'), [keyRule]),
    ).toHaveLength(1);
    expect(scan(text, [keyRule]).map((f) => f.rawMatch)).toEqual([
      'WIDGET_API_KEY=q8Zr2LmX0vT4bN7kY1sD5fH9jW3pC6aE',
    ]);
    const coverage = decodeEncodedWithCoverage(text);
    expect(coverage.truncated).toBe(false);
    expect(coverage.unscannedChars).toBe(0);
  });

  it('exposes what the decode could not cover, beside the segments', () => {
    const clean = decodeEncodedWithCoverage(b64(ENV_FILE));
    expect(clean.truncated).toBe(false);
    expect(clean.unscannedChars).toBe(0);
    expect(clean.segments.length).toBeGreaterThan(0);
  });
});
