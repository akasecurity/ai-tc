import type { Rule } from '@akasecurity/schema';
import { Rule as RuleSchema } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  decodeEncodedSegments,
  MAX_DECODED_CHARS,
  MAX_ENCODED_SEARCH_CHARS,
  sourceSpanOf,
} from '../src/encoded.ts';
import { redact, scan } from '../src/engine.ts';
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
    expect(finding?.rawMatch).toBe(text.slice(finding?.span.start, finding?.span.end));
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
  });

  it('stops decoding once MAX_DECODED_CHARS characters have been decoded', () => {
    const filler = b64('x'.repeat(MAX_DECODED_CHARS));
    const text = `${filler}\n${b64(ENV_FILE)}`.slice(0, MAX_ENCODED_SEARCH_CHARS);
    const segments = decodeEncodedSegments(text);
    const decoded = segments.reduce((n, s) => n + s.text.length, 0);
    expect(decoded).toBeLessThanOrEqual(MAX_DECODED_CHARS);
  });

  it('stays fast on adversarial runs at the search bound', () => {
    const shapes = [
      'A'.repeat(MAX_ENCODED_SEARCH_CHARS),
      'ab\n'.repeat(MAX_ENCODED_SEARCH_CHARS / 3),
      `${'QUJD'.repeat(19)}\n`.repeat(MAX_ENCODED_SEARCH_CHARS / 77),
      `${'0'.repeat(60)}\n`.repeat(MAX_ENCODED_SEARCH_CHARS / 61),
      '00000000: 4142 4344  ABCD\n'.repeat(MAX_ENCODED_SEARCH_CHARS / 26),
      `${'41'.repeat(30)}\n`.repeat(MAX_ENCODED_SEARCH_CHARS / 61),
    ];
    for (const text of shapes) {
      const started = performance.now();
      scan(text, [CANARY_RULE]);
      expect(performance.now() - started).toBeLessThan(1_000);
    }
  });
});
