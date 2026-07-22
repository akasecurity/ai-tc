import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { HttpMethod, Transport } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  EGRESS_CODE_EXTENSIONS,
  extractEgress,
  isVendoredPath,
  redactSnippet,
} from '../../src/egress/extract.ts';
import { resolveHost } from '../../src/egress/registry.ts';

const fixturesDir = join(fileURLToPath(new URL('.', import.meta.url)), '../../src/egress/fixtures');

const SNIPPET_MAX = 200;

interface ExpectedHit {
  url: string;
  host: string;
  port: number | null;
  transport: Transport;
  method: HttpMethod;
  template: boolean;
  line: number;
  snippet?: string;
}

// `text` may be a single string or an array of lines joined with '\n', so
// multi-line cases stay readable in the fixture. `resolvesToNull` marks hits
// the extractor emits raw but the registry excludes downstream.
interface ExtractionCase {
  label: string;
  text: string | string[];
  expect: ExpectedHit[];
  resolvesToNull?: boolean;
}

interface RedactionCase {
  label: string;
  line: string;
  expect: string;
}

function loadCases<T>(file: string): T[] {
  return JSON.parse(readFileSync(join(fixturesDir, file), 'utf8')) as T[];
}

function textOf(c: ExtractionCase): string {
  return Array.isArray(c.text) ? c.text.join('\n') : c.text;
}

function comparable(hit: ExpectedHit): Omit<ExpectedHit, 'snippet'> {
  return {
    url: hit.url,
    host: hit.host,
    port: hit.port,
    transport: hit.transport,
    method: hit.method,
    template: hit.template,
    line: hit.line,
  };
}

function describeExtractionCorpus(title: string, file: string): void {
  const cases = loadCases<ExtractionCase>(file);

  describe(title, () => {
    it('carries at least 2 positive and 2 negative cases', () => {
      expect(cases.filter((c) => c.expect.length > 0).length).toBeGreaterThanOrEqual(2);
      expect(cases.filter((c) => c.expect.length === 0).length).toBeGreaterThanOrEqual(2);
    });

    it.each(cases.map((c) => [c.label, c] as const))('%s', (_label, c) => {
      const hits = extractEgress(textOf(c));

      expect(hits.map((h) => comparable(h))).toEqual(c.expect.map((e) => comparable(e)));

      c.expect.forEach((want, i) => {
        if (want.snippet !== undefined) expect(hits[i]?.snippet).toBe(want.snippet);
      });

      for (const hit of hits) {
        expect(hit.snippet.length).toBeLessThanOrEqual(SNIPPET_MAX);
        if (c.resolvesToNull === true) expect(resolveHost(hit.host)).toBeNull();
      }
    });
  });
}

describeExtractionCorpus('extractEgress — url corpus', 'url-extraction.json');
describeExtractionCorpus('extractEgress — method-inference corpus', 'method-inference.json');
describeExtractionCorpus('extractEgress — bare-IP corpus', 'ip-extraction.json');

describe('extractEgress — general shape', () => {
  it('returns nothing for text with no destination literal', () => {
    expect(extractEgress('export function add(a: number, b: number) {\n  return a + b;\n}\n')).toEqual(
      [],
    );
  });

  it('returns hits in line order', () => {
    const hits = extractEgress(
      [
        "const c = 'https://api.stripe.com/v1/charges';",
        "const t = 'https://api.twilio.com/2010-04-01/Accounts';",
        "const s = 'https://sentry.io/api/1/store/';",
      ].join('\n'),
    );
    expect(hits.map((h) => h.line)).toEqual([1, 2, 3]);
  });

  it('redacts the snippet it stores alongside a hit', () => {
    const hits = extractEgress("fetch('https://api.acme-corp.com/v1?token=SUPERSECRET');");
    expect(hits).toHaveLength(1);
    expect(hits[0]?.snippet).toBe("fetch('https://api.acme-corp.com/v1?token=••••');");
    expect(hits[0]?.snippet).not.toContain('SUPERSECRET');
  });

  it('never emits a snippet longer than the cap', () => {
    const padding = 'y'.repeat(400);
    const hits = extractEgress(`const u = 'https://api.acme-corp.com/v1'; // ${padding}`);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.snippet.length).toBe(SNIPPET_MAX);
  });
});

describe('redactSnippet — fixture corpus', () => {
  const cases = loadCases<RedactionCase>('snippet-redaction.json');

  it('carries at least 2 masking and 2 pass-through cases', () => {
    expect(cases.filter((c) => c.line.trim() !== c.expect).length).toBeGreaterThanOrEqual(2);
    expect(cases.filter((c) => c.line.trim() === c.expect).length).toBeGreaterThanOrEqual(2);
  });

  it.each(cases.map((c) => [c.label, c] as const))('%s', (_label, c) => {
    const redacted = redactSnippet(c.line);
    expect(redacted).toBe(c.expect);
    expect(redacted.length).toBeLessThanOrEqual(SNIPPET_MAX);
  });
});

describe('EGRESS_CODE_EXTENSIONS', () => {
  it('mirrors the scanner source-extension list, dots included', () => {
    expect([...EGRESS_CODE_EXTENSIONS]).toEqual([
      '.ts',
      '.tsx',
      '.js',
      '.jsx',
      '.mjs',
      '.cjs',
      '.py',
      '.java',
      '.rb',
      '.cs',
      '.php',
      '.go',
      '.rs',
    ]);
  });

  it('matches extname output, so a dotless extension is not a member', () => {
    expect(EGRESS_CODE_EXTENSIONS.has('.ts')).toBe(true);
    expect(EGRESS_CODE_EXTENSIONS.has('ts')).toBe(false);
    expect(EGRESS_CODE_EXTENSIONS.has('.md')).toBe(false);
  });
});

describe('isVendoredPath', () => {
  it.each([
    ['vendor/lib/client.go', true],
    ['src/vendor/aws/client.ts', true],
    ['third_party/grpc/stub.py', true],
    ['external/sdk/index.js', true],
    ['a/b/vendor/c/d.rb', true],
  ])('treats %s as vendored', (file, expected) => {
    expect(isVendoredPath(file)).toBe(expected);
  });

  it.each([
    ['src/vendored.ts', false],
    ['src/myvendor/x.ts', false],
    ['src/external.ts', false],
    ['vendor.ts', false],
    ['src/app/main.ts', false],
  ])('treats %s as not vendored', (file, expected) => {
    expect(isVendoredPath(file)).toBe(expected);
  });
});
