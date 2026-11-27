import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  CODEX_CONFIG_MAX_BYTES,
  parseTomlStrings,
  readCodexActiveProviderBaseUrl,
} from '../src/codex-config.ts';

const at = (...path: string[]): string => JSON.stringify(path);

describe('parseTomlStrings', () => {
  it('reads strings under tables, dotted keys and quoted keys', () => {
    const values = parseTomlStrings(
      [
        'a = "top"',
        'n = 3',
        'flag = true',
        '[t."quoted.key"]',
        "lit = 'C:\\path'",
        'x.y = "dotted"',
      ].join('\r\n'),
    );
    expect(values?.get(at('a'))).toBe('top');
    expect(values?.get(at('t', 'quoted.key', 'lit'))).toBe('C:\\path');
    expect(values?.get(at('t', 'quoted.key', 'x', 'y'))).toBe('dotted');
    expect(values?.has(at('n'))).toBe(false);
  });

  it('reads escapes and multi-line strings', () => {
    const values = parseTomlStrings(
      ['e = "a\\"b\\u00e9\\n"', 'm = """', 'one \\', '  two"""'].join('\n'),
    );
    expect(values?.get(at('e'))).toBe('a"bé\n');
    expect(values?.get(at('m'))).toBe('one two');
  });

  it('reads strings inside inline tables, and skips arrays and arrays of tables', () => {
    const values = parseTomlStrings(
      [
        'p = { azure = { base_url = "https://x" }, n = 1 }',
        'list = [ "a", [1, 2], { k = "v" } ]',
        '[[mcp]]',
        'base_url = "ignored"',
      ].join('\n'),
    );
    expect(values?.get(at('p', 'azure', 'base_url'))).toBe('https://x');
    expect(values?.has(at('base_url'))).toBe(false);
  });

  it.each([
    ['an unterminated string', 'a = "open'],
    ['an unterminated table header', '[t'],
    ['a missing value', 'a ='],
    ['text after a value', 'a = "x" y'],
    ['an unknown escape', 'a = "\\q"'],
    ['an unclosed array', 'a = [1, 2'],
  ])('answers undefined for %s', (_label, src) => {
    expect(parseTomlStrings(src)).toBeUndefined();
  });

  it('answers undefined for nesting past its depth bound', () => {
    expect(parseTomlStrings(`a = ${'['.repeat(100)}${']'.repeat(100)}`)).toBeUndefined();
  });
});

describe('readCodexActiveProviderBaseUrl', () => {
  let home: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'aka-codex-config-'));
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  it('reads the base_url of the selected provider', () => {
    writeFileSync(
      join(home, 'config.toml'),
      'model_provider = "az"\n[model_providers.az]\nbase_url = "https://x.openai.azure.com"\n',
    );
    expect(readCodexActiveProviderBaseUrl(home)).toBe('https://x.openai.azure.com');
  });

  it('falls back to the top-level provider when the profile names none', () => {
    writeFileSync(
      join(home, 'config.toml'),
      [
        'profile = "p"',
        'model_provider = "az"',
        '[profiles.p]',
        'model = "gpt-5"',
        '[model_providers.az]',
        'base_url = "https://x"',
      ].join('\n'),
    );
    expect(readCodexActiveProviderBaseUrl(home)).toBe('https://x');
  });

  it('answers undefined for a missing file, a directory, or a file over the size bound', () => {
    expect(readCodexActiveProviderBaseUrl(home)).toBeUndefined();
    mkdirSync(join(home, 'config.toml'));
    expect(readCodexActiveProviderBaseUrl(home)).toBeUndefined();
    rmSync(join(home, 'config.toml'), { recursive: true });
    writeFileSync(
      join(home, 'config.toml'),
      `model_provider = "az"\n[model_providers.az]\nbase_url = "https://x"\n# ${'x'.repeat(CODEX_CONFIG_MAX_BYTES)}\n`,
    );
    expect(readCodexActiveProviderBaseUrl(home)).toBeUndefined();
  });
});
