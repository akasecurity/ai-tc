import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  CODEX_CONFIG_MAX_BYTES,
  codexSystemConfigPath,
  parseTomlStrings,
  readCodexProviderConfig,
  UNSAFE_TEST_ONLY_setCodexSystemConfigPath,
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

describe('readCodexProviderConfig', () => {
  let home: string;
  let system: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'aka-codex-config-'));
    system = join(home, 'system.toml');
    UNSAFE_TEST_ONLY_setCodexSystemConfigPath(system);
  });

  afterEach(() => {
    UNSAFE_TEST_ONLY_setCodexSystemConfigPath(join(tmpdir(), 'aka-no-such-codex-system.toml'));
    rmSync(home, { recursive: true, force: true });
  });

  const user = (lines: readonly string[]): void => {
    writeFileSync(join(home, 'config.toml'), lines.join('\n'));
  };

  it('reads openai with no base URL when nothing is configured', () => {
    expect(readCodexProviderConfig(home)).toEqual({ provider: 'openai', baseUrl: undefined });
    expect(readCodexProviderConfig(undefined)).toEqual({ provider: 'openai', baseUrl: undefined });
  });

  it('reads the base_url of the selected provider', () => {
    user([
      'model_provider = "az"',
      '[model_providers.az]',
      'base_url = "https://x.openai.azure.com"',
    ]);
    expect(readCodexProviderConfig(home)).toEqual({
      provider: 'az',
      baseUrl: 'https://x.openai.azure.com',
    });
  });

  it('reads openai_base_url for the built-in openai provider', () => {
    user(['openai_base_url = "https://proxy.internal/v1"']);
    expect(readCodexProviderConfig(home)).toEqual({
      provider: 'openai',
      baseUrl: 'https://proxy.internal/v1',
    });
  });

  it.each(['openai', 'ollama', 'lmstudio'])(
    'ignores a [model_providers.%s] entry, which Codex does not let a user override',
    (id) => {
      user([
        `model_provider = "${id}"`,
        `[model_providers.${id}]`,
        'base_url = "https://x.openai.azure.com/openai/v1"',
      ]);
      expect(readCodexProviderConfig(home)).toEqual({ provider: id, baseUrl: undefined });
    },
  );

  it('falls back to the top-level provider when the profile names none', () => {
    user([
      'profile = "p"',
      'model_provider = "az"',
      '[profiles.p]',
      'model = "gpt-5"',
      '[model_providers.az]',
      'base_url = "https://x"',
    ]);
    expect(readCodexProviderConfig(home).baseUrl).toBe('https://x');
  });

  it('reads the system file underneath the user file, key by key', () => {
    writeFileSync(
      system,
      [
        'model_provider = "az"',
        'openai_base_url = "https://system.proxy"',
        '[model_providers.az]',
        'base_url = "https://x.openai.azure.com"',
      ].join('\n'),
    );
    expect(readCodexProviderConfig(home).baseUrl).toBe('https://x.openai.azure.com');
    user(['model_provider = "openai"']);
    expect(readCodexProviderConfig(home)).toEqual({
      provider: 'openai',
      baseUrl: 'https://system.proxy',
    });
    user(['model_provider = "openai"', 'openai_base_url = "https://user.proxy"']);
    expect(readCodexProviderConfig(home).baseUrl).toBe('https://user.proxy');
  });

  it('treats an unreadable user file as absent and keeps the system layer', () => {
    writeFileSync(system, 'openai_base_url = "https://system.proxy"\n');
    user(['model_provider = "az']);
    expect(readCodexProviderConfig(home).baseUrl).toBe('https://system.proxy');
  });

  it('strips a leading byte order mark', () => {
    writeFileSync(join(home, 'config.toml'), '\uFEFFopenai_base_url = "https://bom.proxy"\n');
    expect(readCodexProviderConfig(home).baseUrl).toBe('https://bom.proxy');
  });

  it('reads nothing from a missing file, a directory, or a file over the size bound', () => {
    mkdirSync(join(home, 'config.toml'));
    expect(readCodexProviderConfig(home).baseUrl).toBeUndefined();
    rmSync(join(home, 'config.toml'), { recursive: true });
    writeFileSync(
      join(home, 'config.toml'),
      `openai_base_url = "https://x"\n# ${'x'.repeat(CODEX_CONFIG_MAX_BYTES)}\n`,
    );
    expect(readCodexProviderConfig(home).baseUrl).toBeUndefined();
  });
});

describe('codexSystemConfigPath', () => {
  it('names the system file for each platform', () => {
    expect(codexSystemConfigPath('linux')).toBe('/etc/codex/config.toml');
    expect(codexSystemConfigPath('darwin')).toBe('/etc/codex/config.toml');
    expect(codexSystemConfigPath('win32')).toBe('C:\\ProgramData\\OpenAI\\Codex\\config.toml');
  });
});
