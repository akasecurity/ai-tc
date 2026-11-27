/**
 * Unit tests for Codex CLI provider resolution.
 *
 *   - resolveCodexProvider(): Azure from config.toml's active provider, then the
 *       OPENAI_BASE_URL cascade (azure > gateway > openai). Env is injected with
 *       vi.stubEnv, and CODEX_HOME points at a fresh temporary directory per case.
 *   - codexProviderFromModelId(): the pure model-id heuristic (no env).
 */

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { codexProviderFromModelId, resolveCodexProvider } from '../src/provider-codex.ts';

let codexHome: string;

function clearProviderEnv(): void {
  vi.stubEnv('OPENAI_BASE_URL', '');
  vi.stubEnv('CODEX_HOME', codexHome);
}

function writeCodexConfig(lines: readonly string[]): void {
  writeFileSync(join(codexHome, 'config.toml'), lines.join('\n'));
}

beforeEach(() => {
  codexHome = mkdtempSync(join(tmpdir(), 'aka-codex-provider-'));
});

afterEach(() => {
  vi.unstubAllEnvs();
  rmSync(codexHome, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// resolveCodexProvider — env cascade
// ---------------------------------------------------------------------------

describe('resolveCodexProvider', () => {
  it('returns openai when no provider env is set', () => {
    clearProviderEnv();
    expect(resolveCodexProvider()).toEqual({ provider: 'openai' });
  });

  it('returns gateway with host when OPENAI_BASE_URL is a non-default host', () => {
    clearProviderEnv();
    vi.stubEnv('OPENAI_BASE_URL', 'https://litellm.internal:4000/v1');
    expect(resolveCodexProvider()).toEqual({
      provider: 'gateway',
      gatewayHost: 'litellm.internal:4000',
    });
  });

  it('returns gateway for a scheme-less OPENAI_BASE_URL (bare host)', () => {
    clearProviderEnv();
    vi.stubEnv('OPENAI_BASE_URL', 'localhost:11434');
    expect(resolveCodexProvider()).toEqual({
      provider: 'gateway',
      gatewayHost: 'localhost:11434',
    });
  });

  it('returns openai when OPENAI_BASE_URL points at the default host', () => {
    clearProviderEnv();
    vi.stubEnv('OPENAI_BASE_URL', 'https://api.openai.com');
    expect(resolveCodexProvider()).toEqual({ provider: 'openai' });
  });

  it('returns openai when OPENAI_BASE_URL is malformed', () => {
    // A malformed value must not throw — it degrades to undefined and the
    // cascade falls through to the default, same as provider.ts's regression.
    clearProviderEnv();
    vi.stubEnv('OPENAI_BASE_URL', '::not a url');
    expect(resolveCodexProvider()).toEqual({ provider: 'openai' });
  });

  it('returns azure when OPENAI_BASE_URL is an Azure OpenAI endpoint', () => {
    clearProviderEnv();
    vi.stubEnv('OPENAI_BASE_URL', 'https://x.openai.azure.com/openai/v1');
    expect(resolveCodexProvider()).toEqual({ provider: 'azure' });
  });

  it('returns azure when OPENAI_BASE_URL is an Azure AI Foundry endpoint', () => {
    clearProviderEnv();
    vi.stubEnv('OPENAI_BASE_URL', 'https://X.Services.AI.Azure.com:443/openai/v1');
    expect(resolveCodexProvider()).toEqual({ provider: 'azure' });
  });

  it.each([
    ['https://azure.example.com/v1', 'azure.example.com'],
    ['https://openai.azure.com.evil.io/v1', 'openai.azure.com.evil.io'],
    ['https://x.openai.azure.com.evil.io/v1', 'x.openai.azure.com.evil.io'],
    ['https://openai.azure.com/v1', 'openai.azure.com'],
    ['https://evilopenai.azure.com/v1', 'evilopenai.azure.com'],
  ])('keeps %s, which is not under an Azure suffix, a gateway', (url, host) => {
    clearProviderEnv();
    vi.stubEnv('OPENAI_BASE_URL', url);
    expect(resolveCodexProvider()).toEqual({ provider: 'gateway', gatewayHost: host });
  });

  it('returns azure when the active config.toml provider has an Azure base_url', () => {
    clearProviderEnv();
    writeCodexConfig([
      'model = "gpt-5-codex"',
      'model_provider = "azure"',
      '',
      '[model_providers.azure]',
      'name = "Azure"',
      'base_url = "https://x.services.ai.azure.com/openai/v1" # the resource',
      'env_key = "AZURE_OPENAI_API_KEY"',
      'wire_api = "responses"',
    ]);
    expect(resolveCodexProvider()).toEqual({ provider: 'azure' });
  });

  it('returns azure for an Azure provider chosen by the active profile', () => {
    clearProviderEnv();
    writeCodexConfig([
      'profile = "work"',
      'model_provider = "openai"',
      '',
      '[profiles.work]',
      'model_provider = "az"',
      '',
      '[model_providers."az"]',
      "base_url = 'https://x.openai.azure.com/openai/v1'",
    ]);
    expect(resolveCodexProvider()).toEqual({ provider: 'azure' });
  });

  it('reads a dotted-key base_url for the active provider', () => {
    clearProviderEnv();
    writeCodexConfig([
      'model_provider = "azure"',
      'model_providers.azure.base_url = "https://x.openai.azure.com/openai/v1"',
    ]);
    expect(resolveCodexProvider()).toEqual({ provider: 'azure' });
  });

  it('prefers an Azure config.toml provider over a gateway OPENAI_BASE_URL', () => {
    clearProviderEnv();
    vi.stubEnv('OPENAI_BASE_URL', 'https://litellm.internal:4000/v1');
    writeCodexConfig([
      'model_provider = "azure"',
      '[model_providers.azure]',
      'base_url = "https://x.openai.azure.com/openai/v1"',
    ]);
    expect(resolveCodexProvider()).toEqual({ provider: 'azure' });
  });

  it('ignores an Azure provider entry that is not the active provider', () => {
    clearProviderEnv();
    writeCodexConfig([
      '[model_providers.azure]',
      'base_url = "https://x.openai.azure.com/openai/v1"',
    ]);
    expect(resolveCodexProvider()).toEqual({ provider: 'openai' });
  });

  it('keeps the env result when the active config.toml provider is not on Azure', () => {
    clearProviderEnv();
    writeCodexConfig([
      'model_provider = "proxy"',
      '[model_providers.proxy]',
      'base_url = "https://openai.azure.com.evil.io/v1"',
    ]);
    expect(resolveCodexProvider()).toEqual({ provider: 'openai' });
    vi.stubEnv('OPENAI_BASE_URL', 'https://litellm.internal:4000/v1');
    expect(resolveCodexProvider()).toEqual({
      provider: 'gateway',
      gatewayHost: 'litellm.internal:4000',
    });
  });

  it('does not read a section header inside a multi-line string or array', () => {
    clearProviderEnv();
    writeCodexConfig([
      'model_provider = "azure"',
      'notes = """',
      '[model_providers.azure]',
      'base_url = "https://x.openai.azure.com/openai/v1"',
      '"""',
      'args = [',
      '  ["[model_providers.azure]"],',
      '  "base_url = 1",',
      ']',
    ]);
    expect(resolveCodexProvider()).toEqual({ provider: 'openai' });
  });

  it('falls back to the env result when config.toml cannot be read as TOML', () => {
    clearProviderEnv();
    writeCodexConfig(['model_provider = "azure', '[model_providers.azure', 'base_url = 7']);
    expect(resolveCodexProvider()).toEqual({ provider: 'openai' });
  });

  it('falls back to the env result when CODEX_HOME holds no config.toml', () => {
    clearProviderEnv();
    vi.stubEnv('OPENAI_BASE_URL', 'https://x.openai.azure.com/openai/v1');
    expect(resolveCodexProvider()).toEqual({ provider: 'azure' });
  });
});

// ---------------------------------------------------------------------------
// codexProviderFromModelId — pure heuristic (no env)
// ---------------------------------------------------------------------------

describe('codexProviderFromModelId', () => {
  it('classifies plain gpt-* ids as openai', () => {
    expect(codexProviderFromModelId('gpt-5-codex')).toBe('openai');
  });

  it('classifies o1/o3/o4 ids as openai', () => {
    expect(codexProviderFromModelId('o3')).toBe('openai');
    expect(codexProviderFromModelId('o4-mini')).toBe('openai');
  });

  it('classifies codex-* ids as openai', () => {
    expect(codexProviderFromModelId('codex-mini-latest')).toBe('openai');
  });

  it('classifies vendor-prefixed gateway ids (azure/…)', () => {
    expect(codexProviderFromModelId('azure/gpt-5-codex')).toBe('gateway');
  });

  it('classifies name:tag gateway-routed ids', () => {
    expect(codexProviderFromModelId('openrouter:gpt-5')).toBe('gateway');
  });

  it('returns unknown for unrecognized ids', () => {
    expect(codexProviderFromModelId('claude-3-5-sonnet')).toBe('unknown');
  });

  it('returns unknown for an empty / whitespace id', () => {
    expect(codexProviderFromModelId('')).toBe('unknown');
    expect(codexProviderFromModelId('   ')).toBe('unknown');
  });
});
