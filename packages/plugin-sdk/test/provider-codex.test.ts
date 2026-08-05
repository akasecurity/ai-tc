/**
 * Unit tests for Codex CLI provider resolution.
 *
 *   - resolveCodexProvider(): the env cascade (gateway-via-OPENAI_BASE_URL > openai).
 *       Env is injected with vi.stubEnv so each branch is exercised in isolation.
 *   - codexProviderFromModelId(): the pure model-id heuristic (no env).
 */

import { afterEach, describe, expect, it, vi } from 'vitest';

import { codexProviderFromModelId, resolveCodexProvider } from '../src/provider-codex.ts';

function clearProviderEnv(): void {
  vi.stubEnv('OPENAI_BASE_URL', '');
}

afterEach(() => {
  vi.unstubAllEnvs();
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
