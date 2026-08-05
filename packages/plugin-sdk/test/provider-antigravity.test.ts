/**
 * Unit tests for Antigravity provider resolution.
 *
 *   - resolveAntigravityProvider(): the env cascade
 *       (gateway-via-GOOGLE_GEMINI_BASE_URL > vertex > google).
 *       Env is injected with vi.stubEnv so each branch is exercised in isolation.
 *   - antigravityProviderFromModelId(): the pure model-id heuristic (no env).
 */

import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  antigravityProviderFromModelId,
  resolveAntigravityProvider,
} from '../src/provider-antigravity.ts';

function clearProviderEnv(): void {
  vi.stubEnv('GOOGLE_GENAI_USE_VERTEXAI', '');
  vi.stubEnv('GOOGLE_GEMINI_BASE_URL', '');
}

afterEach(() => {
  vi.unstubAllEnvs();
});

// ---------------------------------------------------------------------------
// resolveAntigravityProvider — env cascade
// ---------------------------------------------------------------------------

describe('resolveAntigravityProvider', () => {
  it('returns google when no provider env is set', () => {
    clearProviderEnv();
    expect(resolveAntigravityProvider()).toEqual({ provider: 'google' });
  });

  it('returns vertex when GOOGLE_GENAI_USE_VERTEXAI is truthy', () => {
    clearProviderEnv();
    vi.stubEnv('GOOGLE_GENAI_USE_VERTEXAI', '1');
    expect(resolveAntigravityProvider()).toEqual({ provider: 'vertex' });
  });

  it('treats "0" and "false" as OFF rather than as a set flag', () => {
    // A shell that exports the var to an explicitly falsy value must not be
    // read as "Vertex on" — the string is non-empty either way.
    clearProviderEnv();
    vi.stubEnv('GOOGLE_GENAI_USE_VERTEXAI', '0');
    expect(resolveAntigravityProvider()).toEqual({ provider: 'google' });
    vi.stubEnv('GOOGLE_GENAI_USE_VERTEXAI', 'false');
    expect(resolveAntigravityProvider()).toEqual({ provider: 'google' });
  });

  it('returns gateway with host when GOOGLE_GEMINI_BASE_URL is a non-default host', () => {
    clearProviderEnv();
    vi.stubEnv('GOOGLE_GEMINI_BASE_URL', 'https://litellm.internal:4000/v1');
    expect(resolveAntigravityProvider()).toEqual({
      provider: 'gateway',
      gatewayHost: 'litellm.internal:4000',
    });
  });

  it('returns gateway for a scheme-less base url (bare host)', () => {
    clearProviderEnv();
    vi.stubEnv('GOOGLE_GEMINI_BASE_URL', 'localhost:11434');
    expect(resolveAntigravityProvider()).toEqual({
      provider: 'gateway',
      gatewayHost: 'localhost:11434',
    });
  });

  it('returns google when the base url points at the default Gemini host', () => {
    clearProviderEnv();
    vi.stubEnv('GOOGLE_GEMINI_BASE_URL', 'https://generativelanguage.googleapis.com');
    expect(resolveAntigravityProvider()).toEqual({ provider: 'google' });
  });

  it('lets a gateway base url win over the Vertex flag', () => {
    // The base url is where the request actually goes, so it outranks the
    // backend flag when a user has set both.
    clearProviderEnv();
    vi.stubEnv('GOOGLE_GENAI_USE_VERTEXAI', '1');
    vi.stubEnv('GOOGLE_GEMINI_BASE_URL', 'https://proxy.internal');
    expect(resolveAntigravityProvider()).toEqual({
      provider: 'gateway',
      gatewayHost: 'proxy.internal',
    });
  });

  it('returns google when the base url is malformed', () => {
    // A malformed value must not throw — it degrades to undefined and the
    // cascade falls through to the default, same as the two sibling resolvers.
    clearProviderEnv();
    vi.stubEnv('GOOGLE_GEMINI_BASE_URL', '::not a url');
    expect(resolveAntigravityProvider()).toEqual({ provider: 'google' });
  });
});

// ---------------------------------------------------------------------------
// antigravityProviderFromModelId — pure heuristic (no env)
// ---------------------------------------------------------------------------

describe('antigravityProviderFromModelId', () => {
  it('classifies plain gemini-* ids as google', () => {
    expect(antigravityProviderFromModelId('gemini-3-pro')).toBe('google');
    expect(antigravityProviderFromModelId('gemini-3-flash')).toBe('google');
  });

  it('classifies gemma-* ids as google', () => {
    expect(antigravityProviderFromModelId('gemma-3-27b')).toBe('google');
  });

  it('classifies Vertex resource paths as vertex, not gateway', () => {
    // These contain slashes, so the generic vendor-prefix rule would otherwise
    // claim them for the gateway branch.
    expect(antigravityProviderFromModelId('publishers/google/models/gemini-3-pro')).toBe('vertex');
    expect(antigravityProviderFromModelId('projects/p/locations/us/publishers/google')).toBe(
      'vertex',
    );
  });

  it('classifies vendor-prefixed gateway ids', () => {
    expect(antigravityProviderFromModelId('openrouter/gemini-3-pro')).toBe('gateway');
  });

  it('classifies name:tag gateway-routed ids', () => {
    expect(antigravityProviderFromModelId('litellm:gemini-3-pro')).toBe('gateway');
  });

  it('does not mistake a Gemini method suffix for a gateway tag', () => {
    expect(antigravityProviderFromModelId('gemini-3-pro:generateContent')).toBe('google');
  });

  it('returns unknown for unrecognized ids', () => {
    expect(antigravityProviderFromModelId('gpt-5-codex')).toBe('unknown');
    expect(antigravityProviderFromModelId('claude-3-5-sonnet')).toBe('unknown');
  });

  it('returns unknown for an empty / whitespace id', () => {
    expect(antigravityProviderFromModelId('')).toBe('unknown');
    expect(antigravityProviderFromModelId('   ')).toBe('unknown');
  });
});
