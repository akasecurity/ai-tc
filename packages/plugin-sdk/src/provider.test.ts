/**
 * Unit tests for provider resolution.
 *
 *   - resolveProvider(): the env priority cascade
 *       (Bedrock > Vertex > gateway-via-ANTHROPIC_BASE_URL > anthropic).
 *       Env is injected with vi.stubEnv so each branch is exercised in isolation.
 *   - providerFromModelId(): the pure model-id heuristic (no env).
 */

import { afterEach, describe, expect, it, vi } from 'vitest';

import { providerFromModelId, resolveProvider } from './provider.ts';

// Clear the three provider env vars before each case so a stub from one test
// never leaks into the next (and so the host's real env doesn't bleed in).
function clearProviderEnv(): void {
  vi.stubEnv('CLAUDE_CODE_USE_BEDROCK', '');
  vi.stubEnv('CLAUDE_CODE_USE_VERTEX', '');
  vi.stubEnv('ANTHROPIC_BASE_URL', '');
}

afterEach(() => {
  vi.unstubAllEnvs();
});

// ---------------------------------------------------------------------------
// resolveProvider — env priority cascade
// ---------------------------------------------------------------------------

describe('resolveProvider', () => {
  it('returns anthropic when no provider env is set', () => {
    clearProviderEnv();
    expect(resolveProvider()).toEqual({ provider: 'anthropic' });
  });

  it('returns bedrock when CLAUDE_CODE_USE_BEDROCK is truthy', () => {
    clearProviderEnv();
    vi.stubEnv('CLAUDE_CODE_USE_BEDROCK', '1');
    expect(resolveProvider()).toEqual({ provider: 'bedrock' });
  });

  it('accepts "true" as a truthy Bedrock flag', () => {
    clearProviderEnv();
    vi.stubEnv('CLAUDE_CODE_USE_BEDROCK', 'true');
    expect(resolveProvider()).toEqual({ provider: 'bedrock' });
  });

  it('returns vertex when CLAUDE_CODE_USE_VERTEX is truthy', () => {
    clearProviderEnv();
    vi.stubEnv('CLAUDE_CODE_USE_VERTEX', '1');
    expect(resolveProvider()).toEqual({ provider: 'vertex' });
  });

  it('prefers Bedrock over Vertex when both flags are set', () => {
    clearProviderEnv();
    vi.stubEnv('CLAUDE_CODE_USE_BEDROCK', '1');
    vi.stubEnv('CLAUDE_CODE_USE_VERTEX', '1');
    expect(resolveProvider()).toEqual({ provider: 'bedrock' });
  });

  it('prefers the Bedrock flag over a gateway base URL', () => {
    clearProviderEnv();
    vi.stubEnv('CLAUDE_CODE_USE_BEDROCK', '1');
    vi.stubEnv('ANTHROPIC_BASE_URL', 'https://litellm.internal:4000');
    expect(resolveProvider()).toEqual({ provider: 'bedrock' });
  });

  it('returns gateway with host when ANTHROPIC_BASE_URL is a non-default host', () => {
    clearProviderEnv();
    vi.stubEnv('ANTHROPIC_BASE_URL', 'https://litellm.internal:4000/v1');
    expect(resolveProvider()).toEqual({
      provider: 'gateway',
      gatewayHost: 'litellm.internal:4000',
    });
  });

  it('returns gateway for a scheme-less ANTHROPIC_BASE_URL (Ollama-style bare host)', () => {
    // The schema parses ANTHROPIC_BASE_URL leniently (not a strict z.url()), so a
    // bare host like `localhost:11434` survives the parse and hostOf's https://
    // retry normalizes it — the previously-dead retry branch is now reachable.
    clearProviderEnv();
    vi.stubEnv('ANTHROPIC_BASE_URL', 'localhost:11434');
    expect(resolveProvider()).toEqual({
      provider: 'gateway',
      gatewayHost: 'localhost:11434',
    });
  });

  it('still resolves bedrock when CLAUDE_CODE_USE_BEDROCK is set with a malformed ANTHROPIC_BASE_URL', () => {
    // Regression: a present-but-invalid base URL must not poison the whole parse
    // and discard the valid Bedrock flag (which would mislabel the provider as
    // anthropic → wrong cost attribution). Flags resolve independently of the URL.
    clearProviderEnv();
    vi.stubEnv('CLAUDE_CODE_USE_BEDROCK', '1');
    vi.stubEnv('ANTHROPIC_BASE_URL', '::not a url');
    expect(resolveProvider()).toEqual({ provider: 'bedrock' });
  });

  it('still resolves vertex when CLAUDE_CODE_USE_VERTEX is set with a bare-host ANTHROPIC_BASE_URL', () => {
    // Same regression for the Vertex flag: a scheme-less `my-gateway:4000` value
    // must not knock out flag-based detection.
    clearProviderEnv();
    vi.stubEnv('CLAUDE_CODE_USE_VERTEX', '1');
    vi.stubEnv('ANTHROPIC_BASE_URL', 'my-gateway:4000');
    expect(resolveProvider()).toEqual({ provider: 'vertex' });
  });

  it('returns anthropic when ANTHROPIC_BASE_URL points at the default host', () => {
    clearProviderEnv();
    vi.stubEnv('ANTHROPIC_BASE_URL', 'https://api.anthropic.com');
    expect(resolveProvider()).toEqual({ provider: 'anthropic' });
  });

  it('treats a "false"/"0" Bedrock flag as not set', () => {
    clearProviderEnv();
    vi.stubEnv('CLAUDE_CODE_USE_BEDROCK', 'false');
    vi.stubEnv('CLAUDE_CODE_USE_VERTEX', '0');
    expect(resolveProvider()).toEqual({ provider: 'anthropic' });
  });
});

// ---------------------------------------------------------------------------
// providerFromModelId — pure heuristic (no env)
// ---------------------------------------------------------------------------

describe('providerFromModelId', () => {
  it('classifies Bedrock anthropic.* ids', () => {
    expect(providerFromModelId('anthropic.claude-3-5-sonnet-20241022-v2:0')).toBe('bedrock');
  });

  it('classifies region-prefixed Bedrock ids (us.anthropic.*)', () => {
    expect(providerFromModelId('us.anthropic.claude-3-5-sonnet-20241022-v2:0')).toBe('bedrock');
  });

  it('classifies Vertex @version ids', () => {
    expect(providerFromModelId('claude-3-5-sonnet@20240620')).toBe('vertex');
  });

  it('classifies vendor-prefixed gateway ids (anthropic/…)', () => {
    expect(providerFromModelId('anthropic/claude-3.5-sonnet')).toBe('gateway');
  });

  it('classifies vendor-prefixed gateway ids (openai/…)', () => {
    expect(providerFromModelId('openai/gpt-4o')).toBe('gateway');
  });

  it('classifies Ollama-style name:tag ids as gateway', () => {
    expect(providerFromModelId('llama3:70b')).toBe('gateway');
  });

  it('classifies plain claude-* ids as anthropic', () => {
    expect(providerFromModelId('claude-3-5-sonnet-20241022')).toBe('anthropic');
  });

  it('returns unknown for unrecognized ids', () => {
    expect(providerFromModelId('gpt-4o')).toBe('unknown');
  });

  it('returns unknown for an empty / whitespace id', () => {
    expect(providerFromModelId('')).toBe('unknown');
    expect(providerFromModelId('   ')).toBe('unknown');
  });

  it('prefers the Bedrock anthropic. prefix over a trailing :tag', () => {
    // `anthropic.claude-…-v2:0` has a colon but must classify as bedrock, not the
    // Ollama-style gateway branch — the anthropic. test runs first.
    expect(providerFromModelId('anthropic.claude-3-haiku-20240307-v1:0')).toBe('bedrock');
  });
});
