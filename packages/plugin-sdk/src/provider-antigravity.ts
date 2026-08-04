/**
 * Provider resolution for Antigravity sessions.
 *
 * Antigravity talks to Gemini either through the public Generative Language
 * API (the default) or through Vertex AI when `GOOGLE_GENAI_USE_VERTEXAI` is
 * set, or to any Gemini-compatible gateway (LiteLLM, OpenRouter, a self-hosted
 * shim, …) when `GOOGLE_GEMINI_BASE_URL` points elsewhere. The same `model` id
 * costs a different amount per provider, so token-usage cost attribution needs
 * the provider as a per-session fact — same rationale as the Claude Code
 * resolver in `provider.ts` and the Codex one in `provider-codex.ts`.
 *
 * Two resolvers live here, mirroring both siblings:
 *   - `resolveAntigravityProvider()` — reads the host env once at the first
 *     invocation of a conversation, where it is contemporaneous, and snapshots
 *     the result onto the session root. Never call it from the reconciler.
 *   - `antigravityProviderFromModelId()` — a PURE heuristic (no env) used as
 *     the fallback when env is silent or stale (backfill / pre-session roots).
 */

import { AntigravityProviderEnvSchema, DEFAULT_GEMINI_HOST } from './provider-env-antigravity.ts';

/** Provider backend an Antigravity session talks to. */
export type AntigravityProvider = 'google' | 'vertex' | 'gateway';

/** `antigravityProviderFromModelId` adds 'unknown' for ids it cannot classify. */
export type AntigravityProviderOrUnknown = AntigravityProvider | 'unknown';

export interface ResolvedAntigravityProvider {
  provider: AntigravityProvider;
  /** Host of `GOOGLE_GEMINI_BASE_URL` when the provider is a 'gateway'; else absent. */
  gatewayHost?: string;
}

/**
 * Parse the URL's host; tolerate a bare host (no scheme) by retrying with one.
 * Identical logic to provider.ts's hostOf() — duplicated rather than shared
 * because the resolvers are independent, single-purpose modules with no other
 * overlap.
 */
function hostOf(url: string): string | undefined {
  try {
    const host = new URL(url).host;
    if (host !== '') return host;
  } catch {
    // fall through to the scheme-prefixed retry
  }
  try {
    const host = new URL(`https://${url}`).host;
    return host !== '' ? host : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Resolve the provider from the host process env. Called once at the first
 * invocation of a conversation, where the env is contemporaneous, to snapshot
 * the provider onto the session root.
 *
 * Priority cascade:
 *   1. `GOOGLE_GEMINI_BASE_URL` set AND its host ≠ the Gemini API host
 *      → 'gateway' (+ `gatewayHost`). Checked FIRST: a base-url override is
 *      what the request actually goes to, so it wins over the Vertex flag.
 *   2. `GOOGLE_GENAI_USE_VERTEXAI` truthy → 'vertex'
 *   3. else → 'google'
 */
export function resolveAntigravityProvider(): ResolvedAntigravityProvider {
  // Lenient parse — every field is optional and total, so a default
  // Gemini-direct session (both unset) yields an all-default object and a
  // malformed value degrades instead of throwing in a hook path
  // (n/no-process-env is off for this file). Fall back to a parse of {} on the
  // unexpected failure rather than throwing.
  const parsed = AntigravityProviderEnvSchema.safeParse(process.env);
  const env = parsed.success ? parsed.data : AntigravityProviderEnvSchema.parse({});

  const baseUrl = env.GOOGLE_GEMINI_BASE_URL;
  if (baseUrl !== undefined && baseUrl !== '') {
    const host = hostOf(baseUrl);
    if (host !== undefined && host !== DEFAULT_GEMINI_HOST) {
      return { provider: 'gateway', gatewayHost: host };
    }
  }

  if (env.GOOGLE_GENAI_USE_VERTEXAI) return { provider: 'vertex' };

  return { provider: 'google' };
}

/**
 * PURE heuristic mapping an Antigravity `model` id to a provider — no env
 * access. Used as the fallback when env is silent/stale (the reconciler
 * resolving a backfilled or pre-session root). Best-effort → 'unknown'.
 *
 *   - `publishers/google/models/…` or a `projects/…` resource path → vertex
 *   - plain Gemini ids (`gemini-…`, `gemma-…`)                     → google
 *   - `<vendor>/…` (e.g. `openrouter/…`)                           → gateway
 *   - `…:<tag>` (e.g. gateway-routed aliases)                      → gateway
 *   - anything else                                                → unknown
 */
export function antigravityProviderFromModelId(modelId: string): AntigravityProviderOrUnknown {
  const id = modelId.trim();
  if (id === '') return 'unknown';

  // Vertex addresses a model by resource path. Checked before the generic
  // slash rule below, which would otherwise classify it as a gateway.
  if (id.startsWith('publishers/') || id.startsWith('projects/')) return 'vertex';

  // Gateway/router ids namespace the vendor with a slash, e.g. `openrouter/gemini-3-pro`.
  if (id.includes('/')) return 'gateway';

  // Gateway-routed `name:tag` aliases (e.g. LiteLLM/OpenRouter style). Guarded
  // so a Vertex-style `gemini-3-pro:generateContent` method suffix is not
  // mistaken for one.
  if (id.includes(':') && !/^gem(ini|ma)-/.test(id)) return 'gateway';

  // Plain Gemini-direct model families.
  if (/^gem(ini|ma)-/.test(id)) return 'google';

  return 'unknown';
}
