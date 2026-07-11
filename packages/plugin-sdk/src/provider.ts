/**
 * Provider resolution for Claude Code sessions.
 *
 * Claude Code can run against Anthropic-direct, AWS Bedrock, Google Vertex, or
 * any Anthropic-compatible gateway (`ANTHROPIC_BASE_URL` → LiteLLM, OpenRouter,
 * an Ollama shim, …). The same `model` id costs a different amount per provider,
 * so token-usage cost attribution needs the provider as a per-session fact.
 *
 * Two resolvers live here:
 *   - `resolveProvider()` — reads the host env (`process.env`) and applies the
 *     priority cascade below. Call this ONCE at SessionStart,
 *     where the env is contemporaneous, and snapshot the result onto the session
 *     root. Never call it from the reconciler (it would mislabel backfilled
 *     history under today's env).
 *   - `providerFromModelId()` — a PURE heuristic (no env) used as the fallback
 *     when env is silent or stale (backfill / pre-SessionStart roots).
 */

import { DEFAULT_ANTHROPIC_HOST, ProviderEnvSchema } from './provider-env.ts';

/** Provider backend a Claude Code session talks to. */
export type Provider = 'anthropic' | 'bedrock' | 'vertex' | 'gateway';

/** `providerFromModelId` adds 'unknown' for ids it cannot classify. */
export type ProviderOrUnknown = Provider | 'unknown';

export interface ResolvedProvider {
  provider: Provider;
  /** Host of `ANTHROPIC_BASE_URL` when the provider is a 'gateway'; else absent. */
  gatewayHost?: string;
}

/**
 * Parse the URL's host; tolerate a bare host (no scheme) by retrying with one.
 *
 * The schema now parses ANTHROPIC_BASE_URL leniently (any non-empty string, not a
 * strict URL), so a scheme-less value like `localhost:11434` (Ollama) reaches here
 * intact. Such a value does NOT throw — `new URL('localhost:11434')` parses
 * `localhost:` as the scheme and yields an EMPTY host — so an empty host is also
 * treated as a miss and retried with an explicit `https://` prefix, which
 * normalizes the bare host before the gateway host is extracted.
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
 * Resolve the provider from the host process env (Bedrock/Vertex flags +
 * `ANTHROPIC_BASE_URL`). Called once at SessionStart, where the env is
 * contemporaneous, to snapshot the provider onto the session root.
 *
 * Priority cascade:
 *   1. `CLAUDE_CODE_USE_BEDROCK` truthy → 'bedrock'
 *   2. else `CLAUDE_CODE_USE_VERTEX` truthy → 'vertex'
 *   3. else `ANTHROPIC_BASE_URL` set AND its host ≠ api.anthropic.com → 'gateway'
 *      (+ `gatewayHost`)
 *   4. else → 'anthropic'
 */
export function resolveProvider(): ResolvedProvider {
  // Lenient parse — every field is optional and total (`.catch(undefined)`), so a
  // default Anthropic-direct session (none set) yields an all-undefined object and
  // a single malformed value (e.g. a bad ANTHROPIC_BASE_URL) degrades that one
  // field to undefined instead of failing the whole parse — the Bedrock/Vertex
  // flags resolve independently of URL validity. Fall back to a parse of {}
  // (all-undefined, same shape) on the unexpected failure rather than throwing in
  // a hook path (n/no-process-env is off for this package).
  const parsed = ProviderEnvSchema.safeParse(process.env);
  const env = parsed.success ? parsed.data : ProviderEnvSchema.parse({});

  if (env.CLAUDE_CODE_USE_BEDROCK === true) return { provider: 'bedrock' };
  if (env.CLAUDE_CODE_USE_VERTEX === true) return { provider: 'vertex' };

  const baseUrl = env.ANTHROPIC_BASE_URL;
  if (baseUrl !== undefined && baseUrl !== '') {
    const host = hostOf(baseUrl);
    if (host !== undefined && host !== DEFAULT_ANTHROPIC_HOST) {
      return { provider: 'gateway', gatewayHost: host };
    }
  }

  return { provider: 'anthropic' };
}

/**
 * PURE heuristic mapping a `message.model` id to a provider — no env access.
 * Used as the fallback when env is silent/stale (the reconciler resolving a
 * backfilled or pre-SessionStart root). Best-effort → 'unknown'.
 *
 *   - `anthropic.…` / `us.anthropic.…` (region-prefixed) → bedrock
 *   - `…@<version>` (Vertex publisher suffix)            → vertex
 *   - `<vendor>/…` (e.g. `anthropic/…`, `openai/…`)      → gateway
 *   - `…:<tag>` (e.g. `llama3:70b`, Ollama-style)        → gateway
 *   - plain `claude-…`                                   → anthropic
 *   - anything else                                      → unknown
 */
export function providerFromModelId(modelId: string): ProviderOrUnknown {
  const id = modelId.trim();
  if (id === '') return 'unknown';

  // Bedrock model ids are `anthropic.claude-…` optionally with a region prefix
  // like `us.` / `eu.` / `apac.` (e.g. `us.anthropic.claude-3-5-sonnet-…`).
  if (/^(?:[a-z]{2,4}\.)?anthropic\./.test(id)) return 'bedrock';

  // Vertex publisher model ids carry an `@version` suffix, e.g.
  // `claude-3-5-sonnet@20240620`.
  if (id.includes('@')) return 'vertex';

  // Gateway/router ids namespace the vendor with a slash, e.g.
  // `anthropic/claude-3.5-sonnet`, `openai/gpt-4o`, `bedrock/anthropic.claude-…`.
  if (id.includes('/')) return 'gateway';

  // Ollama-style `name:tag` (e.g. `llama3:70b`) is served via a local gateway.
  if (id.includes(':')) return 'gateway';

  // Plain Anthropic-direct alias, e.g. `claude-3-5-sonnet-20241022`.
  if (id.startsWith('claude-')) return 'anthropic';

  return 'unknown';
}
