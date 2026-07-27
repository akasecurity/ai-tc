/**
 * Provider resolution for Codex CLI sessions.
 *
 * Codex CLI talks to OpenAI-direct by default, or to Azure OpenAI / any
 * OpenAI-compatible gateway (LiteLLM, OpenRouter, a self-hosted shim, …) when
 * `OPENAI_BASE_URL` or a named `model_providers` entry in `~/.codex/config.toml`
 * points elsewhere. The same `model` id costs a different amount per provider,
 * so token-usage cost attribution needs the provider as a per-session fact —
 * same rationale as the Claude Code resolver in `provider.ts`.
 *
 * Named `model_providers` (Azure and friends) are selected in config.toml, not
 * a fixed env var, so this resolver — scoped to `process.env` only, like its
 * Claude Code counterpart — can only distinguish OpenAI-direct from an
 * `OPENAI_BASE_URL` gateway override. A config.toml read would be needed to
 * resolve Azure specifically; out of scope here (see module comment on
 * `provider-env-codex.ts`).
 *
 * Two resolvers live here, mirroring provider.ts:
 *   - `resolveCodexProvider()` — reads the host env once at SessionStart,
 *     where it is contemporaneous, and snapshots the result onto the session
 *     root. Never call it from the reconciler.
 *   - `codexProviderFromModelId()` — a PURE heuristic (no env) used as the
 *     fallback when env is silent or stale (backfill / pre-SessionStart roots).
 */

import { CodexProviderEnvSchema, DEFAULT_OPENAI_HOST } from './provider-env-codex.ts';

/** Provider backend a Codex CLI session talks to. */
export type CodexProvider = 'openai' | 'gateway';

/** `codexProviderFromModelId` adds 'unknown' for ids it cannot classify. */
export type CodexProviderOrUnknown = CodexProvider | 'unknown';

export interface ResolvedCodexProvider {
  provider: CodexProvider;
  /** Host of `OPENAI_BASE_URL` when the provider is a 'gateway'; else absent. */
  gatewayHost?: string;
}

/**
 * Parse the URL's host; tolerate a bare host (no scheme) by retrying with one.
 * Identical logic to provider.ts's hostOf() — duplicated rather than shared
 * because the two resolvers are independent, single-purpose modules with no
 * other overlap.
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
 * Resolve the provider from the host process env (OPENAI_BASE_URL only —
 * see module comment for why Azure/named providers aren't resolvable here).
 * Called once at SessionStart, where the env is contemporaneous, to snapshot
 * the provider onto the session root.
 *
 * Priority cascade:
 *   1. `OPENAI_BASE_URL` set AND its host ≠ api.openai.com → 'gateway' (+ `gatewayHost`)
 *   2. else → 'openai'
 */
export function resolveCodexProvider(): ResolvedCodexProvider {
  // Lenient parse — the field is optional and total (`.catch(undefined)`), so a
  // default OpenAI-direct session (unset) yields an all-undefined object and a
  // malformed value degrades to undefined instead of throwing in a hook path
  // (n/no-process-env is off for this file). Fall back to a parse of {} on the
  // unexpected failure rather than throwing.
  const parsed = CodexProviderEnvSchema.safeParse(process.env);
  const env = parsed.success ? parsed.data : CodexProviderEnvSchema.parse({});

  const baseUrl = env.OPENAI_BASE_URL;
  if (baseUrl !== undefined && baseUrl !== '') {
    const host = hostOf(baseUrl);
    if (host !== undefined && host !== DEFAULT_OPENAI_HOST) {
      return { provider: 'gateway', gatewayHost: host };
    }
  }

  return { provider: 'openai' };
}

/**
 * PURE heuristic mapping a Codex `model` id to a provider — no env access.
 * Used as the fallback when env is silent/stale (the reconciler resolving a
 * backfilled or pre-SessionStart root). Best-effort → 'unknown'.
 *
 *   - plain OpenAI ids (`gpt-…`, `o1…`/`o3…`/`o4…`, `codex-…`) → openai
 *   - `<vendor>/…` (e.g. `azure/…`, `openrouter/…`)            → gateway
 *   - `…:<tag>` (e.g. gateway-routed aliases)                  → gateway
 *   - anything else                                            → unknown
 */
export function codexProviderFromModelId(modelId: string): CodexProviderOrUnknown {
  const id = modelId.trim();
  if (id === '') return 'unknown';

  // Gateway/router ids namespace the vendor with a slash, e.g. `azure/gpt-5-codex`.
  if (id.includes('/')) return 'gateway';

  // Gateway-routed `name:tag` aliases (e.g. LiteLLM/OpenRouter style).
  if (id.includes(':')) return 'gateway';

  // Plain OpenAI-direct model families.
  if (/^(gpt-|o[134](-|$)|codex-)/.test(id)) return 'openai';

  return 'unknown';
}
