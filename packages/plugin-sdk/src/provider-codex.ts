/**
 * Provider resolution for Codex CLI sessions.
 *
 * Codex CLI talks to OpenAI-direct by default, or to Azure OpenAI / any
 * OpenAI-compatible gateway (LiteLLM, OpenRouter, a self-hosted shim, …) when
 * its configuration points elsewhere. The same `model` id costs a different
 * amount per provider, so token-usage cost attribution needs the provider as a
 * per-session fact.
 *
 * The base URL comes from `config.toml` (see `codex-config.ts`): for the
 * built-in `openai` provider, `openai_base_url`, else the `OPENAI_BASE_URL`
 * environment variable older Codex builds read; for a configured provider, its
 * `[model_providers.<id>] base_url`. A host under one of
 * `AZURE_OPENAI_HOST_SUFFIXES` is 'azure'; any other non-default host for the
 * `openai` provider is a 'gateway'.
 *
 * Two resolvers live here, mirroring provider.ts:
 *   - `resolveCodexProvider()` — reads the host env and `config.toml` each
 *     time it is called: at SessionStart, which snapshots the result onto the
 *     session root, and from `readCodexAccountEnv`, whose veto runs on the
 *     hooks that check the Codex account. Never call it from the reconciler.
 *   - `codexProviderFromModelId()` — a PURE heuristic (no env) used as the
 *     fallback when env is silent or stale (backfill / pre-SessionStart roots).
 */

import { readCodexProviderConfig, resolveCodexHome } from './codex-config.ts';
import { CodexProviderEnvSchema, DEFAULT_OPENAI_HOST } from './provider-env-codex.ts';

/** Provider backend a Codex CLI session talks to. */
export type CodexProvider = 'openai' | 'azure' | 'gateway';

/** `codexProviderFromModelId` adds 'unknown' for ids it cannot classify. */
export type CodexProviderOrUnknown = CodexProvider | 'unknown';

export interface ResolvedCodexProvider {
  provider: CodexProvider;
  /** Host of the base URL when the provider is a 'gateway'; else absent. */
  gatewayHost?: string;
}

/** Host suffixes of Azure OpenAI, Azure AI Foundry and Azure AI services endpoints, public and US Government. */
export const AZURE_OPENAI_HOST_SUFFIXES: readonly string[] = [
  '.openai.azure.com',
  '.services.ai.azure.com',
  '.cognitiveservices.azure.com',
  '.openai.azure.us',
  '.services.ai.azure.us',
  '.cognitiveservices.azure.us',
];

/**
 * Parse a base URL; tolerate a bare host (no scheme) by retrying with one.
 * Identical logic to provider.ts's hostOf().
 */
function parseBaseUrl(url: string): URL | undefined {
  try {
    const parsed = new URL(url);
    if (parsed.host !== '') return parsed;
  } catch {
    // fall through to the scheme-prefixed retry
  }
  try {
    const parsed = new URL(`https://${url}`);
    return parsed.host !== '' ? parsed : undefined;
  } catch {
    return undefined;
  }
}

/** True when the URL's host name sits under one of the Azure suffixes. */
export function isAzureOpenAiUrl(url: string): boolean {
  const parsed = parseBaseUrl(url);
  if (parsed === undefined) return false;
  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
  return AZURE_OPENAI_HOST_SUFFIXES.some((suffix) => hostname.endsWith(suffix));
}

/** Azure for an Azure host, a gateway for another non-default host, else OpenAI. */
function classifyBaseUrl(baseUrl: string | undefined): ResolvedCodexProvider {
  if (baseUrl === undefined || baseUrl === '') return { provider: 'openai' };
  if (isAzureOpenAiUrl(baseUrl)) return { provider: 'azure' };
  const host = parseBaseUrl(baseUrl)?.host;
  if (host !== undefined && host !== DEFAULT_OPENAI_HOST) {
    return { provider: 'gateway', gatewayHost: host };
  }
  return { provider: 'openai' };
}

/**
 * Resolve the provider from `config.toml` and the host process env.
 *
 * Priority cascade:
 *   1. the selected provider is `openai` (or none is selected): its base URL is
 *      `openai_base_url`, else `OPENAI_BASE_URL`
 *   2. a configured provider whose `base_url` has an Azure host → 'azure'
 *   3. any other provider: `OPENAI_BASE_URL`
 * and a base URL is then 'azure' on an Azure host, 'gateway' (+ `gatewayHost`)
 * on another host than api.openai.com, and 'openai' when absent or default.
 */
export function resolveCodexProvider(): ResolvedCodexProvider {
  // Lenient parse — every field is optional and total (`.catch(undefined)`), so a
  // malformed value degrades to undefined instead of throwing in a hook path.
  // Fall back to a parse of {} on the unexpected failure rather than throwing.
  const parsed = CodexProviderEnvSchema.safeParse(process.env);
  const env = parsed.success ? parsed.data : CodexProviderEnvSchema.parse({});

  let config: ReturnType<typeof readCodexProviderConfig> | undefined;
  try {
    config = readCodexProviderConfig(resolveCodexHome({ codexHome: env.CODEX_HOME }));
  } catch {
    config = undefined;
  }

  if (config === undefined || config.provider === 'openai') {
    return classifyBaseUrl(config?.baseUrl ?? env.OPENAI_BASE_URL);
  }
  if (config.baseUrl !== undefined && isAzureOpenAiUrl(config.baseUrl)) {
    return { provider: 'azure' };
  }
  return classifyBaseUrl(env.OPENAI_BASE_URL);
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
